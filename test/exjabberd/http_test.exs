defmodule Exjabberd.HttpTest do
  @moduledoc """
  Live HTTP-stack integration tests: admin web, REST API, BOSH
  (XEP-0124/0206), XMPP over WebSocket (RFC 7395) and HTTP File
  Upload (XEP-0363) against the booted application (ports 5222
  for XMPP and 5280 for HTTP).

  Run with the dev server stopped:

      ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test
  """
  use ExUnit.Case, async: false

  @host ~c"127.0.0.1"
  @xmpp_port 5222
  @http_port 5280
  @api_token "dev-api-token-change-me"

  setup_all do
    # :httpc keeps cookies per profile by default: a login in one
    # test would silently authenticate the next. Disable that so
    # each request carries exactly the headers the test passes.
    :httpc.set_options([{:cookies, :disabled}])

    for {user, pass} <- [
          {"httpadmin", "adminsecret"},
          {"httpalice", "secret"},
          {"httpbob", "secret"},
          {"httpcarol", "secret"}
        ] do
      case Exjabberd.Auth.create_user("localhost", user, pass) do
        :ok -> :ok
        {:error, _} -> :ok
      end
    end

    :ok
  end

  # --- HTTP helpers ---

  defp http(method, path, headers \\ [], body \\ "") do
    url = ~c"http://127.0.0.1:#{@http_port}#{path}"
    # :httpc takes the Content-Type as a separate request element;
    # a copy in the header list would send two conflicting values
    # (the server keeps one, unpredictably). Pull it out here.
    {content_type, headers} =
      case List.keytake(headers, "content-type", 0) do
        {{_, ct}, rest} -> {String.to_charlist(ct), rest}
        nil -> {~c"text/plain", headers}
      end

    headers = Enum.map(headers, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    request =
      case method do
        :get -> {url, headers}
        :delete -> {url, headers}
        _ -> {url, headers, content_type, body}
      end

    {:ok, {{_, status, _}, resp_headers, resp_body}} =
      # :httpc follows redirects by default (autoredirect: true):
      # the admin tests assert on the 302 itself, so turn it off.
      :httpc.request(method, request, [{:timeout, 15_000}, {:autoredirect, false}], [])

    {status, resp_headers, to_string(resp_body)}
  end

  defp api_headers,
    do: [{"authorization", "Bearer #{@api_token}"}, {"content-type", "application/json"}]

  # --- TCP XMPP helpers (peer for BOSH/WS message exchange) ---

  defp tcp_connect do
    {:ok, sock} = :gen_tcp.connect(@host, @xmpp_port, [:binary, packet: 0, active: false], 5_000)
    sock
  end

  defp tcp_send(sock, data), do: :gen_tcp.send(sock, data)

  defp tcp_recv_until(sock, needle, timeout \\ 6_000) do
    tcp_recv_until(sock, needle, timeout, "")
  end

  defp tcp_recv_until(_sock, _needle, timeout, acc) when timeout <= 0, do: acc

  defp tcp_recv_until(sock, needle, timeout, acc) do
    if String.contains?(acc, needle) do
      acc
    else
      case :gen_tcp.recv(sock, 0, min(timeout, 2_000)) do
        {:ok, data} -> tcp_recv_until(sock, needle, timeout - 2_000, acc <> data)
        {:error, _} -> acc
      end
    end
  end

  defp tcp_login(sock, user, password, resource) do
    tcp_send(
      sock,
      "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )

    features = tcp_recv_until(sock, "stream:features")
    assert features =~ "mechanism"

    cred = Base.encode64("\0#{user}\0#{password}")

    tcp_send(
      sock,
      "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>#{cred}</auth>"
    )

    assert tcp_recv_until(sock, "success") =~ "success"

    tcp_send(
      sock,
      "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )

    assert tcp_recv_until(sock, "stream:features") =~ "bind"

    tcp_send(
      sock,
      "<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>#{resource}</resource></bind></iq>"
    )

    reply = tcp_recv_until(sock, "bind")
    assert reply =~ "<jid>#{user}@localhost/#{resource}</jid>"
    :ok
  end

  # --- REST API ---

  test "REST API: status requires a Bearer token, then reports live numbers" do
    {status, _, body} = http(:get, "/api/status")
    assert status == 401
    assert Jason.decode!(body)["error"] == "unauthorized"

    {status, _, _} = http(:get, "/api/status", [{"authorization", "Bearer wrong"}])
    assert status == 401

    {status, _, body} = http(:get, "/api/status", api_headers())
    assert status == 200
    doc = Jason.decode!(body)
    assert doc["status"] == "ok"
    assert doc["version"] == Exjabberd.version()
    assert doc["registered_users"] >= 4
    assert is_integer(doc["uptime_seconds"]) and doc["uptime_seconds"] >= 0
  end

  test "REST API: create / get / delete a user" do
    user = "httpapi#{System.unique_integer([:positive])}"

    {status, _, _} =
      http(:post, "/api/users", api_headers(), Jason.encode!(%{user: user, password: "secret"}))

    assert status == 201

    {status, _, body} = http(:get, "/api/users/#{user}", api_headers())
    assert status == 200
    assert Jason.decode!(body)["exists"] == true

    {status, _, _} = http(:delete, "/api/users/#{user}", api_headers())
    assert status == 200

    {_, _, body} = http(:get, "/api/users/#{user}", api_headers())
    assert Jason.decode!(body)["exists"] == false
  end

  # --- Admin web ---

  test "admin web: login page, wrong password rejected, admin login shows dashboard" do
    {status, _, body} = http(:get, "/admin/login")
    assert status == 200
    assert body =~ "exjabberd admin"

    {status, _, _} = http(:get, "/admin")
    assert status == 302

    {status, _, _} =
      http(
        :post,
        "/admin/login",
        [{"content-type", "application/x-www-form-urlencoded"}],
        "user=admin&password=wrong"
      )

    assert status == 401

    # httpadmin is not in the admin ACL, so a correct password is not enough.
    {status, _, _} =
      http(
        :post,
        "/admin/login",
        [{"content-type", "application/x-www-form-urlencoded"}],
        "user=httpadmin&password=adminsecret"
      )

    assert status == 401
  end

  test "admin web: real admin (admin@localhost) logs in and sees live stats" do
    Exjabberd.Auth.create_user("localhost", "admin", "adminsecret")

    {status, headers, _} =
      http(
        :post,
        "/admin/login",
        [{"content-type", "application/x-www-form-urlencoded"}],
        "user=admin&password=adminsecret"
      )

    assert status == 302
    cookie = headers |> Enum.find_value(fn {k, v} -> if k == ~c"set-cookie", do: to_string(v) end)
    assert cookie =~ "exjabberd_admin="
    cookie_hdr = [{"cookie", cookie |> String.split(";") |> hd()}]

    {status, _, body} = http(:get, "/admin", cookie_hdr)
    assert status == 200
    assert body =~ "Registered users"
    assert body =~ "Online sessions"

    {status, _, body} = http(:get, "/admin/users", cookie_hdr)
    assert status == 200
    assert body =~ "admin@localhost"

    {status, _, body} = http(:get, "/admin/sessions", cookie_hdr)
    assert status == 200
    assert body =~ "Online sessions"
  end

  # --- BOSH ---

  defp bosh_post(body) do
    {status, _, resp} =
      http(:post, "/bosh", [{"content-type", "text/xml; charset=utf-8"}], body)

    assert status == 200
    resp
  end

  test "BOSH: create, auth, bind, and exchange messages with a TCP client" do
    resp =
      bosh_post(
        "<body rid='101' xmlns='http://jabber.org/protocol/httpbind' to='localhost' xml:lang='en' wait='5' hold='1' ver='1.6'/>"
      )

    assert resp =~ "stream:features"
    [_, sid] = Regex.run(~r/sid='([^']+)'/, resp)

    cred = Base.encode64("\0httpalice\0secret")

    resp =
      bosh_post(
        "<body rid='102' sid='#{sid}' xmlns='http://jabber.org/protocol/httpbind'><auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>#{cred}</auth></body>"
      )

    assert resp =~ "<success"

    resp =
      bosh_post(
        "<body rid='103' sid='#{sid}' xmlns='http://jabber.org/protocol/httpbind' xmpp:restart='true' xmlns:xmpp='urn:xmpp:xbosh'/>"
      )

    assert resp =~ "stream:features"
    assert resp =~ "bind"

    resp =
      bosh_post(
        "<body rid='104' sid='#{sid}' xmlns='http://jabber.org/protocol/httpbind'><iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>bosh</resource></bind></iq></body>"
      )

    assert resp =~ "<jid>httpalice@localhost/bosh</jid>"

    bob = tcp_connect()
    :ok = tcp_login(bob, "httpbob", "secret", "tcp")

    bosh_post(
      "<body rid='105' sid='#{sid}' xmlns='http://jabber.org/protocol/httpbind'><message to='httpbob@localhost' type='chat'><body>bosh-hello</body></message></body>"
    )

    assert tcp_recv_until(bob, "bosh-hello") =~ "bosh-hello"

    tcp_send(
      bob,
      "<message to='httpalice@localhost' type='chat'><body>tcp-reply</body></message>"
    )

    resp =
      bosh_post("<body rid='106' sid='#{sid}' xmlns='http://jabber.org/protocol/httpbind'/>")

    assert resp =~ "tcp-reply"

    resp =
      bosh_post(
        "<body rid='107' sid='#{sid}' xmlns='http://jabber.org/protocol/httpbind' type='terminate'/>"
      )

    assert resp =~ "type='terminate'"
    :gen_tcp.close(bob)
  end

  test "BOSH: unknown sid is a 404" do
    {status, _, _} =
      http(
        :post,
        "/bosh",
        [{"content-type", "text/xml; charset=utf-8"}],
        "<body rid='1' sid='nosuchsid' xmlns='http://jabber.org/protocol/httpbind'/>"
      )

    assert status == 404
  end

  # --- WebSocket ---

  defp ws_connect do
    {:ok, sock} = :gen_tcp.connect(@host, @http_port, [:binary, packet: 0, active: false], 5_000)
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    :ok =
      :gen_tcp.send(
        sock,
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:5280\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: #{key}\r\nSec-WebSocket-Protocol: xmpp\r\nSec-WebSocket-Version: 13\r\n\r\n"
      )

    {:ok, resp} = :gen_tcp.recv(sock, 0, 5_000)
    assert resp =~ "101"
    assert resp =~ "Sec-WebSocket-Protocol: xmpp"
    sock
  end

  defp ws_send(sock, text) do
    data = text
    mask = :crypto.strong_rand_bytes(4)
    masked = mask_payload(data, mask)

    header =
      case byte_size(data) do
        n when n < 126 -> <<0x81, Bitwise.bor(0x80, n)>>
        n -> <<0x81, Bitwise.bor(0x80, 126), n::16>>
      end

    :ok = :gen_tcp.send(sock, header <> mask <> masked)
  end

  defp mask_payload(data, <<m0, m1, m2, m3>>) do
    data
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {b, i} ->
      Bitwise.bxor(b, Enum.at([m0, m1, m2, m3], rem(i, 4)))
    end)
    |> :binary.list_to_bin()
  end

  defp ws_recv_text(sock, needle, timeout \\ 6_000) do
    ws_recv_text(sock, needle, timeout, "", "")
  end

  defp ws_recv_text(_sock, _needle, timeout, _raw, acc) when timeout <= 0, do: acc

  defp ws_recv_text(sock, needle, timeout, raw, acc) do
    if String.contains?(acc, needle) do
      acc
    else
      case take_ws_frame(raw, sock, timeout) do
        {:ok, text, rest} ->
          ws_recv_text(sock, needle, timeout, rest, acc <> text)

        {:incomplete, _} ->
          acc
      end
    end
  end

  # Read buffered raw bytes until one complete server text frame is
  # available; returns the frame payload and the leftover bytes.
  defp take_ws_frame(raw, sock, timeout) do
    case parse_ws_frame(raw) do
      {:ok, payload, rest} ->
        {:ok, payload, rest}

      :incomplete ->
        case :gen_tcp.recv(sock, 0, min(max(timeout, 0), 2_000)) do
          {:ok, data} -> take_ws_frame(raw <> data, sock, timeout - 2_000)
          {:error, _} -> {:incomplete, raw}
        end
    end
  end

  defp parse_ws_frame(<<0x81, len, rest::binary>>) when len < 126 do
    if byte_size(rest) >= len do
      <<payload::binary-size(len), tail::binary>> = rest
      {:ok, payload, tail}
    else
      :incomplete
    end
  end

  defp parse_ws_frame(<<0x81, 126, len::16, rest::binary>>) do
    if byte_size(rest) >= len do
      <<payload::binary-size(len), tail::binary>> = rest
      {:ok, payload, tail}
    else
      :incomplete
    end
  end

  defp parse_ws_frame(<<0x81, 127, len::64, rest::binary>>) do
    if byte_size(rest) >= len do
      <<payload::binary-size(len), tail::binary>> = rest
      {:ok, payload, tail}
    else
      :incomplete
    end
  end

  defp parse_ws_frame(_), do: :incomplete

  test "WebSocket: handshake, login, bind, and exchange messages with a TCP client" do
    sock = ws_connect()

    ws_send(
      sock,
      "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )

    assert ws_recv_text(sock, "stream:features") =~ "mechanism"

    cred = Base.encode64("\0httpcarol\0secret")

    ws_send(
      sock,
      "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>#{cred}</auth>"
    )

    assert ws_recv_text(sock, "success") =~ "success"

    ws_send(
      sock,
      "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    )

    assert ws_recv_text(sock, "stream:features") =~ "bind"

    ws_send(
      sock,
      "<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>ws</resource></bind></iq>"
    )

    assert ws_recv_text(sock, "bind") =~ "<jid>httpcarol@localhost/ws</jid>"

    bob = tcp_connect()
    :ok = tcp_login(bob, "httpbob", "secret", "tcpws")

    ws_send(
      sock,
      "<message to='httpbob@localhost' type='chat'><body>ws-hello</body></message>"
    )

    assert tcp_recv_until(bob, "ws-hello") =~ "ws-hello"

    tcp_send(
      bob,
      "<message to='httpcarol@localhost' type='chat'><body>tcp-ws-reply</body></message>"
    )

    assert ws_recv_text(sock, "tcp-ws-reply") =~ "tcp-ws-reply"

    :gen_tcp.close(sock)
    :gen_tcp.close(bob)
  end

  # --- HTTP File Upload ---

  test "HTTP File Upload: slot IQ, PUT, GET identical bytes, forged token rejected" do
    alice = tcp_connect()
    :ok = tcp_login(alice, "httpalice", "secret", "up")
    data = String.duplicate("upload-bytes-", 10)
    size = byte_size(data)

    tcp_send(
      alice,
      "<iq type='set' id='up1'><request xmlns='urn:xmpp:http:upload:0' filename='test.txt' size='#{size}' content-type='text/plain'/></iq>"
    )

    reply = tcp_recv_until(alice, "slot")
    assert reply =~ "<slot"
    [_, put_url] = Regex.run(~r/<put url='([^']+)'/, reply)
    [_, get_url] = Regex.run(~r/<get url='([^']+)'/, reply)

    put_path =
      put_url
      |> String.replace("&amp;", "&")
      |> URI.parse()
      |> then(&(&1.path <> "?" <> &1.query))

    get_path =
      get_url
      |> String.replace("&amp;", "&")
      |> URI.parse()
      |> then(&(&1.path <> "?" <> &1.query))

    {status, _, _} =
      http(:put, put_path, [{"content-type", "text/plain"}], data)

    assert status == 201

    {status, _, body} = http(:get, get_path)
    assert status == 200
    assert body == data

    forged =
      String.replace(put_path, "token=", "token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    {status, _, _} = http(:put, forged, [{"content-type", "text/plain"}], data)
    assert status == 403

    {status, _, _} =
      http(
        :put,
        "/upload/nosuchslot/test.txt?token=x&exp=9999999999",
        [{"content-type", "text/plain"}],
        "x"
      )

    assert status == 404

    :gen_tcp.close(alice)
  end

  test "HTTP File Upload: oversize slot request is not-acceptable" do
    alice = tcp_connect()
    :ok = tcp_login(alice, "httpalice", "secret", "up2")

    tcp_send(
      alice,
      "<iq type='set' id='up9'><request xmlns='urn:xmpp:http:upload:0' filename='big.bin' size='999999999' content-type='application/octet-stream'/></iq>"
    )

    assert tcp_recv_until(alice, "error") =~ "not-acceptable"
    :gen_tcp.close(alice)
  end
end
