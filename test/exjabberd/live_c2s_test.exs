defmodule Exjabberd.LiveC2STest do
  @moduledoc """
  Live C2S integration tests: real XMPP over a raw TCP socket against
  the booted application (port 5222). This is the automated version of
  the audit's raw-socket suite.

  Run with the dev server stopped (it also binds 5222), and with a
  named node so Mnesia uses disc_copies:

      ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test

  Without a node name the server still works, but accounts live in ETS
  only and do not survive a restart.
  """
  use ExUnit.Case, async: false

  @host ~c"127.0.0.1"
  @port 5222
  @stream_open "<?xml version='1.0'?><stream:stream to='localhost' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"

  setup_all do
    # Test accounts (duplicates from a previous run are fine).
    for {user, pass} <- [{"testandi", "secret"}, {"testbudi", "secret"}, {"testcarol", "secret"}] do
      case Exjabberd.Auth.create_user("localhost", user, pass) do
        :ok -> :ok
        {:error, _} -> :ok
      end
    end

    :ok
  end

  setup do
    on_exit(fn -> :ok end)
    :ok
  end

  # --- socket helpers ---

  defp connect do
    {:ok, sock} = :gen_tcp.connect(@host, @port, [:binary, packet: 0, active: false], 5_000)
    sock
  end

  defp send_recv(sock, data, needle, timeout \\ 6_000) do
    :ok = sock_send(sock, data)
    recv_until(sock, needle, timeout)
  end

  defp sock_send(sock, data) when is_port(sock), do: :gen_tcp.send(sock, data)
  defp sock_send({:ssl, ssl_sock}, data), do: :ssl.send(ssl_sock, data)

  defp recv_until(sock, needle), do: recv_until(sock, needle, 6_000)

  defp recv_until(sock, needle, timeout) do
    recv_until(sock, needle, timeout, "")
  end

  defp recv_until(sock, needle, timeout, acc) do
    if String.contains?(acc, needle) do
      acc
    else
      case sock_recv(sock, timeout) do
        {:ok, data} -> recv_until(sock, needle, timeout, acc <> data)
        {:error, _} -> acc
      end
    end
  end

  defp sock_recv(sock, timeout) when is_port(sock), do: :gen_tcp.recv(sock, 0, timeout)
  defp sock_recv({:ssl, ssl_sock}, timeout), do: :ssl.recv(ssl_sock, 0, timeout)

  defp login(sock, user, pass, resource) do
    _ = send_recv(sock, @stream_open, "stream:features")
    b64 = Base.encode64("\0#{user}\0#{pass}")

    r =
      send_recv(
        sock,
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>#{b64}</auth>",
        "success"
      )

    assert r =~ "<success", "PLAIN auth failed for #{user}: #{r}"
    _ = send_recv(sock, @stream_open, "stream:features")

    r =
      send_recv(
        sock,
        "<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>#{resource}</resource></bind></iq>",
        "bind"
      )

    assert r =~ "<jid>#{user}@localhost/#{resource}</jid>", "bind failed: #{r}"
    :ok
  end

  # --- tests ---

  test "stream open returns exactly one valid <stream:features>" do
    sock = connect()
    r = send_recv(sock, @stream_open, "stream:features")
    assert r =~ "<stream:stream from='localhost'"
    assert r =~ "<stream:features>"
    assert r =~ "SCRAM-SHA-256"
    assert r =~ "starttls"
    # No bare features outside the wrapper, no duplicate wrapper.
    assert length(String.split(r, "<stream:features>")) == 2
    assert length(String.split(r, "</stream:features>")) == 2
    refute r =~ "<mechanisms" and not (r =~ "<stream:features><starttls")
    :gen_tcp.close(sock)
  end

  test "roster, disco, ping, time and version answer over the wire" do
    sock = connect()
    login(sock, "testandi", "secret", "live1")

    r =
      send_recv(
        sock,
        "<iq type='get' id='roster1'><query xmlns='jabber:iq:roster'/></iq>",
        "roster1"
      )

    assert r =~ "type='result'" and r =~ "jabber:iq:roster"

    r =
      send_recv(
        sock,
        "<iq type='get' id='disco1' to='localhost'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        "disco1"
      )

    assert r =~ "type='result'" and r =~ "disco#info"

    r =
      send_recv(
        sock,
        "<iq type='get' id='ping1' to='localhost'><ping xmlns='urn:xmpp:ping'/></iq>",
        "ping1"
      )

    assert r =~ "type='result'"

    r =
      send_recv(
        sock,
        "<iq type='get' id='time1' to='localhost'><time xmlns='urn:xmpp:time'/></iq>",
        "time1"
      )

    assert r =~ "type='result'" and r =~ "<utc>"

    r =
      send_recv(
        sock,
        "<iq type='get' id='ver1' to='localhost'><query xmlns='jabber:iq:version'/></iq>",
        "ver1"
      )

    assert r =~ "type='result'" and r =~ "<name>exjabberd</name>"

    :gen_tcp.close(sock)
  end

  test "roster set adds an item and roster get shows it" do
    sock = connect()
    login(sock, "testandi", "secret", "live2")

    r =
      send_recv(
        sock,
        "<iq type='set' id='rs1'><query xmlns='jabber:iq:roster'><item jid='testbudi@localhost' name='Budi'><group>Teman</group></item></query></iq>",
        "rs1"
      )

    assert r =~ "type='result'"

    r = send_recv(sock, "<iq type='get' id='rs2'><query xmlns='jabber:iq:roster'/></iq>", "rs2")
    assert r =~ "testbudi@localhost" and r =~ "Teman"

    _ =
      send_recv(
        sock,
        "<iq type='set' id='rs3'><query xmlns='jabber:iq:roster'><item jid='testbudi@localhost' subscription='remove'/></query></iq>",
        "rs3"
      )

    :gen_tcp.close(sock)
  end

  test "presence and 1-1 messages flow both ways" do
    a = connect()
    b = connect()
    login(a, "testandi", "secret", "live3")
    login(b, "testbudi", "secret", "live4")

    :ok = :gen_tcp.send(a, "<presence/>")
    assert recv_until(b, "presence") =~ "testandi@localhost/live3"

    :ok =
      :gen_tcp.send(
        a,
        "<message to='testbudi@localhost/live4' type='chat' id='m1'><body>halo budi</body></message>"
      )

    assert recv_until(b, "halo budi") =~ "halo budi"

    :ok =
      :gen_tcp.send(
        b,
        "<message to='testandi@localhost/live3' type='chat' id='m2'><body>halo andi</body></message>"
      )

    assert recv_until(a, "halo andi") =~ "halo andi"

    :gen_tcp.close(a)
    :gen_tcp.close(b)
  end

  test "MUC: join, groupchat both ways, leave" do
    room = "troom#{System.unique_integer([:positive])}"
    a = connect()
    b = connect()
    login(a, "testandi", "secret", "live5")
    login(b, "testbudi", "secret", "live6")

    :ok =
      :gen_tcp.send(
        a,
        "<presence to='#{room}@conference.localhost/andi'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
      )

    r = recv_until(a, "110")
    assert r =~ "110" and r =~ "201"

    :ok =
      :gen_tcp.send(
        b,
        "<presence to='#{room}@conference.localhost/budi'><x xmlns='http://jabber.org/protocol/muc'/></presence>"
      )

    assert recv_until(b, "110") =~ "110"
    assert recv_until(a, "#{room}@conference.localhost/budi") =~ "budi"

    :ok =
      :gen_tcp.send(
        a,
        "<message to='#{room}@conference.localhost' type='groupchat' id='g1'><body>halo room</body></message>"
      )

    r = recv_until(b, "halo room")
    assert r =~ "halo room" and r =~ "#{room}@conference.localhost/andi"

    :ok =
      :gen_tcp.send(b, "<presence to='#{room}@conference.localhost/budi' type='unavailable'/>")

    assert recv_until(a, "unavailable") =~ "unavailable"

    :gen_tcp.close(a)
    :gen_tcp.close(b)
  end

  test "offline message is stored and flushed on next login" do
    a = connect()
    login(a, "testandi", "secret", "live7")

    :ok =
      :gen_tcp.send(
        a,
        "<message to='testcarol@localhost' type='chat' id='o1'><body>pesan offline</body></message>"
      )

    Process.sleep(500)
    :gen_tcp.close(a)

    c = connect()
    login(c, "testcarol", "secret", "live8")
    assert recv_until(c, "pesan offline") =~ "pesan offline"
    :gen_tcp.close(c)
  end

  test "in-band registration creates a usable account" do
    user = "reg#{System.unique_integer([:positive])}"
    sock = connect()
    _ = send_recv(sock, @stream_open, "stream:features")

    r = send_recv(sock, "<iq type='get' id='r0'><query xmlns='jabber:iq:register'/></iq>", "r0")
    assert r =~ "instructions"

    r =
      send_recv(
        sock,
        "<iq type='set' id='r1'><query xmlns='jabber:iq:register'><username>#{user}</username><password>secret</password></query></iq>",
        "r1"
      )

    assert r =~ "type='result'"
    :gen_tcp.close(sock)

    sock2 = connect()
    login(sock2, user, "secret", "live9")
    :gen_tcp.close(sock2)
  end

  test "malformed stanza gets a proper stream error (RFC 6120 4.9)" do
    sock = connect()
    _ = send_recv(sock, @stream_open, "stream:features")
    :ok = :gen_tcp.send(sock, "<message><broken")
    Process.sleep(300)
    :ok = :gen_tcp.send(sock, "<presence/>")
    r = recv_until(sock, "stream:error")
    assert r =~ "stream:error" and r =~ "invalid-xml"
    :gen_tcp.close(sock)
  end

  test "300 KB stanza is rejected with policy-violation" do
    sock = connect()
    _ = send_recv(sock, @stream_open, "stream:features")

    :ok =
      :gen_tcp.send(
        sock,
        "<message to='testbudi@localhost'>" <> String.duplicate("x", 300_000) <> "</message>"
      )

    r = recv_until(sock, "stream:error")
    assert r =~ "policy-violation"
    :gen_tcp.close(sock)
  end

  test "STARTTLS handshake works and PLAIN login succeeds over TLS" do
    sock = connect()
    _ = send_recv(sock, @stream_open, "stream:features")
    r = send_recv(sock, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", "proceed")
    assert r =~ "<proceed"

    {:ok, ssl_sock} =
      :ssl.connect(sock, [verify: :verify_none, versions: [:"tlsv1.2", :"tlsv1.3"]], 10_000)

    tls = {:ssl, ssl_sock}
    r = send_recv(tls, @stream_open, "stream:features")
    # After TLS, STARTTLS must no longer be offered.
    refute r =~ "starttls"
    assert r =~ "SCRAM-SHA-256"
    login(tls, "testandi", "secret", "live10")
    :ssl.close(ssl_sock)
  end

  test "SCRAM-SHA-256 exchange succeeds (client side, RFC 5802)" do
    sock = connect()
    _ = send_recv(sock, @stream_open, "stream:features")

    nonce = Base.encode64(:crypto.strong_rand_bytes(12), padding: false)
    first_bare = "n=testandi,r=#{nonce}"
    first = "n,," <> first_bare

    r =
      send_recv(
        sock,
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-256'>#{Base.encode64(first)}</auth>",
        "challenge"
      )

    assert r =~ "<challenge"
    [_, chal_b64] = Regex.run(~r/<challenge[^>]*>([^<]+)<\/challenge>/, r)
    server_first = Base.decode64!(chal_b64)

    %{"r" => server_nonce, "s" => salt_b64, "i" => iters} =
      server_first
      |> String.split(",")
      |> Enum.map(&(String.split(&1, "=", parts: 2) |> List.to_tuple()))
      |> Map.new()

    salted =
      :crypto.pbkdf2_hmac(
        :sha256,
        "secret",
        Base.decode64!(salt_b64),
        String.to_integer(iters),
        32
      )

    client_key = :crypto.mac(:hmac, :sha256, salted, "Client Key")
    stored_key = :crypto.hash(:sha256, client_key)
    channel = Base.encode64("n,,")
    final_wo = "c=#{channel},r=#{server_nonce}"
    auth_message = "#{first_bare},#{server_first},#{final_wo}"
    signature = :crypto.mac(:hmac, :sha256, stored_key, auth_message)
    proof = :crypto.exor(client_key, signature)
    final = "#{final_wo},p=#{Base.encode64(proof)}"

    r =
      send_recv(
        sock,
        "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>#{Base.encode64(final)}</response>",
        "success"
      )

    assert r =~ "<success"
    :gen_tcp.close(sock)
  end

  test "accounts are stored in Mnesia disc_copies (survive restart)" do
    # Only meaningful on a named node; on :nonode@nohost Mnesia cannot
    # create disc_copies tables and the test is skipped.
    if node() == :nonode@nohost do
      :ok
    else
      assert :mnesia.table_info(:passwd, :disc_copies) == [node()]
      assert Exjabberd.Auth.user_exists("localhost", "testandi")
      {:ok, creds} = Exjabberd.Auth.get_scram("localhost", "testandi")
      assert is_map(creds) and is_binary(creds.salt)
      refute Map.has_key?(creds, :password)
    end
  end
end
