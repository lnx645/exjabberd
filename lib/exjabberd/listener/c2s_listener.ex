defmodule Exjabberd.Listener.C2S do
  @moduledoc """
  Real C2S TCP listener (ejabberd_c2s + ejabberd_listener compatibility).

  Binds a port, accepts XMPP client streams (RFC 6120), and drives one
  `Exjabberd.C2S` process per connection. The serve loop owns reading;
  the C2S process owns writing (it holds the socket).

  What this listener does, per connection:
  * splits the byte stream with `Exjabberd.Xmpp.StreamParser` — several
    stanzas in one TCP packet are all delivered, a stanza split across
    packets is reassembled, and nothing is silently dropped;
  * answers the stream open with exactly ONE valid `<stream:features>`
    block (no bare elements, no duplicates, `from` is the server host);
  * SASL PLAIN and SCRAM-SHA-256 (RFC 5802) for real — no fallback to
    plain inside SCRAM;
  * STARTTLS (RFC 6120 §4.7) with a real `:ssl` handshake; when the
    listener is started with `tls: true` the socket is TLS from the
    first byte (direct-TLS C2S, port 5223);
  * resource binding, then IQ dispatch via `Exjabberd.Iq.dispatch/2`
    (roster, disco, ping, time, version, register, MUC) — server IQs
    are answered on the same socket instead of being routed into the
    void;
  * malformed XML gets a proper stream error (RFC 6120 §4.9) and the
    stream is closed; a stanza over the configured size limit gets a
    `policy-violation` stream error.
  """
  use GenServer
  require Logger

  alias Exjabberd.Auth.Scram
  alias Exjabberd.Xmpp.{Codec, Jid, Stanza, StreamParser}

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 5222)
    tls = Keyword.get(opts, :tls, false)

    cert =
      if tls do
        case Exjabberd.Tls.ensure_cert() do
          {:ok, pair} ->
            pair

          {:error, reason} ->
            Logger.error("C2S TLS cert unavailable: #{inspect(reason)}")
            nil
        end
      else
        nil
      end

    {:ok, ls} =
      :gen_tcp.listen(port, [:binary, packet: 0, active: false, reuseaddr: true, backlog: 128])

    Logger.info(
      "exjabberd C2S listening real on 0.0.0.0:#{port}#{if tls, do: " (direct TLS)", else: ""}"
    )

    send(self(), :accept)
    {:ok, %{ls: ls, port: port, tls: tls, cert: cert}}
  end

  @impl true
  def handle_info(:accept, %{ls: ls} = s) do
    case :gen_tcp.accept(ls, 1000) do
      {:ok, sock} ->
        {:ok, c2s} = Exjabberd.C2S.start_link(host: "localhost")
        pid = spawn_link(fn -> serve(sock, c2s, s.tls, s.cert) end)
        # :ssl.connect (STARTTLS / direct TLS) requires the calling
        # process to own the socket — hand it to the serve process
        # before it reads anything.
        :ok = :gen_tcp.controlling_process(sock, pid)
        send(pid, {:take_socket, sock})

      {:error, :timeout} ->
        :ok

      {:error, e} ->
        Logger.warning("C2S accept error #{inspect(e)}")
        Process.sleep(100)
    end

    send(self(), :accept)
    {:noreply, s}
  end

  # --- per-connection serve loop ---

  defp serve(sock, c2s, tls, _cert) do
    # Wait until the acceptor has transferred socket ownership to us
    # (needed for :ssl.connect); the transfer always precedes this
    # message, so the timeout is only a safety net.
    receive do
      {:take_socket, ^sock} -> :ok
    after
      5_000 -> :ok
    end

    :inet.setopts(sock, active: false)

    if tls do
      case Exjabberd.Tls.ensure_cert() do
        {:ok, pair} ->
          upgrade_to_tls(sock, c2s, pair, %{
            sock: sock,
            kind: :tcp,
            c2s: c2s,
            buf: "",
            tls: false,
            authenticated: false,
            scram: nil,
            host: "localhost",
            stream_open: false,
            max_size: max_stanza_size()
          })

        {:error, reason} ->
          Logger.warning("C2S direct-TLS accept failed: #{inspect(reason)}")
          :gen_tcp.close(sock)
          Exjabberd.C2S.close(c2s, "tls unavailable")
      end
    else
      :ok = Exjabberd.C2S.set_socket(c2s, sock, :tcp)

      loop(%{
        sock: sock,
        kind: :tcp,
        c2s: c2s,
        buf: "",
        tls: false,
        authenticated: false,
        scram: nil,
        host: "localhost",
        stream_open: false,
        max_size: max_stanza_size()
      })
    end
  end

  # Direct-TLS accept: the handshake happens before any XML.
  defp upgrade_to_tls(sock, c2s, cert, state) do
    # Server-side handshake: :ssl.handshake/3 waits for the client's
    # ClientHello. (:ssl.connect/3 is the CLIENT side — it sends a
    # ClientHello, which is why clients answered with an
    # unexpected_message alert before this fix.)
    case :ssl.handshake(sock, Exjabberd.Tls.ssl_opts(cert), 10_000) do
      {:ok, ssl_sock} ->
        :ok = Exjabberd.C2S.set_socket(c2s, ssl_sock, :ssl)
        loop(%{state | sock: ssl_sock, kind: :ssl, tls: true})

      {:error, reason} ->
        Logger.warning("C2S TLS handshake failed: #{inspect(reason)}")
        :gen_tcp.close(sock)
        Exjabberd.C2S.close(c2s, "tls handshake failed")
    end
  end

  defp loop(state) do
    case sock_recv(state, 60_000) do
      {:ok, data} ->
        buf = state.buf <> data

        case StreamParser.parse_buffer(buf, state.max_size) do
          {:ok, units, rest} ->
            state = %{state | buf: rest}

            case process_units(units, state) do
              {:ok, state2} -> loop(state2)
              {:closed, state2} -> cleanup(state2)
            end

          {:error, :too_large} ->
            send_stream_error(
              state,
              "policy-violation",
              "Stanza too large (max #{state.max_size} bytes)"
            )

            cleanup(state)

          {:error, :malformed} ->
            send_stream_error(state, "invalid-xml", "Malformed XML")
            cleanup(state)
        end

      {:error, :closed} ->
        cleanup(state)

      {:error, reason} ->
        Logger.debug("C2S recv #{inspect(reason)}")
        cleanup(state)
    end
  end

  defp process_units(units, state) do
    Enum.reduce_while(units, {:ok, state}, fn unit, {:ok, acc} ->
      case handle_unit(unit, acc) do
        {:ok, next} -> {:cont, {:ok, next}}
        {:closed, next} -> {:halt, {:closed, next}}
      end
    end)
  end

  defp cleanup(state) do
    # Idempotent: the STARTTLS upgrade path already closes the
    # connection inside `loop/1`, so this may run a second time.
    try do
      Exjabberd.C2S.close(state.c2s, "closed")
    catch
      :exit, _ -> :ok
    end

    try do
      sock_close(state)
    catch
      :exit, _ -> :ok
    end

    :ok
  end

  # --- one complete XML unit ---

  defp handle_unit(unit, state) do
    cond do
      String.starts_with?(unit, "<?xml") or String.starts_with?(unit, "<!--") ->
        {:ok, state}

      String.starts_with?(unit, "<stream:stream") ->
        handle_stream_open(unit, state)

      String.starts_with?(unit, "</stream:stream") ->
        sock_send(state, "</stream:stream>")
        Exjabberd.C2S.close(state.c2s, "stream closed")
        {:closed, state}

      String.starts_with?(unit, "<starttls") ->
        handle_starttls(state)

      String.starts_with?(unit, "<auth") ->
        handle_auth(unit, state)

      String.starts_with?(unit, "<response") ->
        handle_scram_response(unit, state)

      String.starts_with?(unit, "<abort") ->
        sock_send(state, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>")
        {:ok, %{state | scram: nil}}

      not state.stream_open ->
        # Stanzas before the stream open are a protocol violation.
        send_stream_error(state, "invalid-namespace", "Stanza before stream open")
        {:closed, state}

      String.starts_with?(unit, "<iq") ->
        handle_iq(unit, state)

      String.starts_with?(unit, "<message") ->
        handle_stanza(unit, state, :message)

      String.starts_with?(unit, "<presence") ->
        handle_stanza(unit, state, :presence)

      true ->
        # Unknown top-level element: dropped, like ejabberd does.
        Logger.debug("C2S dropping unknown element: #{String.slice(unit, 0, 80)}")
        {:ok, state}
    end
  end

  defp handle_stream_open(unit, state) do
    to = attr(unit, "to") || "localhost"
    version = attr(unit, "version")

    if version not in [nil, "1.0"] do
      send_stream_error(state, "unsupported-version", "Only XMPP 1.0 is supported")
      {:closed, state}
    else
      case Exjabberd.C2S.open_stream(state.c2s, to, to) do
        {:ok, header} ->
          sock_send(state, header)
          {:ok, %{state | host: to, stream_open: true, scram: nil}}

        {:error, reason} ->
          Logger.warning("C2S open_stream failed: #{inspect(reason)}")
          {:closed, state}
      end
    end
  end

  defp handle_starttls(state) do
    cond do
      state.tls or state.authenticated ->
        # STARTTLS after TLS (or after auth) is not offered; RFC 6120
        # §4.7.3 says the server answers <failure/>.
        sock_send(state, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        {:ok, state}

      true ->
        case Exjabberd.Tls.ensure_cert() do
          {:ok, cert} ->
            sock_send(state, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            # The upgraded loop runs on the TLS socket until the
            # connection ends; `state.buf` (bytes pipelined after the
            # <starttls/> unit) is carried over.
            upgrade_to_tls(state.sock, state.c2s, cert, state)
            {:closed, %{state | tls: true}}

          {:error, reason} ->
            Logger.warning("C2S STARTTLS cert unavailable: #{inspect(reason)}")
            sock_send(state, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            {:ok, state}
        end
    end
  end

  defp handle_auth(unit, state) do
    mechanism = attr(unit, "mechanism") || ""
    body = inner_text(unit)

    case mechanism do
      "PLAIN" -> handle_plain(body, state)
      "SCRAM-SHA-256" -> handle_scram_first(body, state)
      _ -> send_sasl_failure(state, "invalid-mechanism")
    end
  end

  defp handle_plain(body, state) do
    with {:ok, decoded} <- Base.decode64(String.trim(body)),
         parts when length(parts) == 3 <- String.split(decoded, <<0>>),
         user = Enum.at(parts, 1),
         pass = Enum.at(parts, 2),
         true <- user != "" do
      case Exjabberd.C2S.authenticate(state.c2s, user, pass) do
        :ok ->
          sock_send(state, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
          {:ok, %{state | authenticated: true, scram: nil}}

        _ ->
          send_sasl_failure(state, "not-authorized")
      end
    else
      _ -> send_sasl_failure(state, "malformed-request")
    end
  end

  defp handle_scram_first(body, state) do
    with {:ok, first} <- Scram.parse_client_first(body),
         {:ok, creds} <- Exjabberd.Auth.get_scram(state.host, first.user) do
      {session, server_first} = Scram.server_first(creds, first.client_nonce)

      session = %{session | user: first.user, client_first_bare: first.client_first_bare}
      challenge = Base.encode64(server_first)

      sock_send(
        state,
        "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>#{challenge}</challenge>"
      )

      {:ok, %{state | scram: session}}
    else
      _ -> send_sasl_failure(state, "not-authorized")
    end
  end

  defp handle_scram_response(unit, state) do
    case state.scram do
      nil ->
        send_sasl_failure(state, "not-authorized")

      session ->
        case Scram.verify_client_final(inner_text(unit), session) do
          {:ok, server_final} ->
            :ok = Exjabberd.C2S.authenticate_scram_verified(state.c2s, session.user)

            sock_send(
              state,
              "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>#{Base.encode64(server_final)}</success>"
            )

            {:ok, %{state | authenticated: true, scram: nil}}

          :error ->
            send_sasl_failure(state, "not-authorized")
        end
    end
  end

  defp send_sasl_failure(state, condition) do
    sock_send(
      state,
      "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><#{condition}/></failure>"
    )

    {:ok, %{state | scram: nil}}
  end

  defp handle_iq(unit, state) do
    case Codec.decode(unit) do
      {:ok, stanza} ->
        if bind_iq?(stanza) do
          handle_bind(stanza, state)
        else
          dispatch_iq(stanza, state)
        end

      {:error, _} ->
        send_stream_error(state, "invalid-xml", "Malformed IQ stanza")
        {:closed, state}
    end
  end

  defp bind_iq?(%{name: :iq, type: "set"} = stanza) do
    Stanza.get_subtag(stanza, "urn:ietf:params:xml:ns:xmpp-bind") != nil
  end

  defp bind_iq?(_), do: false

  defp handle_bind(stanza, state) do
    bind_el = Stanza.get_subtag(stanza, "urn:ietf:params:xml:ns:xmpp-bind")
    resource = Stanza.child_text(bind_el && bind_el.children, "resource") || ""
    id = stanza.id || "bind_1"

    case Exjabberd.C2S.bind(state.c2s, resource) do
      {:ok, jid} ->
        jid_s = Jid.to_string(jid)

        result =
          Stanza.new(:iq,
            id: id,
            from: state.host,
            type: "result",
            payload: [
              %{
                name: "bind",
                attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-bind"},
                children: [%{name: "jid", attrs: %{}, children: [jid_s]}]
              }
            ]
          )

        sock_send(state, Codec.encode(result))
        {:ok, state}

      err ->
        Logger.warning("bind fail #{inspect(err)}")

        sock_send(
          state,
          "<iq type='error' id='#{id}'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
        )

        {:ok, state}
    end
  end

  defp dispatch_iq(%{type: type} = stanza, state) when type in ["get", "set"] do
    # Server IQs (no `to`, or addressed to this host / the MUC service)
    # are answered here; IQs to another user are routed.
    to_domain =
      case stanza.to do
        %Jid{domain: d} ->
          d

        bin when is_binary(bin) ->
          bin |> String.split("@") |> List.last() |> String.split("/") |> hd()

        _ ->
          nil
      end

    local? =
      is_nil(to_domain) or Exjabberd.Router.my_host?(to_domain) or
        Exjabberd.Router.conference_domain?(to_domain)

    if local? do
      case Exjabberd.Iq.dispatch(stanza, state.host) do
        {:ok, result} ->
          sock_send(state, Codec.encode(result))
          {:ok, state}

        {:error, _, err_iq} ->
          sock_send(state, Codec.encode(err_iq))
          {:ok, state}

        {:error, reason} ->
          sock_send(state, Codec.encode(Exjabberd.Iq.error_iq(stanza, error_condition(reason))))
          {:ok, state}
      end
    else
      Exjabberd.Router.route(stanza)
      {:ok, state}
    end
  end

  defp dispatch_iq(stanza, state) do
    # IQ result/error stanzas are replies: route them to the requester.
    Exjabberd.Router.route(stanza)
    {:ok, state}
  end

  defp error_condition(:bad_request), do: "bad-request"
  defp error_condition(:not_allowed), do: "not-allowed"
  defp error_condition(:forbidden), do: "forbidden"
  defp error_condition(:not_found), do: "item-not-found"
  defp error_condition(:conflict), do: "conflict"
  defp error_condition(:internal_server_error), do: "internal-server-error"
  defp error_condition(_), do: "internal-server-error"

  defp handle_stanza(unit, state, _kind) do
    case Codec.decode(unit) do
      {:ok, stanza} ->
        Exjabberd.C2S.send_stanza(state.c2s, stanza)
        {:ok, state}

      {:error, _} ->
        send_stream_error(state, "invalid-xml", "Malformed stanza")
        {:closed, state}
    end
  end

  # --- socket helpers ---

  defp sock_recv(%{sock: sock, kind: :ssl}, timeout), do: :ssl.recv(sock, 0, timeout)
  defp sock_recv(%{sock: sock}, timeout), do: :gen_tcp.recv(sock, 0, timeout)

  defp sock_send(%{sock: sock, kind: :ssl}, data) do
    case :ssl.send(sock, data) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("C2S listener ssl send failed: #{inspect(reason)}")
    end
  end

  defp sock_send(%{sock: sock}, data) do
    case :gen_tcp.send(sock, data) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("C2S listener tcp send failed: #{inspect(reason)}")
    end
  end

  defp sock_close(%{sock: sock, kind: :ssl}), do: :ssl.close(sock)
  defp sock_close(%{sock: sock}), do: :gen_tcp.close(sock)

  defp send_stream_error(state, condition, text) do
    sock_send(state, Exjabberd.Xmpp.Stream.error(condition, text) <> "</stream:stream>")
  end

  defp max_stanza_size do
    Exjabberd.Config.get("localhost", :max_stanza_size, 262_144)
  end

  # Attribute value of a single tag (the unit is one complete element).
  defp attr(unit, name) do
    case Regex.run(~r/#{name}=(["'])(.*?)\1/, unit) do
      [_, _, value] -> value
      _ -> nil
    end
  end

  # Text between the first ">" and the last "<" of a single element.
  defp inner_text(unit) do
    case Regex.run(~r/^<[^>]*>(.*)<\/[^>]+>$/s, unit) do
      [_, text] -> text
      _ -> ""
    end
  end
end
