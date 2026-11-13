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
    host = Keyword.get(opts, :host, "localhost")

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
      "exjabberd C2S listening real on 0.0.0.0:#{port}#{if tls, do: " (direct TLS)", else: ""} (host #{host})"
    )

    send(self(), :accept)
    {:ok, %{ls: ls, port: port, tls: tls, cert: cert, host: host}}
  end

  @impl true
  def handle_info(:accept, %{ls: ls} = s) do
    case :gen_tcp.accept(ls, 1000) do
      {:ok, sock} ->
        {:ok, c2s} = Exjabberd.C2S.start_link(host: s.host)
        pid = spawn_link(fn -> serve(sock, c2s, s.tls, s.cert, s.host) end)
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

  defp serve(sock, c2s, tls, _cert, host) do
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
            host: host,
            jid: nil,
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
        host: host,
        jid: nil,
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

      String.starts_with?(unit, "<enable") and attr(unit, "xmlns") == "urn:xmpp:sm:3" ->
        handle_sm_enable(unit, state)

      String.starts_with?(unit, "<resume") and attr(unit, "xmlns") == "urn:xmpp:sm:3" ->
        handle_sm_resume(unit, state)

      sm_nonza?(unit, "r") ->
        handle_sm_request_ack(state)

      sm_nonza?(unit, "a") ->
        handle_sm_client_ack(unit, state)

      String.starts_with?(unit, "<active") and attr(unit, "xmlns") == "urn:xmpp:csi:0" ->
        handle_csi(state, :active)

      String.starts_with?(unit, "<inactive") and attr(unit, "xmlns") == "urn:xmpp:csi:0" ->
        handle_csi(state, :inactive)

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
    # `starttls_required`: no authentication on a plaintext stream —
    # the mechanisms were not advertised either; a client that tries
    # anyway gets a stream error and the connection closes.
    if not state.tls and Exjabberd.Config.starttls_required?(state.host || "localhost") do
      send_stream_error(state, "policy-violation", "STARTTLS is required before authentication")
      {:closed, state}
    else
      mechanism = attr(unit, "mechanism") || ""
      body = inner_text(unit)

      case mechanism do
        "PLAIN" -> handle_plain(body, state)
        "SCRAM-SHA-256" -> handle_scram_first(body, state)
        _ -> send_sasl_failure(state, "invalid-mechanism")
      end
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

  # --- Stream Management (XEP-0198) + CSI (XEP-0352) nonzas ---

  # `<enable/>`: the C2S process answers with `<enabled/>` or
  # `<failed/>`; the reply is not a stanza, so it is written here.
  defp handle_sm_enable(unit, state) do
    resume? = attr(unit, "resume") in ["true", "1"]
    client_max = parse_non_neg_int(attr(unit, "max"))

    case Exjabberd.C2S.sm_enable(state.c2s, resume?, client_max) do
      {:ok, xml} -> sock_send(state, xml)
      {:error, xml} -> sock_send(state, xml)
    end

    {:ok, state}
  end

  # `<resume h previd/>` on a fresh stream (before or after auth).
  # On success the old C2S process takes this socket over; this
  # stream's fresh C2S process is stopped and the serve loop keeps
  # going with the resumed session.
  defp handle_sm_resume(unit, state) do
    previd = attr(unit, "previd") || ""

    case parse_non_neg_int(attr(unit, "h")) do
      {:ok, h} ->
        case Exjabberd.Mod.StreamMgmt.resume(state.host, previd, h, state.sock, state.kind) do
          {:ok, old_pid, _replayed, full_jid} ->
            stop_fresh_c2s(state.c2s)

            jid =
              case Jid.parse(full_jid) do
                {:ok, parsed} -> parsed
                _ -> state.jid
              end

            {:ok, %{state | c2s: old_pid, authenticated: true, jid: jid}}

          {:error, reason} when reason in [:not_found, :superseded] ->
            sock_send(state, Exjabberd.Mod.StreamMgmt.failed_xml("item-not-found"))
            {:ok, state}

          {:error, :count_too_high} ->
            send_count_too_high(state)
            {:closed, state}
        end

      :error ->
        sock_send(state, Exjabberd.Mod.StreamMgmt.failed_xml("bad-request"))
        {:ok, state}
    end
  end

  # `<r/>`: answer with the number of stanzas handled so far.
  defp handle_sm_request_ack(state) do
    case Exjabberd.C2S.sm_request_ack(state.c2s) do
      {:ok, xml} -> sock_send(state, xml)
      {:error, :not_enabled} -> :ok
    end

    {:ok, state}
  end

  # `<a h='N'/>`: the client acked our outbound stanzas up to N.
  defp handle_sm_client_ack(unit, state) do
    case parse_non_neg_int(attr(unit, "h")) do
      {:ok, h} ->
        case Exjabberd.C2S.sm_client_ack(state.c2s, h) do
          {:ok, _} ->
            {:ok, state}

          {:error, :count_too_high, got, sent} ->
            # XEP-0198 §6: the client acked more than we ever sent.
            send_count_too_high(state, got, sent)
            {:closed, state}

          {:error, _} ->
            {:ok, state}
        end

      :error ->
        {:ok, state}
    end
  end

  # `<active/>` / `<inactive/>`: synchronous, so the CSI flush (on
  # active) reaches the wire before any stanza that follows it in
  # the same packet is answered (XEP-0352 §5.1).
  defp handle_csi(state, csi_state) do
    :ok = Exjabberd.C2S.csi_set(state.c2s, csi_state)
    {:ok, state}
  end

  # True for a bare `<r/>` / `<a/>` SM nonza (tag + delimiter, so
  # `<resume/>`, `<response/>` and `<active/>` do not match).
  defp sm_nonza?(unit, tag) do
    (String.starts_with?(unit, "<#{tag} ") or String.starts_with?(unit, "<#{tag}/>") or
       String.starts_with?(unit, "<#{tag}>")) and
      attr(unit, "xmlns") == "urn:xmpp:sm:3"
  end

  defp parse_non_neg_int(nil), do: :error

  defp parse_non_neg_int(str) do
    case Integer.parse(String.trim(str)) do
      {n, ""} when n >= 0 -> {:ok, n}
      _ -> :error
    end
  end

  defp stop_fresh_c2s(pid) do
    try do
      GenServer.stop(pid, :normal)
    catch
      :exit, _ -> :ok
    end

    :ok
  end

  # XEP-0198 §6: the peer acked more stanzas than we sent.
  defp send_count_too_high(state, got \\ nil, sent \\ nil) do
    extra =
      if is_integer(got) and is_integer(sent) do
        "<handled-count-too-high xmlns='urn:xmpp:sm:3' h='#{got}' send-count='#{sent}'/>"
      else
        ""
      end

    sock_send(
      state,
      "<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>" <>
        extra <>
        "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Acknowledged more stanzas than sent</text>" <>
        "</stream:error></stream:stream>"
    )
  end

  defp handle_iq(unit, state) do
    case Codec.decode(unit) do
      {:ok, stanza} ->
        # Clients usually omit `from` on IQs; stamp the bound JID
        # so handlers (carbons enable/disable, roster, ...) see the
        # sender. Message/presence get the same treatment in C2S.
        stanza =
          if stanza.from == nil and state.jid != nil,
            do: %{stanza | from: state.jid},
            else: stanza

        # Every stanza the client sends counts as handled, including
        # IQs answered here instead of routed.
        Exjabberd.C2S.sm_inbound(state.c2s)

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

        # Written directly (not via C2S.send_xml): the bind call
        # itself fires `user_available`, which flushes offline
        # messages into the C2S mailbox — if the result went through
        # the mailbox too, the flush would overtake it on the wire
        # and clients waiting for the bind result would see the
        # offline messages first. Stream Management can never be
        # enabled yet (it requires binding first), so nothing needs
        # counting here.
        sock_send(state, Codec.encode(result))
        {:ok, %{state | jid: jid}}

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
    # An IQ addressed to *another* local user is routed to that
    # user's session — the server must not answer for the peer (RFC
    # 6120 §8.1.3: the recipient is the one who answers). Jingle
    # IQ-sets pass through the signaling gate first (XEP-0166
    # session tracking + errors); everything else goes straight to
    # the router, which bounces to an offline peer with
    # service-unavailable.
    if peer_user_iq?(stanza, state) do
      handle_peer_iq(stanza, state)
    else
      dispatch_local_iq(stanza, state)
    end
  end

  defp dispatch_iq(stanza, state) do
    # IQ result/error stanzas are replies: route them to the requester.
    Exjabberd.Router.route(stanza)
    {:ok, state}
  end

  # True when the IQ is addressed to a different local user (a full
  # or bare JID with a local part, on this host, not the sender).
  defp peer_user_iq?(stanza, state) do
    case stanza.to do
      %Jid{local: local, domain: domain} when is_binary(local) and local != "" ->
        Exjabberd.Router.my_host?(domain) and
          Jid.bare(stanza.to) != sender_bare(state)

      bin when is_binary(bin) ->
        case Jid.parse(bin) do
          {:ok, %Jid{local: local, domain: domain}} when is_binary(local) and local != "" ->
            Exjabberd.Router.my_host?(domain) and Jid.bare(bin) != sender_bare(state)

          _ ->
            false
        end

      _ ->
        false
    end
  end

  defp sender_bare(%{jid: %Jid{} = jid}), do: Jid.bare(jid)
  defp sender_bare(_), do: nil

  defp handle_peer_iq(stanza, state) do
    cond do
      stanza.type == "set" and jingle_iq?(stanza) ->
        case Exjabberd.Mod.Jingle.intercept(stanza, state.host) do
          :route ->
            Exjabberd.Router.route(stanza)

          {:error, condition, jingle_condition} ->
            Exjabberd.C2S.send_xml(
              state.c2s,
              Codec.encode(
                Exjabberd.Mod.Jingle.error_iq(stanza, state.host, condition, jingle_condition)
              )
            )
        end

      server_handled_peer_iq?(stanza) ->
        dispatch_local_iq(stanza, state)

      true ->
        Exjabberd.Router.route(stanza)
    end

    {:ok, state}
  end

  defp jingle_iq?(stanza),
    do: Exjabberd.Xmpp.Stanza.get_subtag(stanza, "urn:xmpp:jingle:1") != nil

  # IQs the server itself must answer even though they are
  # addressed to a local user: PEP (XEP-0163 — PubSub at a user's
  # JID is a server service, not the client) and disco to a *bare*
  # JID (the account's own features and PEP nodes; disco to a full
  # JID belongs to that client). Without this, a peer's OMEMO
  # fetch or bare-JID disco query would be delivered to the user's
  # client socket and never answered by the server.
  defp server_handled_peer_iq?(stanza) do
    stanza.type in ["get", "set"] and
      case Exjabberd.Iq.payload_xmlns(stanza) do
        "http://jabber.org/protocol/pubsub" -> true
        "http://jabber.org/protocol/pubsub#owner" -> true
        # vCard (XEP-0054) and last activity (XEP-0012) are answered
        # by the server on behalf of the addressee, like ejabberd.
        "vcard-temp" -> true
        "jabber:iq:last" -> true
        "http://jabber.org/protocol/disco#info" -> bare_jid?(stanza.to)
        "http://jabber.org/protocol/disco#items" -> bare_jid?(stanza.to)
        _ -> false
      end
  end

  defp bare_jid?(%Jid{local: local, resource: nil})
       when is_binary(local) and local != "",
       do: true

  defp bare_jid?(bin) when is_binary(bin), do: not String.contains?(bin, "/")
  defp bare_jid?(_), do: false

  defp dispatch_local_iq(stanza, state) do
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
        Exjabberd.Router.conference_domain?(to_domain) or
        Exjabberd.Router.pubsub_domain?(to_domain)

    if local? do
      case Exjabberd.Iq.dispatch(stanza, state.host) do
        {:ok, result} ->
          # Via C2S so Stream Management counts the reply and wire
          # order against routed stanzas is kept.
          Exjabberd.C2S.send_xml(state.c2s, Codec.encode(result))
          {:ok, state}

        {:error, _, err_iq} ->
          Exjabberd.C2S.send_xml(state.c2s, Codec.encode(err_iq))
          {:ok, state}

        {:error, reason} ->
          Exjabberd.C2S.send_xml(
            state.c2s,
            Codec.encode(Exjabberd.Iq.error_iq(stanza, error_condition(reason)))
          )

          {:ok, state}
      end
    else
      Exjabberd.Router.route(stanza)
      {:ok, state}
    end
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
        # Count the stanza as handled (XEP-0198 `h`).
        Exjabberd.C2S.sm_inbound(state.c2s)
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
