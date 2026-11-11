defmodule Exjabberd.Listener.S2S do
  @moduledoc """
  Inbound S2S TCP listener (ejabberd_s2s_in equivalent, RFC 6120 §4 +
  XEP-0220 Server Dialback).

  Binds the configured S2S port (5269 by default), accepts server
  streams (`xmlns='jabber:server'`) and drives one serve-loop process
  per connection. The serve loop owns reading; verified stanzas are
  handed to `Exjabberd.Router`, which delivers them to local sessions
  or local services.

  What one connection does:
  * answers the stream open with a stream header (fresh random stream
    ID — the ID dialback keys are bound to) plus `<stream:features>`
    advertising STARTTLS (optional) and dialback;
  * STARTTLS upgrade via `:ssl` (same dev certificate as C2S);
  * as Receiving Server: on `<db:result/>`, verifies the key by
    opening a dialback connection to the Authoritative Server for the
    asserted Sender Domain (`Exjabberd.S2S.Dialback.verify_remote/4`)
    and answers `<db:result type='valid'|'invalid'/>` — an invalid
    key closes the stream;
  * as Authoritative Server: on `<db:verify/>`, recomputes the key
    from our own secret and answers `type='valid'|'invalid'`;
  * stanzas are routed only from a dialback-verified connection, and
    only when their `from` domain matches the verified domain —
    anything else is dropped (unverified) or refused with a
    `not-authorized` stream error.
  """

  use GenServer
  require Logger

  alias Exjabberd.S2S.Dialback
  alias Exjabberd.Xmpp.{Codec, Jid, Stream, StreamParser}

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 5269)
    host = Keyword.get(opts, :host, "localhost")

    {:ok, ls} =
      :gen_tcp.listen(port, [:binary, packet: 0, active: false, reuseaddr: true, backlog: 128])

    Logger.info("exjabberd S2S listening real on 0.0.0.0:#{port} (host #{host})")
    send(self(), :accept)
    {:ok, %{ls: ls, port: port, host: host}}
  end

  @impl true
  def handle_info(:accept, %{ls: ls} = s) do
    case :gen_tcp.accept(ls, 1000) do
      {:ok, sock} ->
        pid = spawn_link(fn -> serve(sock, s.host) end)
        :ok = :gen_tcp.controlling_process(sock, pid)
        send(pid, {:take_socket, sock})

      {:error, :timeout} ->
        :ok

      {:error, e} ->
        Logger.warning("S2S accept error #{inspect(e)}")
        Process.sleep(100)
    end

    send(self(), :accept)
    {:noreply, s}
  end

  # --- per-connection serve loop ---

  defp serve(sock, host) do
    receive do
      {:take_socket, ^sock} -> :ok
    after
      5_000 -> :ok
    end

    :inet.setopts(sock, active: false)

    loop(%{
      sock: sock,
      kind: :tcp,
      host: host,
      buf: "",
      tls: false,
      stream_open: false,
      stream_id: nil,
      remote_domain: nil,
      verified: nil,
      max_size: max_stanza_size()
    })
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
            send_stream_error(state, "policy-violation", "Stanza too large")
            cleanup(state)

          {:error, :malformed} ->
            send_stream_error(state, "invalid-xml", "Malformed XML")
            cleanup(state)
        end

      {:error, :closed} ->
        cleanup(state)

      {:error, reason} ->
        Logger.debug("S2S recv #{inspect(reason)}")
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
        {:closed, state}

      String.starts_with?(unit, "<starttls") ->
        handle_starttls(state)

      String.starts_with?(unit, "<db:result") ->
        handle_db_result(unit, state)

      String.starts_with?(unit, "<db:verify") ->
        handle_db_verify(unit, state)

      not state.stream_open ->
        send_stream_error(state, "invalid-namespace", "Stanza before stream open")
        {:closed, state}

      String.starts_with?(unit, "<message") or String.starts_with?(unit, "<presence") or
          String.starts_with?(unit, "<iq") ->
        handle_stanza(unit, state)

      true ->
        Logger.debug("S2S dropping unknown element: #{String.slice(unit, 0, 80)}")
        {:ok, state}
    end
  end

  defp handle_stream_open(unit, state) do
    from = attr(unit, "from")
    to = attr(unit, "to")
    xmlns = attr(unit, "xmlns")
    version = attr(unit, "version")

    cond do
      xmlns != "jabber:server" ->
        send_stream_error(state, "invalid-namespace", "S2S streams use jabber:server")
        {:closed, state}

      version not in [nil, "1.0"] ->
        send_stream_error(state, "unsupported-version", "Only XMPP 1.0 is supported")
        {:closed, state}

      from in [nil, ""] ->
        send_stream_error(state, "invalid-from", "Stream open without from domain")
        {:closed, state}

      to not in [nil, ""] and not Exjabberd.Router.my_host?(to) ->
        send_stream_error(state, "host-unknown", "Unknown target domain #{to}")
        {:closed, state}

      true ->
        stream_id = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
        host = state.host

        header =
          "<?xml version='1.0'?><stream:stream xmlns='jabber:server' " <>
            "xmlns:stream='http://etherx.jabber.org/streams' " <>
            "xmlns:db='jabber:server:dialback' from='#{host}' to='#{from}' " <>
            "id='#{stream_id}' version='1.0'>"

        # STARTTLS is only offered before TLS (RFC 6120 §4.7):
        # after the upgrade the feature must disappear, or a
        # peer that re-reads features would request it again.
        features =
          "<stream:features>" <>
            if(state.tls,
              do: "",
              else: "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
            ) <>
            "<dialback xmlns='urn:xmpp:features:dialback'/>" <>
            "</stream:features>"

        sock_send(state, header <> features)

        {:ok,
         %{state | stream_open: true, stream_id: stream_id, remote_domain: from, verified: nil}}
    end
  end

  defp handle_starttls(state) do
    cond do
      state.tls ->
        sock_send(state, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        {:ok, state}

      true ->
        case Exjabberd.Tls.ensure_cert() do
          {:ok, cert} ->
            sock_send(state, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            upgrade_to_tls(state.sock, cert, state)
            {:closed, %{state | tls: true}}

          {:error, reason} ->
            Logger.warning("S2S STARTTLS cert unavailable: #{inspect(reason)}")
            sock_send(state, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            {:ok, state}
        end
    end
  end

  # Server-side TLS handshake, then a fresh stream is expected.
  defp upgrade_to_tls(sock, cert, state) do
    case :ssl.handshake(sock, Exjabberd.Tls.ssl_opts(cert), 10_000) do
      {:ok, ssl_sock} ->
        loop(%{state | sock: ssl_sock, kind: :ssl, tls: true, buf: "", stream_open: false})

      {:error, reason} ->
        Logger.warning("S2S TLS handshake failed: #{inspect(reason)}")
        :gen_tcp.close(sock)
    end
  end

  # --- Dialback: Receiving Server side ---

  defp handle_db_result(unit, state) do
    with {:ok, %{attrs: attrs, children: children}} <- Codec.parse_xml(unit),
         from when is_binary(from) <- Map.get(attrs, "from"),
         to when is_binary(to) <- Map.get(attrs, "to"),
         key <- children |> Enum.filter(&is_binary/1) |> Enum.join("") |> String.trim(),
         true <- state.stream_open do
      cond do
        not Exjabberd.Router.my_host?(to) ->
          # Target Domain is not one of our domains: a dialback
          # error, not a stream error (XEP-0220 §2.2.1) — the stream
          # stays open for other domain pairs.
          sock_send(
            state,
            "<db:result xmlns:db='jabber:server:dialback' from='#{state.host}' to='#{from}' type='error'>" <>
              "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" <>
              "</db:result>"
          )

          {:ok, state}

        Exjabberd.Router.my_host?(from) ->
          sock_send(
            state,
            "<db:result xmlns:db='jabber:server:dialback' from='#{state.host}' to='#{from}' type='error'>" <>
              "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>" <>
              "</db:result>"
          )

          {:ok, state}

        true ->
          case Dialback.verify_remote(from, state.host, state.stream_id, key) do
            :ok ->
              Logger.info("S2S dialback verified #{from} -> #{state.host} (tls=#{state.tls})")

              sock_send(
                state,
                "<db:result xmlns:db='jabber:server:dialback' from='#{state.host}' to='#{from}' type='valid'/>"
              )

              {:ok, %{state | verified: String.downcase(from)}}

            {:error, reason} ->
              Logger.warning("S2S dialback invalid for #{from}: #{inspect(reason)}")

              sock_send(
                state,
                "<db:result xmlns:db='jabber:server:dialback' from='#{state.host}' to='#{from}' type='invalid'/>"
              )

              # An invalid key closes the stream (XEP-0220 §2.2.1,
              # pre-errors behaviour).
              {:closed, state}
          end
      end
    else
      _ ->
        Logger.warning("S2S malformed db:result, closing")
        send_stream_error(state, "invalid-xml", "Malformed db:result")
        {:closed, state}
    end
  end

  # --- Dialback: Authoritative Server side ---

  defp handle_db_verify(unit, state) do
    with {:ok, %{attrs: attrs, children: children}} <- Codec.parse_xml(unit),
         from when is_binary(from) <- Map.get(attrs, "from"),
         to when is_binary(to) <- Map.get(attrs, "to"),
         id when is_binary(id) <- Map.get(attrs, "id"),
         key <- children |> Enum.filter(&is_binary/1) |> Enum.join("") |> String.trim(),
         true <- state.stream_open do
      # The key was generated by the Initiating Server for the pair
      # (Sender Domain = `to` here, Target Domain = `from` here)
      # bound to the Receiving Server's stream ID (`id`).
      valid =
        try do
          Dialback.verify_key(Dialback.secret(), id, to, from, key)
        rescue
          _ -> false
        end

      type = if valid, do: "valid", else: "invalid"

      Logger.info("S2S dialback verify #{to} -> #{from} id=#{id}: #{type}")

      sock_send(
        state,
        "<db:verify xmlns:db='jabber:server:dialback' from='#{to}' to='#{from}' id='#{id}' type='#{type}'/>"
      )

      {:ok, state}
    else
      _ ->
        Logger.warning("S2S malformed db:verify, closing")
        send_stream_error(state, "invalid-xml", "Malformed db:verify")
        {:closed, state}
    end
  end

  # --- stanzas from a (hopefully verified) peer ---

  defp handle_stanza(unit, state) do
    case Codec.decode(unit) do
      {:ok, stanza} ->
        cond do
          state.verified == nil ->
            Logger.warning("S2S stanza on unverified connection, refusing")
            send_stream_error(state, "not-authorized", "Dialback verification required")
            {:closed, state}

          not from_domain?(stanza.from, state.verified) ->
            Logger.warning(
              "S2S stanza from #{inspect(stanza.from)} on connection verified for #{state.verified}, dropping"
            )

            {:ok, state}

          stanza.name == :iq and stanza.type in ["get", "set"] and service_addressed?(stanza) ->
            dispatch_service_iq(stanza, state)

          # Federated Jingle to a local user: same signaling gate as
          # local clients — track the session, route to the peer, or
          # answer the error back over S2S. (Jingle to a remote user
          # is not our business: it is routed onward untouched.)
          stanza.name == :iq and stanza.type == "set" and jingle_to_local_user?(stanza) ->
            case Exjabberd.Mod.Jingle.intercept(stanza, state.host) do
              :route ->
                Exjabberd.Router.route(stanza)

              {:error, condition, jingle_condition} ->
                Exjabberd.Router.route(
                  Exjabberd.Mod.Jingle.error_iq(stanza, state.host, condition, jingle_condition)
                )
            end

            {:ok, state}

          # Federated PEP / bare-JID disco to a local user: same
          # server-side service as for local clients — answer here
          # and route the reply back over S2S.
          stanza.name == :iq and stanza.type in ["get", "set"] and
              pep_or_bare_disco_to_local_user?(stanza) ->
            dispatch_service_iq(stanza, state)

          true ->
            Exjabberd.Router.route(stanza)
            {:ok, state}
        end

      {:error, _} ->
        send_stream_error(state, "invalid-xml", "Malformed stanza")
        {:closed, state}
    end
  end

  defp jingle_to_local_user?(stanza) do
    Exjabberd.Xmpp.Stanza.get_subtag(stanza, "urn:xmpp:jingle:1") != nil and
      case stanza.to do
        %Exjabberd.Xmpp.Jid{local: local, domain: domain}
        when is_binary(local) and local != "" ->
          Exjabberd.Router.my_host?(domain)

        _ ->
          false
      end
  end

  defp pep_or_bare_disco_to_local_user?(stanza) do
    local_user? =
      case stanza.to do
        %Exjabberd.Xmpp.Jid{local: local, domain: domain}
        when is_binary(local) and local != "" ->
          Exjabberd.Router.my_host?(domain)

        _ ->
          false
      end

    local_user? and
      case Exjabberd.Iq.payload_xmlns(stanza) do
        "http://jabber.org/protocol/pubsub" -> true
        "http://jabber.org/protocol/pubsub#owner" -> true
        "http://jabber.org/protocol/disco#info" -> bare_jid?(stanza.to)
        "http://jabber.org/protocol/disco#items" -> bare_jid?(stanza.to)
        _ -> false
      end
  end

  defp bare_jid?(%Exjabberd.Xmpp.Jid{local: local, resource: nil})
       when is_binary(local) and local != "",
       do: true

  defp bare_jid?(_), do: false

  # An IQ addressed to the server domain itself (no `to`, or `to` is
  # the bare domain) is answered by the local service; the answer is
  # routed back to the foreign requester through the router (which
  # opens the reverse S2S connection for it).
  defp dispatch_service_iq(stanza, state) do
    host = state.host

    case Exjabberd.Iq.dispatch(stanza, host) do
      {:ok, result} ->
        Exjabberd.Router.route(result)

      {:error, _, err} ->
        Exjabberd.Router.route(err)

      {:error, reason} ->
        Exjabberd.Router.route(Exjabberd.Iq.error_iq(stanza, error_condition(reason)))
    end

    {:ok, state}
  end

  defp error_condition(:bad_request), do: "bad-request"
  defp error_condition(:not_allowed), do: "not-allowed"
  defp error_condition(:forbidden), do: "forbidden"
  defp error_condition(:not_found), do: "item-not-found"
  defp error_condition(:conflict), do: "conflict"
  defp error_condition(_), do: "internal-server-error"

  defp service_addressed?(%{to: nil}), do: true

  defp service_addressed?(%{to: %Jid{local: nil, domain: domain}}) do
    Exjabberd.Router.my_host?(domain)
  end

  defp service_addressed?(%{to: to}) when is_binary(to) do
    not String.contains?(to, "@") and Exjabberd.Router.my_host?(String.split(to, "/") |> hd())
  end

  defp service_addressed?(_), do: false

  defp from_domain?(%Jid{domain: domain}, verified),
    do: String.downcase(domain) == verified

  defp from_domain?(bin, verified) when is_binary(bin) do
    case Jid.parse(bin) do
      {:ok, %Jid{domain: domain}} -> String.downcase(domain) == verified
      _ -> false
    end
  end

  defp from_domain?(_, _), do: false

  # --- socket helpers ---

  defp sock_recv(%{sock: sock, kind: :ssl}, timeout), do: :ssl.recv(sock, 0, timeout)
  defp sock_recv(%{sock: sock}, timeout), do: :gen_tcp.recv(sock, 0, timeout)

  defp sock_send(%{sock: sock, kind: :ssl}, data) do
    case :ssl.send(sock, data) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("S2S listener ssl send failed: #{inspect(reason)}")
    end
  end

  defp sock_send(%{sock: sock}, data) do
    case :gen_tcp.send(sock, data) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("S2S listener tcp send failed: #{inspect(reason)}")
    end
  end

  defp sock_close(%{sock: sock, kind: :ssl}), do: :ssl.close(sock)
  defp sock_close(%{sock: sock}), do: :gen_tcp.close(sock)

  defp send_stream_error(state, condition, text) do
    sock_send(state, Stream.error(condition, text) <> "</stream:stream>")
  end

  defp max_stanza_size do
    Exjabberd.Config.get("localhost", :max_stanza_size, 262_144)
  end

  defp attr(unit, name) do
    case Regex.run(~r/#{name}=(["'])(.*?)\1/, unit) do
      [_, _, value] -> value
      _ -> nil
    end
  end
end
