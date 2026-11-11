defmodule Exjabberd.Http.XmppTransport do
  @moduledoc """
  One XMPP session over a non-TCP transport (BOSH, WebSocket).

  This is the same session the TCP listener drives in
  `Exjabberd.Listener.C2S`, factored out so BOSH and WebSocket speak
  exactly the same XMPP: stream open, SASL PLAIN + SCRAM-SHA-256,
  resource binding, Stream Management, CSI, IQ dispatch (roster,
  disco, MAM, PubSub, upload slots, …) and message/presence routing.

  The difference from TCP is only the wire: a `Exjabberd.C2S`
  process is started with `out_pid` set to the transport owner, so
  outbound XML arrives as `{:xmpp_out, xml}` messages instead of
  going to a socket, and the replies the TCP listener writes
  directly to the socket (stream header/features, SASL success,
  bind result, SM answers) are returned here as a list of XML
  strings for the transport to send. IQ answers go through
  `C2S.send_xml/2` like on TCP (so Stream Management counts them);
  the transport calls `C2S.sync/1` afterwards to make sure they
  have reached its outbound queue before it answers the client.

  Stream Management resumption across connections is NOT supported
  over these transports (`C2S` answers `<failed/>`
  `item-not-found`): BOSH already retransmits by `rid`, and a
  WebSocket reconnect starts a fresh stream. SM `<enable/>` inside
  one session works (counting + `<a h/>` answers).
  """

  require Logger

  alias Exjabberd.Auth.Scram
  alias Exjabberd.Xmpp.{Codec, Jid, Stanza, Stream, StreamParser}

  @type t :: %{
          c2s: pid(),
          host: binary(),
          out_pid: pid(),
          stream_open: boolean(),
          authenticated: boolean(),
          jid: Jid.t() | nil,
          scram: map() | nil,
          max_size: non_neg_integer()
        }

  @doc "Start a session: a fresh C2S process whose outbound XML goes to `out_pid`."
  @spec start(binary(), pid()) :: {:ok, t()} | {:error, term()}
  def start(host, out_pid) do
    case Exjabberd.C2S.start_link(host: host, out_pid: out_pid) do
      {:ok, c2s} ->
        {:ok,
         %{
           c2s: c2s,
           host: host,
           out_pid: out_pid,
           stream_open: false,
           authenticated: false,
           jid: nil,
           scram: nil,
           max_size: max_stanza_size()
         }}

      err ->
        err
    end
  end

  @doc "Bound JID, or nil before resource binding."
  @spec jid(t()) :: Jid.t() | nil
  def jid(%{jid: jid}), do: jid

  @doc "Open the stream. Returns `{state, header_xml, features_xml}`."
  @spec open_stream(t(), binary()) :: {:ok, t(), binary(), binary()} | {:error, term()}
  def open_stream(state, to) do
    case Exjabberd.C2S.open_stream(state.c2s, to, to) do
      {:ok, header_and_features} ->
        {header, features} = split_header_features(header_and_features)
        {:ok, %{state | host: to, stream_open: true, scram: nil}, header, features}

      err ->
        err
    end
  end

  @doc """
  Handle one complete top-level XML unit from the client.

  Returns `{:ok, state, outs}` (keep going, send `outs` to the
  client) or `{:closed, state, outs}` (send `outs`, then end the
  session with `close/1`).
  """
  @spec handle_unit(t(), binary()) :: {:ok, t(), [binary()]} | {:closed, t(), [binary()]}
  def handle_unit(state, unit) do
    cond do
      String.starts_with?(unit, "<?xml") or String.starts_with?(unit, "<!--") ->
        {:ok, state, []}

      String.starts_with?(unit, "<stream:stream") ->
        handle_stream_open(unit, state)

      String.starts_with?(unit, "<open") ->
        handle_framing_open(unit, state)

      String.starts_with?(unit, "</stream:stream") or String.starts_with?(unit, "</open") ->
        close_tag =
          if String.starts_with?(unit, "</open"), do: "</open>", else: "</stream:stream>"

        {:closed, state, [close_tag]}

      String.starts_with?(unit, "<starttls") ->
        {:ok, state, ["<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"]}

      String.starts_with?(unit, "<auth") ->
        handle_auth(unit, state)

      String.starts_with?(unit, "<response") ->
        handle_scram_response(unit, state)

      String.starts_with?(unit, "<abort") ->
        {:ok, %{state | scram: nil},
         ["<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><aborted/></failure>"]}

      not state.stream_open ->
        {:closed, state,
         [Stream.error("invalid-namespace", "Stanza before stream open") <> "</stream:stream>"]}

      String.starts_with?(unit, "<enable") and attr(unit, "xmlns") == "urn:xmpp:sm:3" ->
        handle_sm_enable(unit, state)

      String.starts_with?(unit, "<resume") and attr(unit, "xmlns") == "urn:xmpp:sm:3" ->
        {:ok, state, [Exjabberd.Mod.StreamMgmt.failed_xml("item-not-found")]}

      sm_nonza?(unit, "r") ->
        handle_sm_request_ack(state)

      sm_nonza?(unit, "a") ->
        handle_sm_client_ack(unit, state)

      String.starts_with?(unit, "<active") and attr(unit, "xmlns") == "urn:xmpp:csi:0" ->
        :ok = Exjabberd.C2S.csi_set(state.c2s, :active)
        {:ok, state, []}

      String.starts_with?(unit, "<inactive") and attr(unit, "xmlns") == "urn:xmpp:csi:0" ->
        :ok = Exjabberd.C2S.csi_set(state.c2s, :inactive)
        {:ok, state, []}

      String.starts_with?(unit, "<iq") ->
        handle_iq(unit, state)

      String.starts_with?(unit, "<message") ->
        handle_stanza(unit, state)

      String.starts_with?(unit, "<presence") ->
        handle_stanza(unit, state)

      true ->
        Logger.debug("XMPP transport dropping unknown element: #{String.slice(unit, 0, 80)}")
        {:ok, state, []}
    end
  end

  @doc "End the session for real (unregisters routes, flushes offline, stops the C2S process)."
  @spec close(t()) :: :ok
  def close(%{c2s: c2s}) do
    try do
      GenServer.call(c2s, :sm_terminate_now, 5_000)
    catch
      :exit, _ -> :ok
    end

    :ok
  end

  @doc "Split a raw XMPP byte buffer into complete units (shared with the TCP listener)."
  @spec parse_buffer(binary(), non_neg_integer()) ::
          {:ok, [binary()], binary()} | {:error, :malformed | :too_large}
  def parse_buffer(buf, max_size), do: StreamParser.parse_buffer(buf, max_size)

  # --- stream open ---

  defp handle_stream_open(unit, state) do
    to = attr(unit, "to") || state.host
    version = attr(unit, "version")

    if version not in [nil, "1.0"] do
      {:closed, state,
       [Stream.error("unsupported-version", "Only XMPP 1.0 is supported") <> "</stream:stream>"]}
    else
      case open_stream(state, to) do
        {:ok, state, header, features} -> {:ok, state, [header <> features]}
        {:error, _} -> {:closed, state, []}
      end
    end
  end

  # RFC 7395 §3.3 framing: `<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>`
  # instead of `<stream:stream>`. Same stream, different envelope.
  defp handle_framing_open(unit, state) do
    to = attr(unit, "to") || state.host

    case open_stream(state, to) do
      {:ok, state, _header, features} ->
        id = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)

        open =
          "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='#{to}' id='#{id}' version='1.0'/>"

        {:ok, state, [open <> features]}

      {:error, _} ->
        {:closed, state, []}
    end
  end

  defp split_header_features(header_and_features) do
    case :binary.split(header_and_features, "<stream:features>") do
      [header, rest] -> {header, "<stream:features>" <> rest}
      _ -> {header_and_features, ""}
    end
  end

  # --- SASL ---

  defp handle_auth(unit, state) do
    mechanism = attr(unit, "mechanism") || ""
    body = inner_text(unit)

    case mechanism do
      "PLAIN" -> handle_plain(body, state)
      "SCRAM-SHA-256" -> handle_scram_first(body, state)
      _ -> {:ok, state, [sasl_failure("invalid-mechanism")]}
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
          {:ok, %{state | authenticated: true, scram: nil},
           ["<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"]}

        _ ->
          {:ok, state, [sasl_failure("not-authorized")]}
      end
    else
      _ -> {:ok, state, [sasl_failure("malformed-request")]}
    end
  end

  defp handle_scram_first(body, state) do
    with {:ok, first} <- Scram.parse_client_first(body),
         {:ok, creds} <- Exjabberd.Auth.get_scram(state.host, first.user) do
      {session, server_first} = Scram.server_first(creds, first.client_nonce)
      session = %{session | user: first.user, client_first_bare: first.client_first_bare}
      challenge = Base.encode64(server_first)

      {:ok, %{state | scram: session},
       ["<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>#{challenge}</challenge>"]}
    else
      _ -> {:ok, state, [sasl_failure("not-authorized")]}
    end
  end

  defp handle_scram_response(unit, state) do
    case state.scram do
      nil ->
        {:ok, state, [sasl_failure("not-authorized")]}

      session ->
        case Scram.verify_client_final(inner_text(unit), session) do
          {:ok, server_final} ->
            :ok = Exjabberd.C2S.authenticate_scram_verified(state.c2s, session.user)

            {:ok, %{state | authenticated: true, scram: nil},
             [
               "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>#{Base.encode64(server_final)}</success>"
             ]}

          :error ->
            {:ok, state, [sasl_failure("not-authorized")]}
        end
    end
  end

  defp sasl_failure(condition),
    do: "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><#{condition}/></failure>"

  # --- Stream Management + CSI ---

  defp handle_sm_enable(unit, state) do
    resume? = attr(unit, "resume") in ["true", "1"]
    client_max = parse_non_neg_int(attr(unit, "max"))

    case Exjabberd.C2S.sm_enable(state.c2s, resume?, client_max) do
      {:ok, xml} -> {:ok, state, [xml]}
      {:error, xml} -> {:ok, state, [xml]}
    end
  end

  defp handle_sm_request_ack(state) do
    case Exjabberd.C2S.sm_request_ack(state.c2s) do
      {:ok, xml} -> {:ok, state, [xml]}
      {:error, :not_enabled} -> {:ok, state, []}
    end
  end

  defp handle_sm_client_ack(unit, state) do
    case parse_non_neg_int(attr(unit, "h")) do
      {:ok, h} ->
        case Exjabberd.C2S.sm_client_ack(state.c2s, h) do
          {:ok, _} ->
            {:ok, state, []}

          {:error, :count_too_high, got, sent} ->
            {:closed, state, [count_too_high_xml(got, sent)]}

          {:error, _} ->
            {:ok, state, []}
        end

      :error ->
        {:ok, state, []}
    end
  end

  defp count_too_high_xml(got, sent) do
    "<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>" <>
      "<handled-count-too-high xmlns='urn:xmpp:sm:3' h='#{got}' send-count='#{sent}'/>" <>
      "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Acknowledged more stanzas than sent</text>" <>
      "</stream:error></stream:stream>"
  end

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

  # --- IQ / stanzas ---

  defp handle_iq(unit, state) do
    case Codec.decode(unit) do
      {:ok, stanza} ->
        stanza =
          if stanza.from == nil and state.jid != nil,
            do: %{stanza | from: state.jid},
            else: stanza

        Exjabberd.C2S.sm_inbound(state.c2s)

        if bind_iq?(stanza) do
          handle_bind(stanza, state)
        else
          dispatch_iq(stanza, state)
        end

      {:error, _} ->
        {:closed, state,
         [Stream.error("invalid-xml", "Malformed IQ stanza") <> "</stream:stream>"]}
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

        # Sent synchronously (not via C2S.send_xml): the bind itself
        # fires `user_available`, which flushes offline messages into
        # the C2S mailbox — if the result went through the mailbox
        # too, the flush would overtake it on the wire. Same reason
        # as the TCP listener's direct write.
        {:ok, %{state | jid: jid}, [Codec.encode(result)]}

      _ ->
        {:ok, state,
         [
           "<iq type='error' id='#{id}'><error type='cancel'><not-allowed xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>"
         ]}
    end
  end

  defp dispatch_iq(%{type: type} = stanza, state) when type in ["get", "set"] do
    # Same rule as the TCP listener: an IQ to another local user is
    # routed to that user (Jingle IQ-sets through the signaling
    # gate first); only server- / self-addressed IQs are answered
    # locally.
    if peer_user_iq?(stanza, state) do
      handle_peer_iq(stanza, state)
    else
      dispatch_local_iq(stanza, state)
    end
  end

  defp dispatch_iq(stanza, state) do
    Exjabberd.Router.route(stanza)
    {:ok, state, []}
  end

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
      stanza.type == "set" and
          Exjabberd.Xmpp.Stanza.get_subtag(stanza, "urn:xmpp:jingle:1") != nil ->
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

    {:ok, state, []}
  end

  # Same rule as the TCP listener: PEP and bare-JID disco addressed
  # to a local user are answered by the server, not the client.
  defp server_handled_peer_iq?(stanza) do
    stanza.type in ["get", "set"] and
      case Exjabberd.Iq.payload_xmlns(stanza) do
        "http://jabber.org/protocol/pubsub" -> true
        "http://jabber.org/protocol/pubsub#owner" -> true
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
          Exjabberd.C2S.send_xml(state.c2s, Codec.encode(result))

        {:error, _, err_iq} ->
          Exjabberd.C2S.send_xml(state.c2s, Codec.encode(err_iq))

        {:error, reason} ->
          Exjabberd.C2S.send_xml(
            state.c2s,
            Codec.encode(Exjabberd.Iq.error_iq(stanza, error_condition(reason)))
          )
      end

      {:ok, state, []}
    else
      Exjabberd.Router.route(stanza)
      {:ok, state, []}
    end
  end

  defp error_condition(:bad_request), do: "bad-request"
  defp error_condition(:not_allowed), do: "not-allowed"
  defp error_condition(:forbidden), do: "forbidden"
  defp error_condition(:not_found), do: "item-not-found"
  defp error_condition(:conflict), do: "conflict"
  defp error_condition(_), do: "internal-server-error"

  defp handle_stanza(unit, state) do
    case Codec.decode(unit) do
      {:ok, stanza} ->
        Exjabberd.C2S.send_stanza(state.c2s, stanza)
        Exjabberd.C2S.sm_inbound(state.c2s)
        {:ok, state, []}

      {:error, _} ->
        {:closed, state, [Stream.error("invalid-xml", "Malformed stanza") <> "</stream:stream>"]}
    end
  end

  # --- helpers ---

  defp max_stanza_size do
    Exjabberd.Config.get("localhost", :max_stanza_size, 262_144)
  end

  defp attr(unit, name) do
    case Regex.run(~r/#{name}=(["'])(.*?)\1/, unit) do
      [_, _, value] -> value
      _ -> nil
    end
  end

  defp inner_text(unit) do
    case Regex.run(~r/^<[^>]*>(.*)<\/[^>]+>$/s, unit) do
      [_, text] -> text
      _ -> ""
    end
  end
end
