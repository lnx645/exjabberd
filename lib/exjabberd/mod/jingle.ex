defmodule Exjabberd.Mod.Jingle do
  @moduledoc """
  Jingle — XEP-0166 (signaling) + XEP-0176 (ICE-UDP transport-info)
  + XEP-0215 (external service discovery for STUN/TURN).

  The server is a *signaling* relay, not a media endpoint: it
  tracks sessions (initiator, responder, `sid`, state) and routes
  the clients' IQ-sets to each other. Media never touches this
  server — it flows peer-to-peer, or through the TURN relay on
  port 5478 (`Exjabberd.StunTurn.Server`).

  How routing works here: an IQ-set addressed to *another* local
  user is not answered by the server — the C2S listener (and the
  BOSH/WebSocket transport, and the S2S listener for federated
  senders) hands it to `intercept/2` first, which validates the
  action against the session state machine and either lets the
  stanza through to the peer (`:route`) or answers it with a
  Jingle error (`unknown-session`, `out-of-order`, `tie-break`,
  `feature-not-implemented`, `bad-request`, `forbidden` — XEP-0166
  §10, with the Jingle condition in `urn:xmpp:jingle:errors:1`
  next to the XMPP condition). The peer's own IQ-result / error
  reply is what the initiator receives; the server never fakes an
  acknowledgement.

  `handle_jingle/2` is the IQ handler for stanzas addressed to the
  server or to the sender's *own* JID (the only ones that reach
  `Exjabberd.Iq.dispatch/2` for this namespace): it runs the same
  state machine and answers with a plain result.

  Sessions end on `session-terminate` or when either party
  disconnects (`:user_unavailable` hook) — a stale `sid` then
  answers `unknown-session`, exactly as XEP-0166 §5.8 requires.

  ICE-UDP (XEP-0176) needs no special casing: `transport-info`
  stanzas carry `<transport
  xmlns='urn:xmpp:jingle:transports:ice-udp:1'>` with `<candidate/>`
  children, and the stanza is routed verbatim — candidates are
  forwarded as-is, never interpreted.

  XEP-0215: an IQ-get for `<services/>` (namespaces
  `urn:xmpp:extdisco:2` and, for older clients, `urn:xmpp:extdisco:1`)
  returns the STUN server and the TURN servers (UDP, plus TCP when
  enabled) with ephemeral credentials for the requesting user:
  username `"<expiry>:<bare JID>"`, password
  `Base64(HMAC-SHA1(shared_secret, username))` — the same
  derivation the TURN server verifies (RFC 5389 long-term
  credential mechanism), so no password is ever stored.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @jingle_ns "urn:xmpp:jingle:1"
  @jingle_errors_ns "urn:xmpp:jingle:errors:1"
  @extdisco_ns "urn:xmpp:extdisco:2"
  @extdisco_ns_legacy "urn:xmpp:extdisco:1"
  @ice_udp_ns "urn:xmpp:jingle:transports:ice-udp:1"
  @rtp_ns "urn:xmpp:jingle:apps:rtp:1"

  @table :exjabberd_jingle_sessions

  @known_actions [
    "content-accept",
    "content-add",
    "content-modify",
    "content-remove",
    "session-accept",
    "session-info",
    "session-initiate",
    "session-terminate",
    "transport-accept",
    "transport-info",
    "transport-reject",
    "transport-replace"
  ]

  @impl true
  def start(host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    Exjabberd.Iq.register(host, @jingle_ns, __MODULE__, :handle_jingle)
    Exjabberd.Iq.register(host, @extdisco_ns, __MODULE__, :handle_extdisco)
    Exjabberd.Iq.register(host, @extdisco_ns_legacy, __MODULE__, :handle_extdisco)
    Exjabberd.Hooks.add(:disco_info, host, __MODULE__, :disco_info, 50)
    Exjabberd.Hooks.add(:user_unavailable, host, __MODULE__, :on_unavailable, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @jingle_ns, :both)
    Exjabberd.Iq.unregister(host, @extdisco_ns, :both)
    Exjabberd.Iq.unregister(host, @extdisco_ns_legacy, :both)
    Exjabberd.Hooks.delete(:disco_info, host, __MODULE__, :disco_info)
    Exjabberd.Hooks.delete(:user_unavailable, host, __MODULE__, :on_unavailable)
    :ok
  end

  @doc false
  def disco_info(acc, _host),
    do:
      Map.update(
        acc,
        :features,
        [@jingle_ns, @rtp_ns, @ice_udp_ns, @extdisco_ns],
        &(&1 ++ [@jingle_ns, @rtp_ns, @ice_udp_ns, @extdisco_ns])
      )

  @doc false
  def on_unavailable(jid, host) do
    cleanup_user(host, jid_to_bare(jid))
    jid
  end

  # --- session registry ---

  @doc "All live sessions for `host`, newest first."
  @spec list_sessions(binary()) :: [map()]
  def list_sessions(host) do
    if :ets.whereis(@table) == :undefined do
      []
    else
      :ets.tab2list(@table)
      |> Enum.filter(fn {{h, _sid}, _} -> h == host end)
      |> Enum.map(fn {{_h, sid}, sess} -> Map.put(sess, :sid, sid) end)
      |> Enum.sort_by(& &1.created, :desc)
    end
  end

  @doc "One live session, or `{:error, :not_found}`."
  @spec get_session(binary(), binary()) :: {:ok, map()} | {:error, :not_found}
  def get_session(host, sid) do
    case :ets.whereis(@table) do
      :undefined ->
        {:error, :not_found}

      _ ->
        case :ets.lookup(@table, {host, sid}) do
          [{{_, _}, sess}] -> {:ok, Map.put(sess, :sid, sid)}
          [] -> {:error, :not_found}
        end
    end
  end

  @doc "Forget every session where `bare_jid` is initiator or responder."
  @spec cleanup_user(binary(), binary()) :: :ok
  def cleanup_user(host, bare_jid) when is_binary(bare_jid) and bare_jid != "" do
    list_sessions(host)
    |> Enum.filter(fn sess ->
      jid_to_bare(sess.initiator) == bare_jid or jid_to_bare(sess.responder) == bare_jid
    end)
    |> Enum.each(fn sess -> :ets.delete(@table, {host, sess.sid}) end)

    :ok
  end

  def cleanup_user(_host, _bare), do: :ok

  # --- the signaling gate (listeners call this before routing) ---

  @doc """
  Validate a Jingle IQ-set addressed to another user.

  Returns `:route` (let the stanza through to the peer) or
  `{:error, xmpp_condition, jingle_condition | nil}` (answer the
  sender with that error instead). Runs the XEP-0166 state machine
  against the session table as a side effect.
  """
  @spec intercept(map(), binary()) ::
          :route | {:error, binary(), binary() | nil}
  def intercept(iq, host) do
    ensure_table()

    with {:ok, action, sid} <- parse_jingle(iq),
         :ok <- check_action(action) do
      case action do
        "session-initiate" -> track_initiate(iq, host, sid)
        "session-accept" -> track_accept(iq, host, sid)
        "session-terminate" -> track_terminate(iq, host, sid)
        _ -> track_in_session(iq, host, sid)
      end
    else
      {:error, condition, jingle_condition} -> {:error, condition, jingle_condition}
    end
  end

  @doc """
  Build a Jingle error IQ reply for `iq` (from the server `host`):
  the XMPP condition in `urn:ietf:params:xml:ns:xmpp-stanzas` plus,
  when given, the Jingle condition in `urn:xmpp:jingle:errors:1`.
  """
  @spec error_iq(map(), binary(), binary(), binary() | nil) :: map()
  def error_iq(iq, host, condition, jingle_condition \\ nil) do
    children = [
      %{
        name: condition,
        attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-stanzas"},
        children: []
      }
    ]

    children =
      if jingle_condition do
        children ++
          [%{name: jingle_condition, attrs: %{"xmlns" => @jingle_errors_ns}, children: []}]
      else
        children
      end

    Stanza.new(:iq,
      id: iq.id,
      from: host,
      to: iq.from,
      type: "error",
      payload: [
        %{name: "error", attrs: %{"type" => error_type(condition)}, children: children}
      ]
    )
  end

  # --- IQ handler (server- / self-addressed Jingle) ---

  @doc false
  def handle_jingle(%{type: "get"} = iq, host) do
    {:error, :bad_request, error_iq(iq, host, "bad-request")}
  end

  def handle_jingle(%{type: "set"} = iq, host) do
    case intercept(iq, host) do
      :route ->
        # Addressed to the server or to the sender themselves: the
        # stanza has no other peer to go to, so tracking it and
        # acknowledging is the whole job.
        {:ok, %{iq | type: "result", payload: []}}

      {:error, condition, jingle_condition} ->
        {:error, :bad_request, error_iq(iq, host, condition, jingle_condition)}
    end
  end

  def handle_jingle(iq, host),
    do: {:error, :bad_request, error_iq(iq, host, "bad-request")}

  # --- XEP-0215 external service discovery ---

  @doc false
  def handle_extdisco(%{type: "get"} = iq, host) do
    requester = jid_to_bare(iq.from)
    services = services_for(host, requester)

    elements =
      Enum.map(services, fn service ->
        attrs = %{
          "host" => service.host,
          "port" => to_string(service.port),
          "type" => service.type
        }

        attrs =
          if service[:transport], do: Map.put(attrs, "transport", service.transport), else: attrs

        attrs =
          if service[:username], do: Map.put(attrs, "username", service.username), else: attrs

        attrs =
          if service[:password], do: Map.put(attrs, "password", service.password), else: attrs

        attrs = if service[:expires], do: Map.put(attrs, "expires", service.expires), else: attrs

        %{name: "service", attrs: attrs, children: []}
      end)

    {:ok,
     %{
       iq
       | type: "result",
         payload: [
           %{name: "services", attrs: %{"xmlns" => @extdisco_ns}, children: elements}
         ]
     }}
  end

  def handle_extdisco(iq, host),
    do: {:error, :bad_request, error_iq(iq, host, "bad-request")}

  @doc """
  STUN/TURN services for `host`, with ephemeral TURN credentials
  for `bare_jid` (XEP-0215). The STUN entry carries no credentials;
  each TURN entry carries a username/password that expires with
  the credential TTL.
  """
  @spec services_for(binary(), binary()) :: [map()]
  def services_for(host, bare_jid) do
    turn = Exjabberd.Config.turn()
    stun_host = to_string(turn["host"] || turn[:host] || host)
    port = turn["port"] || turn[:port] || 5478
    tcp? = turn["tcp"] != false and turn[:tcp] != false
    cred = turn_credential(host, bare_jid)

    base = [%{host: stun_host, port: port, type: "stun"}]

    turn_udp = %{
      host: stun_host,
      port: port,
      type: "turn",
      transport: "udp",
      username: cred.username,
      password: cred.password,
      expires: cred.expires
    }

    turn_tcp = %{turn_udp | transport: "tcp"}

    if tcp?, do: base ++ [turn_udp, turn_tcp], else: base ++ [turn_udp]
  end

  @doc "STUN/TURN servers for a host (no credentials — see `services_for/2`)."
  @spec stun_servers(binary()) :: [map()]
  def stun_servers(host) do
    turn = Exjabberd.Config.turn()
    stun_host = to_string(turn["host"] || turn[:host] || host)
    port = turn["port"] || turn[:port] || 5478

    [%{host: stun_host, port: port, type: "stun"}]
  end

  @doc """
  Ephemeral TURN credential for `bare_jid` (XEP-0215 §3.3 /
  draft-uberti-behave-turn-rest): username
  `"<expiry unix>:<bare JID>"`, password
  `Base64(HMAC-SHA1(shared_secret, username))`, valid 24 h. The
  TURN server derives the same password from the same secret, so
  the password is never stored anywhere.
  """
  @spec turn_credential(binary(), binary()) :: %{
          username: binary(),
          password: binary(),
          ttl: non_neg_integer(),
          expires: binary(),
          host: binary(),
          port: non_neg_integer()
        }
  def turn_credential(host, bare_jid) do
    secret = Exjabberd.Config.turn_secret() || ""
    turn = Exjabberd.Config.turn()
    ttl = 86_400
    expiry = System.system_time(:second) + ttl
    username = "#{expiry}:#{bare_jid}"
    password = Base.encode64(:crypto.mac(:hmac, :sha, secret, username))

    %{
      username: username,
      password: password,
      ttl: ttl,
      expires: DateTime.from_unix!(expiry) |> DateTime.to_iso8601(),
      host: to_string(turn["host"] || turn[:host] || host),
      port: turn["port"] || turn[:port] || 5478
    }
  end

  # --- server-side helpers (SIP bridge, not the client path) ---

  @doc """
  Start a Jingle session from the server (SIP INVITE bridge):
  records the session and routes a `session-initiate` IQ to the
  responder with a minimal RTP/ICE-UDP content element. The SDP
  offer itself is kept in the session record (`set_sdp/4`) — Jingle
  has no SDP blob on the wire.
  """
  @spec initiate(binary(), binary(), binary(), map()) :: {:ok, binary()} | {:error, term()}
  def initiate(host, from, to, content) do
    ensure_table()
    sid = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    media = Map.get(content, :media, "audio")

    :ets.insert(
      @table,
      {{host, sid},
       %{
         initiator: from,
         responder: to,
         state: :pending,
         created: System.system_time(:second)
       }}
    )

    stanza =
      Stanza.new(:iq,
        type: "set",
        from: from,
        to: to,
        payload: [
          %{
            name: "jingle",
            attrs: %{"xmlns" => @jingle_ns, "action" => "session-initiate", "sid" => sid},
            children: [
              %{
                name: "content",
                attrs: %{"creator" => "initiator", "name" => "main"},
                children: [
                  %{
                    name: "description",
                    attrs: %{"xmlns" => @rtp_ns, "media" => media},
                    children: []
                  },
                  %{name: "transport", attrs: %{"xmlns" => @ice_udp_ns}, children: []}
                ]
              }
            ]
          }
        ]
      )

    Exjabberd.Router.route(stanza)
    {:ok, sid}
  end

  @doc "Store an SDP offer/answer in a live session (SIP bridge)."
  @spec set_sdp(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def set_sdp(host, sid, type, sdp) when type in ["offer", "answer"] do
    ensure_table()

    case :ets.lookup(@table, {host, sid}) do
      [{{_, _}, sess}] ->
        :ets.insert(@table, {{host, sid}, Map.put(sess, String.to_atom("sdp_#{type}"), sdp)})
        :ok

      [] ->
        {:error, :not_found}
    end
  end

  @doc "Terminate a live session from the server (SIP BYE bridge)."
  @spec terminate(binary(), binary(), binary()) :: :ok
  def terminate(host, sid, reason \\ "success") do
    ensure_table()

    case :ets.lookup(@table, {host, sid}) do
      [{{_, _}, sess}] ->
        stanza =
          Stanza.new(:iq,
            type: "set",
            from: sess.initiator,
            to: sess.responder,
            payload: [
              %{
                name: "jingle",
                attrs: %{"xmlns" => @jingle_ns, "action" => "session-terminate", "sid" => sid},
                children: [
                  %{
                    name: "reason",
                    attrs: %{},
                    children: [%{name: reason, attrs: %{}, children: []}]
                  }
                ]
              }
            ]
          )

        Exjabberd.Router.route(stanza)
        :ets.delete(@table, {host, sid})
        :ok

      [] ->
        :ok
    end
  end

  # --- state machine ---

  defp parse_jingle(iq) do
    case Stanza.get_subtag(iq, @jingle_ns) do
      %{name: "jingle", attrs: attrs} ->
        action = Map.get(attrs, "action")
        sid = Map.get(attrs, "sid")

        cond do
          is_nil(action) or action == "" or is_nil(sid) or sid == "" ->
            {:error, "bad-request", nil}

          true ->
            {:ok, action, sid}
        end

      _ ->
        {:error, "bad-request", nil}
    end
  end

  defp check_action(action) when action in @known_actions, do: :ok

  defp check_action(_action),
    do: {:error, "feature-not-implemented", nil}

  defp track_initiate(iq, host, sid) do
    case :ets.lookup(@table, {host, sid}) do
      [] ->
        jingle_el = Stanza.get_subtag(iq, @jingle_ns)

        if jingle_el == nil or jingle_el.children == [] do
          {:error, "bad-request", nil}
        else
          :ets.insert(@table, {
            {host, sid},
            %{
              initiator: jid_to_string(iq.from),
              responder: jid_to_string(iq.to),
              state: :pending,
              created: System.system_time(:second)
            }
          })

          :route
        end

      [{{_, _}, sess}] ->
        # A second initiate for a live sid: simultaneous initiation
        # from the other party is a tie-break; repeating your own
        # initiate is out of order (XEP-0166 §10).
        if jid_to_string(iq.from) == sess.initiator do
          {:error, "unexpected-request", "out-of-order"}
        else
          {:error, "conflict", "tie-break"}
        end
    end
  end

  defp track_accept(iq, host, sid) do
    case :ets.lookup(@table, {host, sid}) do
      [] ->
        {:error, "item-not-found", "unknown-session"}

      [{{_, _}, sess}] ->
        cond do
          jid_to_string(iq.from) != sess.responder ->
            {:error, "unexpected-request", "out-of-order"}

          sess.state != :pending ->
            {:error, "unexpected-request", "out-of-order"}

          true ->
            :ets.insert(@table, {{host, sid}, %{sess | state: :active}})
            :route
        end
    end
  end

  defp track_terminate(iq, host, sid) do
    case :ets.lookup(@table, {host, sid}) do
      [] ->
        {:error, "item-not-found", "unknown-session"}

      [{{_, _}, sess}] ->
        if jid_to_string(iq.from) not in [sess.initiator, sess.responder] do
          {:error, "forbidden", nil}
        else
          :ets.delete(@table, {host, sid})
          :route
        end
    end
  end

  defp track_in_session(iq, host, sid) do
    case :ets.lookup(@table, {host, sid}) do
      [] ->
        {:error, "item-not-found", "unknown-session"}

      [{{_, _}, sess}] ->
        if jid_to_string(iq.from) not in [sess.initiator, sess.responder] do
          {:error, "forbidden", nil}
        else
          :route
        end
    end
  end

  # --- helpers ---

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    :ok
  end

  # XEP-0166 §10 maps each Jingle condition to an XMPP condition;
  # the error `type` follows the XMPP condition (RFC 6120 §8.3.3).
  defp error_type("item-not-found"), do: "cancel"
  defp error_type("bad-request"), do: "modify"
  defp error_type("feature-not-implemented"), do: "cancel"
  defp error_type("unexpected-request"), do: "wait"
  defp error_type("conflict"), do: "cancel"
  defp error_type("forbidden"), do: "auth"
  defp error_type(_), do: "cancel"

  defp jid_to_string(%Jid{} = jid), do: Jid.to_string(jid)
  defp jid_to_string(bin) when is_binary(bin), do: bin
  defp jid_to_string(_), do: ""

  defp jid_to_bare(%Jid{} = jid), do: Jid.bare(jid)
  defp jid_to_bare(bin) when is_binary(bin), do: Jid.bare(bin)
  defp jid_to_bare(_), do: ""
end
