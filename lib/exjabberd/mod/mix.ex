defmodule Exjabberd.Mod.Mix do
  @moduledoc """
  MIX — Mediated Information eXchange, `mod_mix` (XEP-0369, core:0).

  The MIX service lives at `mix.<host>`; channels are addressed as
  `channel@mix.<host>`. Implemented over the wire:

  * Channel lifecycle: `<create/>` / `<destroy/>` IQs to the
    service (destroy is owner-only).
  * `<join/>` / `<leave/>` / `<setnick/>` IQs to the channel, with
    per-participant stable IDs (XEP-0369 §5.3: a hash of the real
    JID and the channel). The join result hands the participant
    their channel JID, `<stable-id>@<channel>`.
  * Groupchat messages to the channel are reflected to every
    participant (sender included) with `from` set to the sender's
    stable participant JID and a `<mix/>` element carrying the
    sender's nick and real JID — channels here are JID-visible, as
    in ejabberd's default configuration.
  * The participants node is retrievable with a PubSub
    `<items node='urn:xmpp:mix:nodes:participants'/>` IQ to the
    channel, returning `<participant/>` items.
  * Discovery: the service and each channel answer disco#info with
    the `conference/mix` identity; disco#items lists channels on
    the service and the MIX nodes on a channel.

  Not implemented (documented in docs/PARITY.md): the presence and
  information nodes as PubSub nodes, MIX over MAM (channel messages
  are kept in an in-memory log only), MIX PAM (XEP-0405) and
  retries/retraction (XEP-0424/0425 for MIX). Channel state is
  in-memory ETS: channels do not survive a restart.
  """

  use Exjabberd.Mod.GenMod

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @mix_ns "urn:xmpp:mix:core:0"
  @participants_node "urn:xmpp:mix:nodes:participants"
  @messages_node "urn:xmpp:mix:nodes:messages"
  @presence_node "urn:xmpp:mix:nodes:presence"
  @info_node "urn:xmpp:mix:nodes:info"
  @pubsub_ns "http://jabber.org/protocol/pubsub"

  @table :exjabberd_mix
  @table_msgs :exjabberd_mix_messages

  @doc "The MIX service JID for a host."
  @spec service_jid(binary()) :: binary()
  def service_jid(host), do: "mix." <> host

  @impl true
  def start(host, _opts) do
    ensure_tables()
    Exjabberd.Iq.register(host, @mix_ns, __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @mix_ns, :both)
    :ok
  end

  @impl true
  def mod_doc,
    do: %{
      desc: "MIX channels (XEP-0369): mix.localhost service",
      doc: "https://xmpp.org/extensions/xep-0369.html"
    }

  defp ensure_tables do
    for t <- [@table, @table_msgs] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true, write_concurrency: true])
      end
    end

    :ok
  end

  # --- channel store ---

  @doc "All channel JIDs of a host, sorted (for disco#items)."
  @spec list_channels(binary()) :: [binary()]
  def list_channels(host) do
    ensure_tables()

    :ets.tab2list(@table)
    |> Enum.filter(fn {{h, _channel}, _data} -> h == host end)
    |> Enum.map(fn {{_h, channel}, _data} -> channel end)
    |> Enum.sort()
  end

  @doc "Channel data, or nil."
  @spec get_channel(binary(), binary()) :: map() | nil
  def get_channel(host, channel) do
    ensure_tables()

    case :ets.lookup(@table, {host, channel}) do
      [{_key, data}] -> data
      [] -> nil
    end
  end

  @doc "Create a channel owned by `owner` (a bare JID)."
  @spec create(binary(), binary(), keyword()) :: :ok | {:error, term()}
  def create(host, channel, opts \\ []) do
    ensure_tables()

    if get_channel(host, channel) != nil do
      {:error, :conflict}
    else
      # insert_new keeps the claim atomic if two creates race: the
      # loser gets a conflict instead of silently overwriting the
      # winner's fresh channel row.
      claimed =
        :ets.insert_new(
          @table,
          {{host, channel},
           %{
             participants: %{},
             created: System.system_time(:second),
             owner: Keyword.get(opts, :owner)
           }}
        )

      if claimed, do: :ok, else: {:error, :conflict}
    end
  end

  @doc "Destroy a channel (owner only)."
  @spec destroy(binary(), binary(), binary()) :: :ok | {:error, term()}
  def destroy(host, channel, requester) do
    ensure_tables()

    case get_channel(host, channel) do
      nil -> {:error, :not_found}
      %{owner: owner} when owner != requester -> {:error, :forbidden}
      _data -> :ets.delete(@table, {host, channel}) && :ok
    end
  end

  @doc """
  Join a channel. Returns `{:ok, participant}` where participant
  carries the stable id and nick, or an error tuple.
  """
  @spec join(binary(), binary(), binary(), binary(), [binary()]) ::
          {:ok, map()} | {:error, term()}
  def join(host, channel, jid, nick, nodes \\ [@messages_node, @participants_node]) do
    ensure_tables()

    case get_channel(host, channel) do
      nil ->
        {:error, :not_found}

      data ->
        nick = if nick in [nil, ""], do: jid |> String.split("@") |> hd(), else: nick
        sid = stable_id(jid, channel)

        participant = %{
          nick: nick,
          jid: jid,
          stable_id: sid,
          nodes: nodes,
          joined: System.system_time(:second)
        }

        :ets.insert(
          @table,
          {{host, channel}, %{data | participants: Map.put(data.participants, jid, participant)}}
        )

        {:ok, participant}
    end
  end

  @doc "Leave a channel."
  @spec leave(binary(), binary(), binary()) :: :ok | {:error, term()}
  def leave(host, channel, jid) do
    ensure_tables()

    case get_channel(host, channel) do
      nil ->
        {:error, :not_found}

      data ->
        if Map.has_key?(data.participants, jid) do
          :ets.insert(
            @table,
            {{host, channel}, %{data | participants: Map.delete(data.participants, jid)}}
          )

          :ok
        else
          {:error, :not_participant}
        end
    end
  end

  @doc "Change a participant's nick."
  @spec set_nick(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def set_nick(host, channel, jid, nick) do
    ensure_tables()

    case get_channel(host, channel) do
      nil ->
        {:error, :not_found}

      data ->
        case Map.get(data.participants, jid) do
          nil ->
            {:error, :not_participant}

          participant ->
            :ets.insert(
              @table,
              {{host, channel},
               %{data | participants: Map.put(data.participants, jid, %{participant | nick: nick})}}
            )

            :ok
        end
    end
  end

  @doc "Participants of a channel as `%{bare_jid => participant}`."
  @spec participants(binary(), binary()) :: {:ok, map()} | {:error, term()}
  def participants(host, channel) do
    case get_channel(host, channel) do
      nil -> {:error, :not_found}
      %{participants: parts} -> {:ok, parts}
    end
  end

  @doc """
  Reflect a groupchat message to all participants of the channel
  (XEP-0369 §5.3). The sender must be a participant subscribed to
  the messages node. Returns `:ok` or an error tuple.
  """
  @spec send_message(binary(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def send_message(host, channel, from_bare, body) do
    ensure_tables()

    case get_channel(host, channel) do
      nil ->
        {:error, :not_found}

      %{participants: parts} ->
        case Map.get(parts, from_bare) do
          nil ->
            {:error, :not_participant}

          sender ->
            ts = System.system_time(:millisecond)
            anon = "#{sender.stable_id}@#{channel}"

            :ets.insert(
              @table_msgs,
              {{host, channel, ts}, %{from: anon, real_from: from_bare, body: body, ts: ts}}
            )

            Enum.each(parts, fn {jid, participant} ->
              if @messages_node in participant.nodes do
                stanza =
                  Stanza.new(:message,
                    type: "groupchat",
                    from: anon,
                    to: jid,
                    payload: [
                      %{name: "body", attrs: %{}, children: [body]},
                      %{
                        name: "mix",
                        attrs: %{"xmlns" => @mix_ns},
                        children: [
                          %{name: "nick", attrs: %{}, children: [sender.nick]},
                          %{name: "jid", attrs: %{}, children: [from_bare]}
                        ]
                      }
                    ]
                  )

                Exjabberd.Router.route(stanza)
              end
            end)

            :ok
        end
    end
  end

  @doc "Stable ID (XEP-0369 §5.3) — hash of the real JID and the channel, like ejabberd."
  @spec stable_id(binary(), binary()) :: binary()
  def stable_id(jid, channel) when is_binary(jid) and is_binary(channel) do
    :crypto.hash(:sha256, "#{jid}:#{channel}")
    |> Base.encode16(case: :lower)
    |> binary_part(0, 16)
  end

  # --- IQ handling (urn:xmpp:mix:core:0 + participants pubsub) ---

  @doc "IQ handler for the MIX namespace, registered per host."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "set"} = iq, host) do
    cond do
      el = Stanza.child(iq.payload, "create") ->
        handle_create(iq, host, el)

      el = Stanza.child(iq.payload, "destroy") ->
        handle_destroy(iq, host, el)

      el = Stanza.child(iq.payload, "join") ->
        handle_join(iq, host, el)

      el = Stanza.child(iq.payload, "leave") ->
        handle_leave(iq, host, el)

      el = Stanza.child(iq.payload, "setnick") ->
        handle_setnick(iq, host, el)

      true ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp handle_create(iq, host, el) do
    requester = bare_of(iq.from)

    channel =
      case el.attrs["channel"] do
        nil -> nil
        name -> if String.contains?(name, "@"), do: name, else: "#{name}@#{service_jid(host)}"
      end

    cond do
      is_nil(channel) ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      true ->
        case create(host, channel, owner: requester) do
          :ok ->
            {:ok,
             %{
               iq
               | type: "result",
                 payload: [
                   %{name: "create", attrs: %{"xmlns" => @mix_ns, "channel" => channel}, children: []}
                 ]
             }}

          {:error, :conflict} ->
            {:error, :conflict, Exjabberd.Iq.error_iq(iq, "conflict")}
        end
    end
  end

  defp handle_destroy(iq, host, el) do
    requester = bare_of(iq.from)

    channel =
      case el.attrs["channel"] do
        nil -> bare_of(iq.to)
        name -> if String.contains?(name, "@"), do: name, else: "#{name}@#{service_jid(host)}"
      end

    case destroy(host, channel, requester) do
      :ok -> {:ok, %{iq | type: "result", payload: []}}
      {:error, :not_found} -> {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
      {:error, :forbidden} -> {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
    end
  end

  defp handle_join(iq, host, el) do
    channel = bare_of(iq.to)
    requester = bare_of(iq.from)
    join_id = el.attrs["id"]

    nodes =
      el.children
      |> Enum.filter(&match?(%{name: "subscribe"}, &1))
      |> Enum.map(& &1.attrs["node"])
      |> Enum.reject(&is_nil/1)

    nodes = if nodes == [], do: [@messages_node, @participants_node], else: nodes
    nick = Stanza.child_text(el.children, "nick")

    case join(host, channel, requester, nick, nodes) do
      {:ok, participant} ->
        payload = %{
          name: "join",
          attrs: %{"xmlns" => @mix_ns} |> maybe_put("id", join_id),
          children:
            [
              %{name: "jid", attrs: %{}, children: ["#{participant.stable_id}@#{channel}"]},
              %{name: "nick", attrs: %{}, children: [participant.nick]}
            ] ++
              Enum.map(participant.nodes, fn node ->
                %{name: "subscription", attrs: %{"node" => node}, children: []}
              end)
        }

        {:ok, %{iq | type: "result", payload: [payload]}}

      {:error, :not_found} ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
    end
  end

  defp handle_leave(iq, host, _el) do
    case leave(host, bare_of(iq.to), bare_of(iq.from)) do
      :ok ->
        {:ok,
         %{
           iq
           | type: "result",
             payload: [%{name: "leave", attrs: %{"xmlns" => @mix_ns}, children: []}]
         }}

      {:error, :not_found} ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

      {:error, :not_participant} ->
        {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
    end
  end

  defp handle_setnick(iq, host, el) do
    nick = Stanza.child_text(el.children, "nick")

    case set_nick(host, bare_of(iq.to), bare_of(iq.from), nick || "") do
      :ok ->
        {:ok,
         %{
           iq
           | type: "result",
             payload: [
               %{
                 name: "setnick",
                 attrs: %{"xmlns" => @mix_ns},
                 children: [%{name: "nick", attrs: %{}, children: [nick || ""]}]
               }
             ]
         }}

      {:error, :not_found} ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

      {:error, :not_participant} ->
        {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
    end
  end

  @doc """
  PubSub `<items/>` retrieval against a channel, for the
  participants node (XEP-0369 §5.2). Called by the router for
  channel-addressed PubSub IQs, which the generic PubSub handler
  cannot resolve (channel nodes are not service nodes).
  """
  @spec participants_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def participants_iq(%{type: "get"} = iq, host) do
    channel = bare_of(iq.to)

    case participants(host, channel) do
      {:error, :not_found} ->
        {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

      {:ok, parts} ->
        items =
          parts
          |> Map.values()
          |> Enum.sort_by(& &1.stable_id)
          |> Enum.map(fn p ->
            %{
              name: "item",
              attrs: %{"id" => p.stable_id},
              children: [
                %{
                  name: "participant",
                  attrs: %{"xmlns" => @mix_ns},
                  children: [
                    %{name: "jid", attrs: %{}, children: [p.jid]},
                    %{name: "nick", attrs: %{}, children: [p.nick]}
                  ]
                }
              ]
            }
          end)

        {:ok,
         %{
           iq
           | type: "result",
             payload: [
               %{
                 name: "pubsub",
                 attrs: %{"xmlns" => @pubsub_ns},
                 children: [
                   %{name: "items", attrs: %{"node" => @participants_node}, children: items}
                 ]
               }
             ]
         }}
    end
  end

  def participants_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  @doc "True when a PubSub IQ asks a channel for its participants node."
  @spec participants_query?(map()) :: boolean()
  def participants_query?(iq) do
    case Stanza.child(iq.payload, "pubsub") do
      nil ->
        false

      pubsub ->
        case Stanza.child(pubsub.children, "items") do
          %{attrs: %{"node" => @participants_node}} -> true
          _ -> false
        end
    end
  end

  @doc "The MIX node URNs a channel exposes in disco#items."
  @spec channel_nodes() :: [binary()]
  def channel_nodes, do: [@participants_node, @messages_node, @presence_node, @info_node]

  @doc "Disco identity/features for the service or one channel."
  @spec disco_info(binary(), binary() | nil) :: {[binary()], [map()]}
  def disco_info(_host, channel) do
    {["http://jabber.org/protocol/disco#info", "http://jabber.org/protocol/disco#items", @mix_ns],
     [%{category: "conference", type: "mix", name: channel || "Mediated Information eXchange"}]}
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp bare_of(%Jid{} = jid), do: Jid.bare(jid)
  defp bare_of(bin) when is_binary(bin), do: Jid.bare(bin)
  defp bare_of(_), do: ""
end
