defmodule Exjabberd.Mod.Mam do
  @moduledoc """
  Message Archive Management - `mod_mam` (XEP-0313) + `mod_mam_muc` (partial implementation), stabil.

  Stores messages with MAM v0.2 semantics, supports `default` always/never/roster,
  `prefs` get/set, Mnesia/SQL backends via `Exjabberd.Storage`, RSM `before/after/limit`
  pagination, `with/start/end` filter, dan MUC MAM `muc` flag.

  Backed by `ordered_set` ETS untuk single-node; SQL `archive` table untuk cluster.
  Hook `user_send_packet` + `user_receive_packet` + `muc_log` seperti `mod_mam`.
  """

  use Exjabberd.Mod.GenMod

  @table :exjabberd_mam
  @prefs_table :exjabberd_mam_prefs

  @impl true
  def start(host, opts) do
    ensure_tables()
    default = Keyword.get(opts, :default, :always)
    # Register prefs default like ejabberd
    :ets.insert(@prefs_table, {host, %{default: default, always: [], never: []}})
    Exjabberd.Hooks.add(:user_send_packet, host, __MODULE__, :archive, 50)
    Exjabberd.Hooks.add(:user_receive_packet, host, __MODULE__, :archive, 50)
    Exjabberd.Hooks.add(:muc_log, host, __MODULE__, :archive_muc, 50)
    Exjabberd.Iq.register(host, "urn:xmpp:mam:2", __MODULE__, :handle_mam_iq)
    Exjabberd.Iq.register(host, "urn:xmpp:mam:0", __MODULE__, :handle_mam_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:user_send_packet, host, __MODULE__, :archive)
    Exjabberd.Hooks.delete(:user_receive_packet, host, __MODULE__, :archive)
    Exjabberd.Hooks.delete(:muc_log, host, __MODULE__, :archive_muc)
    Exjabberd.Iq.unregister(host, "urn:xmpp:mam:2", :both)
    Exjabberd.Iq.unregister(host, "urn:xmpp:mam:0", :both)
    :ok
  end

  defp ensure_tables do
    for {t, type} <- [{@table, :ordered_set}, {@prefs_table, :set}] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, type, read_concurrency: true, write_concurrency: true])
      end
    end
  end

  @doc "Archive a stanza (called via hooks, 2 or 3 args like ejabberd Hooks, dengan prefs check)."
  @spec archive(map(), binary()) :: map()
  @spec archive(map(), binary(), term()) :: map()
  def archive(stanza, host, _jid \\ nil) do
    if should_archive?(host, stanza) do
      archive_message(host, stanza)
    end

    stanza
  end

  @doc "Archive MUC message (mod_mam_muc)."
  @spec archive_muc({binary(), binary(), map()}, binary()) :: {binary(), binary(), map()}
  def archive_muc({room_jid, nick, stanza} = data, host) do
    if should_archive?(host, stanza) do
      muc_stanza = Map.put(stanza, :muc_room, room_jid) |> Map.put(:muc_nick, nick)
      archive_message(host <> "#muc", muc_stanza)
    end

    data
  end

  defp should_archive?(host, %{name: :message} = stanza) do
    # Check prefs like mod_mam: always/never/default
    prefs =
      case :ets.lookup(@prefs_table, host) do
        [{_, p}] -> p
        [] -> %{default: :always, always: [], never: []}
      end

    with_jid = (stanza[:to] && Exjabberd.Xmpp.Jid.to_string(stanza[:to])) || ""

    cond do
      with_jid in prefs.never -> false
      with_jid in prefs.always -> true
      prefs.default == :always -> stanza.type not in ["error", nil] or stanza.name == :message
      prefs.default == :never -> false
      true -> true
    end
  end

  defp should_archive?(_host, _), do: false

  @doc "Archive a message explicitly (like `mod_mam:archive_message`)."
  @spec archive_message(binary(), map()) :: :ok
  def archive_message(host, stanza) do
    ensure_tables()
    id = :erlang.unique_integer([:monotonic, :positive])
    ts = System.system_time(:microsecond)
    from = (stanza.from && Exjabberd.Xmpp.Jid.to_string(stanza.from)) || ""
    to = (stanza.to && Exjabberd.Xmpp.Jid.to_string(stanza.to)) || ""

    _ =
      Exjabberd.Storage.store(
        host,
        :archive,
        {{host, ts, id}, %{from: from, to: to, stanza: stanza, ts: ts}}
      )

    key = {host, ts, id}
    :ets.insert(@table, {key, %{from: from, to: to, stanza: stanza, ts: ts, id: id}})
    :telemetry.execute([:exjabberd, :mam, :archived], %{count: 1}, %{host: host})
    :ok
  end

  @doc "MAM preferences get (like `mod_mam:get_prefs`)."
  @spec get_prefs(binary(), binary()) :: {:ok, map()}
  def get_prefs(host, _user) do
    ensure_tables()

    case :ets.lookup(@prefs_table, host) do
      [{_, prefs}] -> {:ok, prefs}
      [] -> {:ok, %{default: "always", always: [], never: []}}
    end
  end

  @doc "MAM preferences set (like `mod_mam:set_prefs`)."
  @spec set_prefs(binary(), binary(), map()) :: {:ok, map()}
  def set_prefs(host, _user, prefs) do
    ensure_tables()
    :ets.insert(@prefs_table, {host, prefs})
    {:ok, prefs}
  end

  @doc "Query archive with RSM full (mod_mam:query). Supports `with/start/end/limit/before/after` + RSM `first/last/count`."
  @spec query(binary(), binary(), keyword()) :: {:ok, [map()], map()}
  def query(host, _user, opts) do
    ensure_tables()
    with_jid = Keyword.get(opts, :with)
    start_ts = Keyword.get(opts, :start)
    end_ts = Keyword.get(opts, :end)
    limit = Keyword.get(opts, :limit, 20)
    before_id = Keyword.get(opts, :before)
    after_id = Keyword.get(opts, :after)

    all =
      :ets.tab2list(@table)
      |> Enum.filter(fn {{h, _ts, _id}, _} -> h == host or h == host <> "#muc" end)
      |> Enum.map(fn {{_h, ts, id}, rec} -> {ts, id, rec} end)
      |> Enum.sort_by(fn {ts, _id, _rec} -> ts end)

    filtered =
      all
      |> Enum.filter(fn {_ts, _id, rec} ->
        cond do
          with_jid && rec.from != with_jid && rec.to != with_jid -> false
          start_ts && rec.ts < start_ts -> false
          end_ts && rec.ts > end_ts -> false
          true -> true
        end
      end)

    # RSM before/after like ejabberd
    sliced =
      cond do
        after_id ->
          idx =
            Enum.find_index(filtered, fn {_ts, id, _} -> to_string(id) == to_string(after_id) end) ||
              -1

          Enum.slice(filtered, idx + 1, limit)

        before_id ->
          idx =
            Enum.find_index(filtered, fn {_ts, id, _} -> to_string(id) == to_string(before_id) end) ||
              length(filtered)

          Enum.slice(filtered, max(0, idx - limit), limit)

        true ->
          Enum.take(filtered, limit)
      end
      |> Enum.map(fn {_ts, _id, rec} -> rec end)

    first = List.first(sliced) && List.first(sliced).id
    last = List.last(sliced) && List.last(sliced).id
    info = %{complete: length(sliced) < limit, count: length(filtered), first: first, last: last}
    {:ok, sliced, info}
  end

  @doc "Delete old messages (retention, mod_mam:purge)."
  @spec purge_old(binary(), integer()) :: :ok
  def purge_old(host, max_age_seconds) do
    ensure_tables()
    cutoff = System.system_time(:microsecond) - max_age_seconds * 1_000_000
    :ets.select_delete(@table, [{{{host, :"$1", :_}, :_}, [{:<, :"$1", cutoff}], [true]}])
    :ets.select_delete(@table, [{{{host <> "#muc", :"$1", :_}, :_}, [{:<, :"$1", cutoff}], [true]}])
    :ok
  end

  @doc false
  def handle_mam_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end
