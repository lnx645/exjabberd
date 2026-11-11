defmodule Exjabberd.Mod.Mam do
  @moduledoc """
  Message Archive Management — `mod_mam` (XEP-0313, `urn:xmpp:mam:2`).

  Archives 1-1 chat messages per user in Mnesia (`disc_copies`, so an
  archive survives a restart) with an ETS fallback when Mnesia is not
  usable, mirroring `Exjabberd.Mod.Offline`. Each archived record keeps
  the original message stanza (re-encoded XML), a unique id, a
  microsecond timestamp and the peer bare JID, so a MAM query can
  re-emit the message verbatim inside `<forwarded/>` with a
  `<delay/>` stamp.

  Archiving hooks into the two packet hooks `C2S` already runs:

  * `:user_send_packet` — archives the message into the *sender's*
    archive (owner = the sending session's bare JID);
  * `:user_receive_packet` — archives the message into the
    *recipient's* archive (owner = the receiving session's bare JID).

  A message is therefore stored once per participant, never twice for
  the same owner: the send hook only sees the sender's session and the
  receive hook only the recipient's.

  Preferences (`<prefs default='always|never|roster'>` with
  `<always/>` / `<never/>` JID lists) are per user, defaulting to the
  module's configured `default` (`always`). `roster` archives only
  messages whose peer is in the owner's roster.

  Configuration (from `modules:` in `exjabberd.yml`, also mirrored in
  `default_modules/0`):

  * `default` — default archiving policy (`always`, `never`,
    `roster`); default `always`.
  * `max_archive_size` — maximum archived messages kept per owner
    (oldest dropped first); default 500.

  MUC messages are archived separately by `Exjabberd.Mod.Muc.Room`
  via `archive_muc/5`, with the room's bare JID as owner, so a MAM
  query addressed to the room returns the room history.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  alias Exjabberd.Xmpp.{Codec, Jid, Stanza}

  @mam_ns "urn:xmpp:mam:2"
  @archive_table :mam_archive
  @prefs_table :mam_prefs
  @ets_archive :exjabberd_mam
  @ets_prefs :exjabberd_mam_prefs

  @default_max_archive_size 500
  @default_page_size 50

  @doc "MAM namespace (XEP-0313 v2)."
  @spec namespace() :: binary()
  def namespace, do: @mam_ns

  @impl true
  def start(host, opts) do
    ensure_tables()
    default = normalize_default(Keyword.get(opts, :default, "always"))

    Logger.info(
      "mod_mam started for #{host} (default=#{default}, max_archive_size=#{max_archive_size(host)})"
    )

    Exjabberd.Hooks.add(:user_send_packet, host, __MODULE__, :archive, 50)
    Exjabberd.Hooks.add(:user_receive_packet, host, __MODULE__, :archive, 50)
    Exjabberd.Hooks.add(:disco_info, host, __MODULE__, :disco_info, 50)
    Exjabberd.Iq.register(host, @mam_ns, Exjabberd.Mod.Mam.Query, :handle)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:user_send_packet, host, __MODULE__, :archive)
    Exjabberd.Hooks.delete(:user_receive_packet, host, __MODULE__, :archive)
    Exjabberd.Hooks.delete(:disco_info, host, __MODULE__, :disco_info)
    Exjabberd.Iq.unregister(host, @mam_ns, :both)
    :ok
  end

  @impl true
  def mod_options(_host),
    do: [default: "always", max_archive_size: @default_max_archive_size]

  @impl true
  def mod_doc,
    do: %{
      desc: "Message Archive Management (XEP-0313): per-user message archive",
      doc: "https://xmpp.org/extensions/xep-0313.html"
    }

  @doc "Configured default archiving policy for the host."
  @spec default_pref(binary()) :: binary()
  def default_pref(host) do
    host
    |> mod_opt(:default, "always")
    |> normalize_default()
  end

  @doc "Configured maximum archived messages kept per owner."
  @spec max_archive_size(binary()) :: pos_integer()
  def max_archive_size(host) do
    case mod_opt(host, :max_archive_size, @default_max_archive_size) do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_max_archive_size
    end
  end

  @doc "Default MAM query page size when the client sends no RSM `<max/>`."
  @spec default_page_size() :: pos_integer()
  def default_page_size, do: @default_page_size

  # --- disco ---

  @doc false
  def disco_info(acc, _host),
    do: Map.update(acc, :features, [@mam_ns], &(&1 ++ [@mam_ns]))

  # --- archiving hooks ---

  @doc """
  Archive a stanza for one owner (hook handler, arity 3: the stanza,
  the host, the session JID that owns this copy of the archive).

  Returns the stanza unchanged; archiving never blocks delivery.
  """
  @spec archive(map(), binary(), term()) :: map()
  def archive(%{name: :message} = stanza, host, jid) do
    owner = bare_jid(jid)

    if owner != "" and owner != nil and eligible?(stanza) and
         should_archive?(host, owner, stanza) do
      archive_message(host, owner, stanza)
    end

    stanza
  rescue
    e ->
      Logger.warning("mam archive failed: #{inspect(e)}")
      stanza
  catch
    _, _ -> stanza
  end

  def archive(stanza, _host, _jid), do: stanza

  @doc """
  Archive a MUC groupchat message, called by `Exjabberd.Mod.Muc.Room`
  when a room broadcasts. The owner is the room's bare JID; the stored
  stanza is the groupchat message as delivered (`from` is
  `room/nick`).
  """
  @spec archive_muc(binary(), binary(), binary(), binary(), binary()) :: :ok
  def archive_muc(host, room_bare, nick, from_bare, body) do
    stanza =
      Stanza.new(:message,
        type: "groupchat",
        from: "#{room_bare}/#{nick}",
        to: room_bare,
        payload: [%{name: "body", attrs: %{}, children: [body]}]
      )

    # MUC archiving follows the module `default` only: rooms have no
    # per-room prefs yet, so `never` disables it (documented in the
    # README).
    if default_pref(host) != "never" do
      archive_message(host, String.downcase(room_bare), stanza, peer: from_bare)
    end

    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  @doc """
  XEP-0313 §5 eligibility: only real chat traffic is archived.
  Never archived: error messages, groupchat (handled by `archive_muc/5`
  instead), headlines (e.g. PubSub event notifications), carbon
  copies, MAM result messages, messages without a `<body/>`, and
  messages sent by the server itself.
  """
  @spec eligible?(map()) :: boolean()
  def eligible?(%{name: :message} = stanza) do
    cond do
      stanza.type in ["error", "groupchat", "headline"] -> false
      Stanza.get_subtag(stanza, "urn:xmpp:carbons:2") != nil -> false
      Stanza.get_subtag(stanza, @mam_ns) != nil -> false
      Stanza.child(stanza.payload, "body") == nil -> false
      stanza.from in [nil, ""] -> false
      match?(%Jid{local: nil}, stanza.from) -> false
      true -> true
    end
  end

  def eligible?(_), do: false

  @doc """
  Archive one message stanza for `owner` (bare JID). Returns
  `{:ok, record}`. Enforces `max_archive_size/1` by dropping the
  oldest records for that owner first.
  """
  @spec archive_message(binary(), binary(), map(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def archive_message(host, owner, stanza, opts \\ []) do
    ensure_tables()
    owner = String.downcase(owner)
    ts = System.system_time(:microsecond)
    seq = :erlang.unique_integer([:positive, :monotonic])
    id = "#{ts}-#{seq}"
    from = bare_jid(stanza.from)
    to = bare_jid(stanza.to)
    peer = Keyword.get(opts, :peer) || peer_of(stanza, owner)
    xml = Codec.encode(stanza)

    record = %{
      id: id,
      owner: owner,
      from: from,
      to: to,
      peer: peer,
      ts: ts,
      seq: seq,
      xml: xml
    }

    key = {owner, ts, seq}
    write_record(key, record)
    enforce_limit(host, owner)
    {:ok, record}
  end

  @doc "MAM preferences for a user (bare JID `user@host`)."
  @spec get_prefs(binary(), binary()) :: {:ok, map()}
  def get_prefs(host, user) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    case read_pref(bare) do
      nil -> {:ok, %{default: default_pref(host), always: [], never: []}}
      prefs -> {:ok, prefs}
    end
  end

  @doc "Set MAM preferences for a user. `prefs` uses string keys/values."
  @spec set_prefs(binary(), binary(), map()) :: {:ok, map()}
  def set_prefs(host, user, prefs) do
    ensure_tables()
    bare = String.downcase("#{user}@#{host}")

    normalized = %{
      default:
        prefs
        |> Map.get(:default, Map.get(prefs, "default", default_pref(host)))
        |> normalize_default(),
      always:
        prefs
        |> Map.get(:always, Map.get(prefs, "always", []))
        |> Enum.map(&String.downcase/1),
      never:
        prefs
        |> Map.get(:never, Map.get(prefs, "never", []))
        |> Enum.map(&String.downcase/1)
    }

    write_pref(bare, normalized)
    {:ok, normalized}
  end

  @doc """
  Query an owner's archive (XEP-0313 §5 + RSM XEP-0059).

  Options: `:with` (bare peer JID), `:start` / `:end` (unix
  microseconds), `:limit` (page size), `:before` / `:after` (archive
  ids; empty-string `before` means "the last page"). Results are
  oldest-first. Returns `{:ok, records, info}` where `info` has
  `:count` (total matches), `:first` / `:last` (ids of the returned
  page, or nil) and `:complete` (true when the page holds everything
  that matched).
  """
  @spec query(binary(), binary(), keyword()) :: {:ok, [map()], map()}
  def query(_host, owner, opts \\ []) do
    ensure_tables()
    owner = String.downcase(owner)
    with_jid = opts |> Keyword.get(:with) |> then(fn v -> v && String.downcase(v) end)
    start_ts = Keyword.get(opts, :start)
    end_ts = Keyword.get(opts, :end)
    limit = Keyword.get(opts, :limit, @default_page_size)
    before_id = Keyword.get(opts, :before)
    after_id = Keyword.get(opts, :after)

    all =
      read_all(owner)
      |> filter_records(with_jid, start_ts, end_ts)
      |> Enum.sort_by(fn rec -> {rec.ts, rec.seq} end)

    total = length(all)
    page = page_records(all, total, limit, before_id, after_id)

    info = %{
      count: total,
      first: page |> List.first() |> then(fn r -> r && r.id end),
      last: page |> List.last() |> then(fn r -> r && r.id end),
      complete: length(page) == total
    }

    {:ok, page, info}
  end

  # Keep only records matching the `with` peer and the time window.
  defp filter_records(records, with_jid, start_ts, end_ts) do
    Enum.filter(records, fn rec ->
      (is_nil(with_jid) or rec.peer == with_jid or rec.from == with_jid or
         rec.to == with_jid) and
        (is_nil(start_ts) or rec.ts >= start_ts) and
        (is_nil(end_ts) or rec.ts <= end_ts)
    end)
  end

  # One RSM page of the sorted matches: `after` pages forward,
  # `before` pages backward (empty `before` = the last page).
  defp page_records(all, total, limit, before_id, after_id) do
    page =
      cond do
        not is_nil(after_id) -> page_after(all, limit, after_id)
        not is_nil(before_id) -> page_before(all, total, limit, before_id)
        true -> Enum.take(all, limit)
      end

    Enum.reject(page, &is_nil/1)
  end

  defp page_after(all, limit, after_id) do
    idx = Enum.find_index(all, &(&1.id == after_id)) || -1
    Enum.slice(all, (idx + 1)..(idx + limit))
  end

  defp page_before(all, total, limit, "") do
    Enum.slice(all, max(0, total - limit)..(total - 1))
  end

  defp page_before(all, total, limit, before_id) do
    idx = Enum.find_index(all, &(&1.id == before_id)) || total
    Enum.slice(all, max(0, idx - limit)..(idx - 1))
  end

  @doc "Delete archived messages older than `max_age_seconds` for an owner."
  @spec purge_old(binary(), binary(), integer()) :: :ok
  def purge_old(_host, owner, max_age_seconds) do
    ensure_tables()
    cutoff = System.system_time(:microsecond) - max_age_seconds * 1_000_000

    read_all(String.downcase(owner))
    |> Enum.filter(&(&1.ts < cutoff))
    |> Enum.each(fn rec -> delete_record({rec.owner, rec.ts, rec.seq}) end)

    :ok
  end

  @doc "Format a microsecond unix timestamp as an XEP-0082 UTC stamp."
  @spec delay_stamp(integer()) :: binary()
  def delay_stamp(ts_us) do
    ts_us
    |> DateTime.from_unix!(:microsecond)
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end

  # --- prefs decision ---

  defp should_archive?(host, owner, stanza) do
    {:ok, prefs} = get_prefs(host, owner |> String.split("@") |> hd())
    peer = peer_of(stanza, owner) |> String.downcase()

    cond do
      peer in prefs.never -> false
      peer in prefs.always -> true
      prefs.default == "never" -> false
      prefs.default == "roster" -> roster_peer?(host, owner, peer)
      true -> true
    end
  end

  defp roster_peer?(host, owner, peer) do
    user = owner |> String.split("@") |> hd()

    case Exjabberd.Mod.Roster.get_item(host, user, peer) do
      {:ok, _} -> true
      :error -> false
    end
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  # The other party of a 1-1 message, from the owner's point of view.
  defp peer_of(%{from: from, to: to}, owner) do
    from_bare = bare_jid(from)
    to_bare = bare_jid(to)

    cond do
      from_bare != "" and from_bare != owner -> from_bare
      to_bare != "" -> to_bare
      true -> from_bare
    end
  end

  defp bare_jid(%Jid{} = jid), do: Jid.bare(jid)
  defp bare_jid(bin) when is_binary(bin), do: Jid.bare(bin)
  defp bare_jid(_), do: ""

  defp normalize_default(d) when d in ["always", :always], do: "always"
  defp normalize_default(d) when d in ["never", :never], do: "never"
  defp normalize_default(d) when d in ["roster", :roster], do: "roster"
  defp normalize_default(_), do: "always"

  defp mod_opt(host, key, default) do
    host
    |> then(&Exjabberd.Mod.Supervisor.get_opts(&1, __MODULE__))
    |> Keyword.get(key, default)
  end

  # --- storage (Mnesia disc_copies first, ETS fallback — same shape as mod_offline) ---

  defp ensure_tables do
    if :ets.whereis(@ets_archive) == :undefined do
      :ets.new(@ets_archive, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    if :ets.whereis(@ets_prefs) == :undefined do
      :ets.new(@ets_prefs, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    Exjabberd.Mnesia.ensure_table(@archive_table, [:key, :record])
    Exjabberd.Mnesia.ensure_table(@prefs_table, [:user, :prefs])
  end

  defp write_record(key, record) do
    case :mnesia.transaction(fn -> :mnesia.write({@archive_table, key, record}) end) do
      {:atomic, :ok} ->
        :ok

      {:aborted, reason} ->
        Logger.warning("mam: mnesia write failed (#{inspect(reason)}), using ETS")
        :ets.insert(@ets_archive, {key, record})
        :ok
    end
  rescue
    _ -> :ets.insert(@ets_archive, {key, record})
  catch
    _, _ -> :ets.insert(@ets_archive, {key, record})
  end

  defp delete_record(key) do
    case :mnesia.transaction(fn -> :mnesia.delete({@archive_table, key}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, _} -> :ets.delete(@ets_archive, key)
    end

    :ets.delete(@ets_archive, key)
    :ok
  rescue
    _ -> :ets.delete(@ets_archive, key)
  catch
    _, _ -> :ets.delete(@ets_archive, key)
  end

  defp read_all(owner) do
    mnesia =
      :mnesia.dirty_match_object({@archive_table, {owner, :_, :_}, :_})
      |> Enum.map(fn {@archive_table, _key, record} -> record end)

    ets =
      :ets.match_object(@ets_archive, {{owner, :_, :_}, :_})
      |> Enum.map(fn {_key, record} -> record end)

    (mnesia ++ ets)
    |> Enum.uniq_by(& &1.id)
  rescue
    _ -> :ets.match_object(@ets_archive, {{owner, :_, :_}, :_}) |> Enum.map(&elem(&1, 1))
  catch
    _, _ -> []
  end

  defp enforce_limit(host, owner) do
    limit = max_archive_size(host)
    all = read_all(owner) |> Enum.sort_by(fn rec -> {rec.ts, rec.seq} end)

    if length(all) > limit do
      all
      |> Enum.take(length(all) - limit)
      |> Enum.each(fn rec -> delete_record({rec.owner, rec.ts, rec.seq}) end)
    end

    :ok
  end

  defp read_pref(bare) do
    case :mnesia.dirty_read({@prefs_table, bare}) do
      [{@prefs_table, _, prefs}] ->
        prefs

      [] ->
        case :ets.lookup(@ets_prefs, bare) do
          [{_, prefs}] -> prefs
          [] -> nil
        end
    end
  rescue
    _ ->
      case :ets.lookup(@ets_prefs, bare) do
        [{_, prefs}] -> prefs
        [] -> nil
      end
  catch
    _, _ -> nil
  end

  defp write_pref(bare, prefs) do
    case :mnesia.transaction(fn -> :mnesia.write({@prefs_table, bare, prefs}) end) do
      {:atomic, :ok} -> :ok
      {:aborted, _} -> :ets.insert(@ets_prefs, {bare, prefs})
    end
  rescue
    _ -> :ets.insert(@ets_prefs, {bare, prefs})
  catch
    _, _ -> :ets.insert(@ets_prefs, {bare, prefs})
  end
end
