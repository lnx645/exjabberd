defmodule Exjabberd.Mod.StreamMgmt do
  @moduledoc """
  Stream Management — `mod_stream_mgmt` (XEP-0198, `urn:xmpp:sm:3`).

  Owns the resumable-session registry and the module configuration;
  the per-connection counters and the unacknowledged queue live in
  `Exjabberd.C2S` (the process that owns the socket and sends the
  stanzas), because only it can count a stanza exactly when it is
  written to the wire.

  How resumption survives a dropped TCP connection: when the socket
  goes away, the C2S process does *not* stop while stream management
  is enabled — it detaches (socket set to `nil`), keeps its
  SessionManager/Router registrations, and waits up to
  `resume_timeout` seconds for a `<resume/>` on a fresh connection.
  The new connection's listener hands the new socket to the old C2S
  process (`C2S` `{:sm_resume, ...}`), which sends `<resumed/>` and
  replays every stanza the client has not acked yet. If nobody
  resumes in time, the old process tears the session down for real
  (unregisters, sends unavailable presence, drops the SM id).

  Options (from `modules:` in `exjabberd.yml`, see `mod_options/1`):

  * `max_ack_queue` — how many unacknowledged outbound stanzas are
    kept for replay (default 100). Older entries are dropped first.
  * `resume_timeout` — seconds a detached session stays resumable
    (default 60). Also advertised as `max` on `<enabled/>`.

  Deliberate deviations from XEP-0198, documented here rather than
  hidden:

  * A second `<enable/>` gets `<failed><unexpected-request/></failed>`
    instead of the stream error the XEP suggests, so a confused
    client keeps a usable session.
  * A clean `</stream:stream>` close keeps the session resumable
    (like an unexpected TCP drop) instead of ending it outright, as
    XEP-0198 §7 suggests — mobile clients routinely close the stream
    and resume later, and this matches ejabberd behaviour.
  * `<enabled/>` carries both `id` and `previd` (same value): `id`
    is what the XEP defines, `previd` is what the resumption reply
    uses; clients ignore the extra attribute.
  * When a detached session finally times out, its unacknowledged
    *message* stanzas are offered to the offline store (the
    `:offline_message` hook) instead of being silently dropped.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  alias Exjabberd.Xmpp.Feature

  @sm_ns "urn:xmpp:sm:3"

  # Registry of resumable sessions: {sm_id, c2s_pid, full_jid}.
  @table :exjabberd_sm_resume

  @default_max_ack_queue 100
  @default_resume_timeout 60

  @doc "Stream Management namespace (XEP-0198 v3)."
  @spec namespace() :: binary()
  def namespace, do: @sm_ns

  @impl true
  def start(host, _opts) do
    ensure_table()
    Feature.register_sm(host)

    Logger.info(
      "mod_stream_mgmt started for #{host} (max_ack_queue=#{max_ack_queue(host)}, resume_timeout=#{resume_timeout(host)}s)"
    )

    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:c2s_stream_features, host, Feature, :sm_feature)
    :ok
  end

  @impl true
  def mod_options(_host) do
    [max_ack_queue: @default_max_ack_queue, resume_timeout: @default_resume_timeout]
  end

  @impl true
  def mod_doc,
    do: %{
      desc: "Stream Management (XEP-0198): stanza acks and stream resumption",
      doc: "https://xmpp.org/extensions/xep-0198.html"
    }

  @doc "True when this module is loaded for the host (i.e. SM is offered)."
  @spec enabled?(binary()) :: boolean()
  def enabled?(host), do: Exjabberd.Mod.GenMod.is_loaded?(host, __MODULE__)

  @doc "Configured `max_ack_queue` for the host (default #{@default_max_ack_queue})."
  @spec max_ack_queue(binary()) :: pos_integer()
  def max_ack_queue(host) do
    case Keyword.get(opts(host), :max_ack_queue, @default_max_ack_queue) do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_max_ack_queue
    end
  end

  @doc "Configured `resume_timeout` (seconds) for the host (default #{@default_resume_timeout})."
  @spec resume_timeout(binary()) :: pos_integer()
  def resume_timeout(host) do
    case Keyword.get(opts(host), :resume_timeout, @default_resume_timeout) do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_resume_timeout
    end
  end

  @doc "Register a resumable session under its SM id."
  @spec register(binary(), pid(), binary()) :: :ok
  def register(sm_id, pid, full_jid) when is_binary(sm_id) and is_pid(pid) do
    ensure_table()
    :ets.insert(@table, {sm_id, pid, full_jid})
    :ok
  end

  @doc "Forget a resumable session (resumed for good, timed out, or ended)."
  @spec unregister(binary()) :: :ok
  def unregister(sm_id) when is_binary(sm_id) do
    ensure_table()
    :ets.delete(@table, sm_id)
    :ok
  end

  @doc "Look a resumable session up by SM id."
  @spec lookup(binary()) :: {:ok, pid(), binary()} | :error
  def lookup(sm_id) when is_binary(sm_id) do
    ensure_table()

    case :ets.lookup(@table, sm_id) do
      [{_, pid, full_jid}] ->
        if Process.alive?(pid), do: {:ok, pid, full_jid}, else: :error

      [] ->
        :error
    end
  end

  @doc "SM id of the resumable session for a full JID, if any."
  @spec lookup_by_jid(binary()) :: {:ok, binary(), pid()} | :error
  def lookup_by_jid(full_jid) when is_binary(full_jid) do
    ensure_table()

    case :ets.match(@table, {:"$1", :"$2", full_jid}) do
      [[sm_id, pid]] -> {:ok, sm_id, pid}
      _ -> :error
    end
  end

  @doc """
  Resume the session identified by `previd` onto a fresh socket.

  Returns `{:ok, old_pid, replayed}` when the old C2S process took
  the socket over, or `{:error, reason}` where `reason` is
  `:not_found` (unknown/timed-out id), `:superseded` (the resource
  has since bound a newer session) or `:count_too_high` (the client
  acked more stanzas than the server ever sent).
  """
  @spec resume(binary(), binary(), non_neg_integer(), port(), :tcp | :ssl) ::
          {:ok, pid(), non_neg_integer(), binary()}
          | {:error, :not_found | :superseded | :count_too_high}
  def resume(_host, previd, h, socket, kind) do
    case lookup(previd) do
      {:ok, pid, full_jid} ->
        try do
          case GenServer.call(pid, {:sm_resume, h, socket, kind}) do
            {:ok, replayed} -> {:ok, pid, replayed, full_jid}
            {:error, reason} -> {:error, reason}
          end
        catch
          :exit, _ -> {:error, :not_found}
        end

      :error ->
        {:error, :not_found}
    end
  end

  @doc "Ask a resumable session to tear itself down now (e.g. its resource just bound a fresh session)."
  @spec terminate_session(binary()) :: :ok
  def terminate_session(sm_id) when is_binary(sm_id) do
    case lookup(sm_id) do
      {:ok, pid, _} ->
        GenServer.cast(pid, :sm_terminate_now)
        :ok

      :error ->
        :ok
    end
  end

  @doc "Failed SM element for `condition` (an `urn:ietf:params:xml:ns:xmpp-stanzas` condition name)."
  @spec failed_xml(binary()) :: binary()
  def failed_xml(condition) do
    "<failed xmlns='#{@sm_ns}'><#{condition} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></failed>"
  end

  defp opts(host), do: Exjabberd.Mod.Supervisor.get_opts(host, __MODULE__)

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end
  end
end
