defmodule Exjabberd.Mod.Offline do
  @moduledoc """
  Offline messages - `mod_offline` (RFC 6121 §5).

  A message to a local user who exists but has no online session is
  stored (Mnesia `disc_copies`, so it survives a restart) and delivered
  when the user becomes available again. A message to a local user who
  does not exist at all is not stored; the router answers it with
  `service-unavailable` instead.

  The `:offline_message` hook returns `:stored` / `:unknown` / `:deny`;
  the router decides from that whether to bounce the stanza.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  @table :exjabberd_offline
  @mnesia_table :offline_messages
  @max_per_user 100

  @impl true
  def start(host, _opts) do
    ensure_tables()
    Exjabberd.Hooks.add(:offline_message, host, __MODULE__, :on_offline_message, 40)
    Exjabberd.Hooks.add(:user_available, host, __MODULE__, :on_user_available, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:offline_message, host, __MODULE__, :on_offline_message)
    Exjabberd.Hooks.delete(:user_available, host, __MODULE__, :on_user_available)
    :ok
  end

  @doc false
  def on_offline_message(%{name: :message} = stanza, host) do
    case bare_to(stanza) do
      nil ->
        :unknown

      bare ->
        user = bare |> String.split("@") |> hd()

        if Exjabberd.Auth.user_exists(host, user) do
          store(bare, stanza)
          :stored
        else
          :unknown
        end
    end
  end

  def on_offline_message(_stanza, _host), do: :unknown

  @doc false
  def on_user_available(full_jid, _host) do
    bare =
      case full_jid do
        %Exjabberd.Xmpp.Jid{} -> Exjabberd.Xmpp.Jid.bare(full_jid)
        bin when is_binary(bin) -> Exjabberd.Xmpp.Jid.bare(bin)
        _ -> nil
      end

    if bare, do: flush(bare)
    full_jid
  end

  @doc "Stored offline messages for a bare JID (oldest first)."
  @spec messages(binary()) :: [map()]
  def messages(bare) when is_binary(bare) do
    ensure_tables()
    mnesia_messages(bare) ++ ets_messages(bare)
  end

  @doc "How many offline messages are stored for a bare JID."
  @spec count(binary()) :: non_neg_integer()
  def count(bare) when is_binary(bare), do: length(messages(bare))

  defp store(bare, stanza) do
    ensure_tables()

    if count(bare) >= @max_per_user do
      Logger.warning("offline: dropping message for #{bare}, queue full (#{@max_per_user})")
      :ok
    else
      key = {bare, System.unique_integer([:positive, :monotonic])}
      write(bare, key, stanza)
    end
  end

  defp write(_bare, key, stanza) do
    case :mnesia.transaction(fn -> :mnesia.write({@mnesia_table, key, stanza}) end) do
      {:atomic, :ok} ->
        :ok

      {:aborted, reason} ->
        # Mnesia not ready: keep it in ETS so the message is not lost
        # for this run.
        Logger.warning("offline: mnesia write failed (#{inspect(reason)}), using ETS")
        :ets.insert(@table, {key, stanza})
        :ok
    end
  rescue
    _ ->
      :ets.insert(@table, {key, stanza})
      :ok
  catch
    _, _ ->
      :ets.insert(@table, {key, stanza})
      :ok
  end

  defp flush(bare) do
    Enum.each(messages(bare), fn stanza ->
      Exjabberd.Router.route(stanza)
    end)

    delete_all(bare)
    :ok
  end

  defp delete_all(bare) do
    :mnesia.transaction(fn ->
      :mnesia.match_object({@mnesia_table, {bare, :_}, :_})
      |> Enum.each(fn record -> :mnesia.delete_object(record) end)
    end)

    :ets.match_delete(@table, {{bare, :_}, :_})
    :ok
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp mnesia_messages(bare) do
    :mnesia.dirty_match_object({@mnesia_table, {bare, :_}, :_})
    |> Enum.map(fn {@mnesia_table, {_b, ref}, stanza} -> {ref, stanza} end)
    |> Enum.sort_by(fn {ref, _} -> ref end)
    |> Enum.map(fn {_, stanza} -> stanza end)
  rescue
    _ -> []
  catch
    _, _ -> []
  end

  defp ets_messages(bare) do
    :ets.match_object(@table, {{bare, :_}, :_})
    |> Enum.map(fn {{_b, ref}, stanza} -> {ref, stanza} end)
    |> Enum.sort_by(fn {ref, _} -> ref end)
    |> Enum.map(fn {_, stanza} -> stanza end)
  rescue
    _ -> []
  catch
    _, _ -> []
  end

  defp bare_to(%{to: %Exjabberd.Xmpp.Jid{} = to}), do: Exjabberd.Xmpp.Jid.bare(to)
  defp bare_to(%{to: to}) when is_binary(to), do: Exjabberd.Xmpp.Jid.bare(to)
  defp bare_to(_), do: nil

  defp ensure_tables do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :ordered_set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end

    Exjabberd.Mnesia.ensure_table(@mnesia_table, [:key, :stanza])
  end
end
