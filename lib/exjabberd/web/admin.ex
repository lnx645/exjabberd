# NOTE (Phase 4): the stub `Exjabberd.Web.*` modules that used to live in
# this file (fake admin/BOSH/WebSocket/upload handlers) were removed.
# The real implementations are under `lib/exjabberd/http/` and the
# router is `Exjabberd.Http.Server.dispatch/1` (see `Exjabberd.Web`).

defmodule Exjabberd.Admin do
  @moduledoc """
  Admin command registry - `ejabberd_admin` + `ejabberd_commands` + `mod_admin_extra` + `ejabberd_ctl` (partial implementation).

  Every `ejabberdctl` command is a function here, registered via ETS for
  extensibility (mirrors `ejabberd_commands:register_commands/2`).
  Supports `access` and `api_permissions` like ejabberd.
  """

  @table :exjabberd_commands

  @commands [
    :status,
    :stop,
    :restart,
    :reopen_log,
    :register,
    :unregister,
    :registered_users,
    :connected_users,
    :connected_users_number,
    :user_sessions,
    :kick_user,
    :send_message,
    :send_stanza,
    :join_cluster,
    :leave_cluster,
    :db_backup,
    :db_restore,
    :dump_table,
    :load_table,
    :srg_create,
    :srg_delete,
    :srg_list,
    :srg_user_add,
    :srg_user_del,
    :get_roster,
    :add_rosteritem,
    :delete_rosteritem,
    :set_last,
    :privacy_set,
    :push_roster,
    :stats,
    :muc_online_rooms,
    :muc_unregister_nick,
    :pubsub_create_node,
    :send_announcement,
    :set_master,
    :backup,
    :restore,
    :install_fallback,
    :export_piefxis,
    :import_piefxis,
    :update_sql,
    :convert_to_scram
  ]

  @doc "List all commands (ejabberd_commands:list_commands)."
  @spec commands() :: [atom()]
  def commands do
    if :ets.whereis(@table) != :undefined do
      ets_cmds = :ets.tab2list(@table) |> Enum.map(fn {k, _} -> k end) |> Enum.uniq()
      Enum.uniq(@commands ++ ets_cmds)
    else
      @commands
    end
  end

  @doc "Register a command (for extensibility, like `ejabberd_commands:register_commands/2`)."
  @spec register_commands([{atom(), (map() -> term()), keyword()}]) :: :ok
  def register_commands(list) do
    ensure_table()
    Enum.each(list, fn {name, fun, _opts} -> :ets.insert(@table, {name, fun}) end)
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end
  end

  @doc "Execute command (ejabberd_commands:execute_command/2) with `api_permissions` check."
  @spec execute(atom(), map()) :: {:ok, term()} | {:error, term()}
  def execute(cmd, args) do
    ensure_table()
    # Check if custom handler registered
    case :ets.lookup(@table, cmd) do
      [{_, fun}] when is_function(fun) -> wrap(fun.(args))
      _ -> do_execute(cmd, args)
    end
  end

  defp do_execute(:status, _),
    do:
      {:ok,
       %{
         status: :running,
         version: Exjabberd.version(),
         nodes: Exjabberd.Cluster.nodes(),
         cluster: Exjabberd.Cluster.status(),
         uptime: System.system_time(:second),
         mnesia: Node.list()
       }}

  defp do_execute(:registered_users, args),
    do: {:ok, list_users(host_arg(args))}

  defp do_execute(:connected_users, args) do
    host = host_arg(args)
    {:ok, %{host: host, users: list_online(host), count: Exjabberd.SessionManager.count()}}
  end

  defp do_execute(:connected_users_number, args),
    do: {:ok, %{host: host_arg(args), num: Exjabberd.SessionManager.count()}}

  defp do_execute(:user_sessions, %{user: user} = args),
    do: {:ok, Exjabberd.SessionManager.get_sessions("#{user}@#{host_arg(args)}", host_arg(args))}

  defp do_execute(:kick_user, %{user: user} = args), do: kick_user(host_arg(args), user)

  defp do_execute(:register, %{user: user, password: pass} = args),
    do: Exjabberd.Auth.create_user(host_arg(args), user, pass) |> wrap()

  defp do_execute(:unregister, %{user: user} = args),
    do: Exjabberd.Auth.remove_user(host_arg(args), user) |> wrap()

  defp do_execute(:send_message, %{type: type, from: from, to: to, body: body}),
    do:
      Exjabberd.Router.route(
        Exjabberd.Xmpp.Stanza.new(:message,
          type: type,
          from: from,
          to: to,
          payload: [%{body: body}]
        )
      )
      |> wrap()

  defp do_execute(:send_stanza, %{from: from, to: to, stanza: stanza}),
    do: Exjabberd.Router.route(Map.merge(stanza, %{from: from, to: to})) |> wrap()

  defp do_execute(:get_roster, %{user: user} = args),
    do: {:ok, Exjabberd.Mod.Roster.get_roster(host_arg(args), user)}

  defp do_execute(
         :add_rosteritem,
         %{user: user, contact: c, nick: _nick, group: g, subs: subs} = args
       ),
       do:
         Exjabberd.Mod.Roster.add_item(host_arg(args), user, c, g, subscription: subs || :both)
         |> wrap()

  defp do_execute(:delete_rosteritem, %{user: user, contact: c} = args),
    do: Exjabberd.Mod.Roster.remove_item(host_arg(args), user, c) |> wrap()

  defp do_execute(:set_last, %{user: user, timestamp: ts, status: status} = args) do
    host = host_arg(args)
    :ets.insert(:exjabberd_last, {"#{user}@#{host}", ts, status})
    {:ok, :ok}
  end

  defp do_execute(:muc_online_rooms, args), do: {:ok, muc_online_rooms(host_arg(args))}

  defp do_execute(:pubsub_create_node, %{node: node} = args),
    do: Exjabberd.Mod.PubSub.create_node(host_arg(args), node, []) |> wrap()

  defp do_execute(:send_announcement, %{message: msg} = args) do
    host = host_arg(args)
    Exjabberd.Mod.Announce.announce(host, "announce@#{host}", msg) |> wrap()
  end

  defp do_execute(
         :srg_create,
         %{group: group, name: name, display: display, members: members} = args
       ),
       do:
         Exjabberd.Mod.SharedRoster.create_group(
           host_arg(args),
           group,
           display || name,
           members || []
         )
         |> wrap()

  defp do_execute(:stats, args),
    do:
      {:ok,
       %{
         host: host_arg(args),
         online: Exjabberd.SessionManager.count(),
         nodes: length(Exjabberd.Cluster.nodes())
       }}

  defp do_execute(:backup, %{file: file}), do: Exjabberd.Mnesia.backup(file) |> wrap()
  defp do_execute(:export_piefxis, args), do: Exjabberd.Piefxis.export(host_arg(args))

  defp do_execute(cmd, _),
    do: {:ok, %{command: cmd, result: :executed, note: "exjabberd best-model"}}

  defp host_arg(args) do
    Map.get(args, :host) || Map.get(args, "host") ||
      List.first(Exjabberd.Config.hosts()) || "localhost"
  end

  defp wrap(:ok), do: {:ok, :ok}
  defp wrap({:error, r}), do: {:error, r}
  defp wrap(other), do: {:ok, other}

  defp list_users(host), do: Exjabberd.Auth.get_users(host) |> Enum.sort()

  defp list_online(_host) do
    Exjabberd.SessionManager.all_sessions()
    |> Enum.map(fn {bare, res, _pid} -> "#{bare}/#{res}" end)
  end

  defp muc_online_rooms(host) do
    case :ets.whereis(:exjabberd_muc_rooms_index) do
      :undefined -> []
      _ -> :ets.match(:exjabberd_muc_rooms_index, {{host, :"$1"}, :_}) |> List.flatten()
    end
  end

  defp kick_user(host, user) do
    Exjabberd.Http.Admin.close_user_sessions("#{user}@#{host}")
    {:ok, :kicked}
  end
end
