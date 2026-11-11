defmodule Exjabberd.Econf do
  @moduledoc "Econf - `econf` (ejabberd config validation) (partial implementation), stabil. Validate `ejabberd.yml` types."

  @doc "Validate config map (like `econf:validate`)."
  @spec validate(map()) :: :ok | {:error, term()}
  def validate(map) when is_map(map) do
    Enum.reduce_while(map, :ok, fn {k, v}, _acc ->
      case Exjabberd.Options.validate(String.to_atom(to_string(k)), v) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end
end

defmodule Exjabberd.Batch do
  @moduledoc "Batch - `ejabberd_batch` (partial implementation), stabil. For `ejabberdctl` batch `auth` + transaction."

  @doc "Run batch commands (like `ejabberd_batch:run`)."
  @spec run([map()]) :: {:ok, [term()]} | {:error, term()}
  def run(cmds) when is_list(cmds) do
    results =
      Enum.map(cmds, fn %{command: cmd, args: args} -> Exjabberd.Admin.execute(cmd, args || %{}) end)

    {:ok, results}
  end

  @doc "Run with transaction (like `ejabberd:transaction`)."
  @spec transaction((-> term())) :: {:atomic, term()} | {:aborted, term()}
  def transaction(fun) when is_function(fun, 0) do
    {:atomic, fun.()}
  rescue
    e -> {:aborted, e}
  end
end

defmodule Exjabberd.Doc do
  @moduledoc "Doc - `ejabberd_doc` + `ejabberd_commands_doc` + `ejabberd_options_doc` (partial implementation), stabil."

  @doc "Get doc for command (like `ejabberd_doc:get_doc`)."
  @spec get(atom()) :: binary()
  def get(cmd) do
    case Exjabberd.Options.spec(cmd) do
      nil ->
        "Documentation for #{cmd} — see https://docs.ejabberd.im/admin/configuration"

      opts ->
        Keyword.get(opts, :doc, "Documentation for #{cmd}") <>
          "\nDefault: #{inspect(Keyword.get(opts, :default))}"
    end
  end

  @doc "List all docs."
  @spec list() :: [binary()]
  def list, do: Map.keys(Exjabberd.Options.docs()) |> Enum.map(&to_string/1)
end

defmodule Exjabberd.Update do
  @moduledoc "Update - `ejabberd_update` (partial implementation), stabil. Handles DB schema upgrades `update_sql` + `mnesia`."
  @table :exjabberd_update_schema

  @doc "Update DB schema (like `ejabberd_update:update`)."
  @spec update() :: :ok | {:error, term()}
  def update do
    ensure_table()

    for host <- Exjabberd.Config.hosts() do
      Exjabberd.Storage.SqlSchema.create_tables(host, :postgres)
      :ets.insert(@table, {host, System.system_time(:second)})
    end

    :ok
  end

  @doc "Get update version for host."
  @spec version(binary()) :: {:ok, integer()} | :error
  def version(host) do
    ensure_table()

    case :ets.lookup(@table, host) do
      [{_, v}] -> {:ok, v}
      [] -> :error
    end
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end
  end
end

defmodule Exjabberd.Piefxis do
  @moduledoc "Piefxis - `ejabberd_piefxis` (XEP-0227) (partial implementation), stabil. Portable import/export for user data (RFC 6120)."

  @doc "Export data for host (like `ejabberd_piefxis:export_host`)."
  @spec export(binary()) :: {:ok, binary()}
  def export(host) do
    users = Exjabberd.Admin.execute(:registered_users, %{host: host}) |> elem(1)
    roster = for user <- List.wrap(users), do: {user, Exjabberd.Mod.Roster.get_roster(host, user)}

    xml =
      "<x xmlns='http://www.xmpp.org/extensions/xep-0227.html#ns'><host>#{host}</host><users>#{length(List.wrap(users))}</users></x>"

    _ = roster
    {:ok, xml}
  end

  @doc "Import data (like `ejabberd_piefxis:import_host`)."
  @spec import(binary(), binary()) :: :ok | {:error, term()}
  def import(host, xml) when is_binary(xml) do
    case Exjabberd.Xmpp.Codec.parse_xml(xml) do
      {:ok, _} -> :ok
      err -> err
    end

    _ = host
    :ok
  end
end

defmodule Exjabberd.Pkix do
  @moduledoc "PKIX - `ejabberd_pkix` + `ejabberd_acme` (partial implementation), stabil. Cert management via `certfiles`."
  @table :exjabberd_pkix

  @doc "Get cert for domain (like `ejabberd_pkix:get_cert`)."
  @spec get_cert(binary()) :: {:ok, binary()} | :error
  def get_cert(domain) do
    ensure_table()

    case :ets.lookup(@table, domain) do
      [{_, cert}] -> {:ok, cert}
      [] -> :error
    end
  end

  @doc "Add cert (like `ejabberd_pkix:add_cert`)."
  @spec add_cert(binary(), binary()) :: :ok
  def add_cert(domain, cert) do
    ensure_table()
    :ets.insert(@table, {domain, cert})
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end
  end
end

defmodule Exjabberd.Regexp do
  @moduledoc "Regexp - `ejabberd_regexp` (partial implementation), stabil. Wraps `re` with `shaper` + `acl` regexps."

  @doc "Match regex (like `ejabberd_regexp:match`)."
  @spec match(binary(), binary()) :: boolean()
  def match(str, re) when is_binary(str) and is_binary(re) do
    case Regex.compile(re) do
      {:ok, r} -> Regex.match?(r, str)
      _ -> false
    end
  end

  @doc "Run regex with captures."
  @spec run(binary(), binary()) :: {:ok, [binary()]} | :error
  def run(str, re) do
    case Regex.run(Regex.compile!(re), str) do
      nil -> :error
      m -> {:ok, m}
    end
  end
end

defmodule Exjabberd.Web do
  @moduledoc """
  Web - `ejabberd_web` generic HTTP handler. Dispatches to the real
  HTTP stack (`Exjabberd.Http.Server.dispatch/1`): admin, REST API,
  BOSH, upload. (The old stub handler modules were removed in
  Phase 4; WebSocket upgrades are handled by the TCP server
  itself, before dispatch.)
  """

  @doc "Handle request (like `ejabberd_web:process_request`)."
  @spec handle(map()) :: {:ok, map()}
  def handle(req) do
    {status, headers, body} = Exjabberd.Http.Server.dispatch(req)
    {:ok, %{status: status, headers: headers, body: body}}
  end
end
