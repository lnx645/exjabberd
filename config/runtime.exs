import Config

# 100% ejabberd parity: load exjabberd.yml / nxmpps.yml like ejabberd does
# ejabberd searches /etc/ejabberd/ejabberd.yml, ./ejabberd.yml, ./nxmpps.yml
# exjabberd mirrors that: priv/exjabberd.yml, ./exjabberd.yml, ./nxmpps.yml
config_path =
  System.get_env("EXJABBERD_CONFIG") ||
    System.get_env("EJABBERD_CONFIG_PATH") ||
    (File.exists?("exjabberd.yml") && "exjabberd.yml") ||
    (File.exists?("nxmpps.yml") && "nxmpps.yml") ||
    (File.exists?("priv/exjabberd.yml") && "priv/exjabberd.yml") ||
    nil

if config_path && File.exists?(config_path) do
  case YamlElixir.read_from_file(config_path) do
    {:ok, %{"hosts" => hosts}} when is_list(hosts) ->
      config :exjabberd, hosts: hosts

    {:ok, _} ->
      :ok

    {:error, _} ->
      :ok
  end
end
