import Config

config :exjabberd,
  hosts: ["localhost"],
  log_level: :info,
  default_db: :mnesia,
  auth_method: :mnesia,
  # Mnesia schema directory (accounts + offline messages). Overridden
  # per environment below; the test env uses its own directory because
  # a Mnesia schema belongs to exactly one node name.
  mnesia_dir: Path.join(File.cwd!(), "mnesia_data")

import_config "#{config_env()}.exs"
