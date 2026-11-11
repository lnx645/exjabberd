import Config

config :exjabberd,
  hosts: ["localhost"],
  log_level: :info,
  default_db: :mnesia,
  auth_method: :mnesia

import_config "#{config_env()}.exs"
