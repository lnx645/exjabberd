import Config

config :exjabberd,
  mnesia_dir: Path.join(File.cwd!(), "mnesia_data")
