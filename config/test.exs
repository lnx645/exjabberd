import Config

# The test suite boots the application on its own node name; its schema
# must live in a separate directory from the dev server's.
config :exjabberd,
  mnesia_dir: Path.join(File.cwd!(), "mnesia_data_test")

config :logger, level: :warning
