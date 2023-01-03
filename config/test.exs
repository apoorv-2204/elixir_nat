import Config

# Print only errors during test
config :logger, level: :error

config :natex, :mut_dir, "data_test"

config :natex, NATCache, enabled: false
