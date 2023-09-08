import Config

# Print only errors during test
config :logger, level: :error

config :nat, :mut_dir, "data_test"

config :nat, NATCache, enabled: false
