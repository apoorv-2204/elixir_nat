import Config

config :nat, :src_dir, File.cwd!()

config :nat, :mut_dir, "data"

config :nat, :cache_file, "nat_cache"

import_config("#{Mix.env()}.exs")
