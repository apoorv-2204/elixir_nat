import Config

config :natex, :src_dir, File.cwd!()

config :natex, :mut_dir, "data"

config :natex, :cache_file, "nat_cache"

import_config("#{Mix.env()}.exs")
