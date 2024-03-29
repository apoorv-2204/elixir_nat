defmodule ElixirNat.MixProject do
  use Mix.Project

  def project do
    [
      app: :nat,
      version: "0.1.0",
      # elixir: "~> 1.14",
      config_path: "config/config.exs",
      build_path: "_build",
      deps_path: "deps",
      lockfile: "mix.lock",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [
        :logger,
        :inets,
        :xmerl,
        :public_key,
        :httpoison
      ]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:inet_ext, "~> 1.0"},
      {:inet_cidr, "~> 1.0.2", hex: :erl_cidr},
      {:castore, "~> 1.0", override: true},
      {:httpoison, "~> 2.0"}
    ]
  end
end

#  [kernel, stdlib, inet_cidr, inet_ext, inets, xmerl, rand_compat]
# % https://hex.pm/packages/rand_compat
# rand_compat:seed
# %  https://www.erlang.org/doc/man/xmerl.html
# % https://www.erlang.org/doc/man/inets.html#
# %
# % https://hex.pm/packages/inet_ext
# % https://hex.pm/packages/inet_cidr
