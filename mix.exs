defmodule ElixirNat.MixProject do
  use Mix.Project

  def project do
    [
      app: :natex,
      version: "0.1.0",
      elixir: "~> 1.14",
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
      extra_applications: [:logger],
      mod: {NatEx.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false}
      # {:Inet_Cidr, git: "https://github.com/cobenian/inet_cidr", branch: "main"},
      # {:inet_ext, "~> 1.0"}
      # # {:inet_ext, "~> 1.0"},
      # {:intercept, "~> 1.0"}
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
