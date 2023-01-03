defmodule NatEx.Application do
  @moduledoc false

  use Application

  alias NatEx.Utils
  alias NatEx.NATCache

  @spec start(any, any) :: {:error, any} | {:ok, pid}
  def start(_type, _args) do
    children = [
      {NATCache, [get: true, file: "nat_cache"]}
      # , {:inets, []}
    ]

    Supervisor.start_link(Utils.configurable_children(children),
      strategy: :one_for_one,
      name: NatEx.Supervisor
    )
  end
end
