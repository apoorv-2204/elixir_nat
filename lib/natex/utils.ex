defmodule NatEx.Utils do
  @moduledoc false

  @doc """
  Returns path in the mutable storage directory
  """
  @spec mut_dir(String.t() | nonempty_list(Path.t())) :: Path.t()
  def mut_dir(path) when is_binary(path) do
    [
      get_root_mut_dir(),
      Application.get_env(:natex, :mut_dir),
      path
    ]
    |> Path.join()
    |> Path.expand()
  end

  def mut_dir, do: mut_dir("")

  def get_root_mut_dir() do
    case Application.get_env(:natex, :root_mut_dir) do
      nil -> Application.app_dir(:natex)
      dir -> dir
    end
  end

  @doc """
  Configure supervisor children to be disabled if their configuration has a `enabled` option to false
  """
  @spec configurable_children(
          list(
            process ::
              atom()
              | {process :: atom(), args :: list()}
              | {process :: atom(), args :: list(), opts :: list()}
          )
        ) ::
          list(Supervisor.child_spec())
  def configurable_children(children) when is_list(children) do
    children
    |> Enum.filter(fn
      {process, _, _} -> should_start?(process)
      {process, _} -> should_start?(process)
      process -> should_start?(process)
    end)
    |> Enum.map(fn
      {process, args, opts} -> Supervisor.child_spec({process, args}, opts)
      {process, args} -> Supervisor.child_spec({process, args}, [])
      process -> Supervisor.child_spec({process, []}, [])
    end)
  end

  defp should_start?(nil), do: false

  defp should_start?(process) do
    case Application.get_env(NatEx, process) do
      nil ->
        true

      conf when is_list(conf) ->
        Keyword.get(conf, :enabled, true)

      mod when is_atom(mod) ->
        NatEx
        |> Application.get_env(mod, [])
        |> Keyword.get(:enabled, true)
    end
  end
end
