defmodule Natex.NAT do
  @moduledoc false
  @nat_tries 3
  @nat_initial_ms 250
  @lifetime 3600

  alias Natex.NATCache
  alias Natex.NatupnpV1
  alias Natex.NatupnpV2
  alias Natex.Natpmp

  @supported_protocols [NatupnpV1, NatupnpV2, Natpmp]
  @discover_timeout 5_000

  @type conn_protocol :: :tcp | :udp
  @type context :: any()

  def debug_start(file) do
    {:ok, _} = NATCache.start(file: file)
    # :ok = Intercept.add(:gen_udp, :gen_udp_intercepts, [[{:send, 4}, :send]])
    # :ok = Intercept.add(:httpc, :httpc_intercepts, [[{:request, 1}, :request], {request, 4}, request]])
    # :ok = Intercept.add(:inet_ext, :inet_ext_intercepts, [[{:get_internal_address, 1}, :get_internal_address]])
  end

  def debug_stop() do
    NATCache.stop()
    # :ok = Intercept.clean(:gen_udp)
    # :ok = Intercept.clean(:httpc)
    # :ok = Intercept.clean(:inet_ext)
  end

  def discover() do
    :ok = Application.start(:inets)
    # self = self()
    # ref = make_ref()
    # workers = spawn_workers(@backends, self, ref, [])
    # discover_loop(workers, ref)
  end

  def get_device_address({mod, ctx}) do
    mod.get_device_address(ctx)
  end

  def get_external_address({mod, ctx}) do
    mod.get_external_address(ctx)
  end

  def get_internal_address({mod, ctx}) do
    mod.get_internal_address(ctx)
  end

  # @spec add_port_mapping(nat_ctx, nat_protocol, non_neg_integer, non_neg_integer) ::
  #         {:ok, non_neg_integer, non_neg_integer, non_neg_integer, non_neg_integer | :infinity}
  #         | {:error, any | :timeout}
  def add_port_mapping(ctx, protocol, internal_port, external_port_request) do
    {mod, ctx} = ctx
    mod.add_port_mapping(ctx, protocol, internal_port, external_port_request)
  end

  # @spec add_port_mapping(nat_ctx, nat_protocol, non_neg_integer, non_neg_integer, non_neg_integer) ::
  #         {:ok, non_neg_integer, non_neg_integer, non_neg_integer, non_neg_integer | :infinity}
  #         | {:error, any | :timeout}
  def add_port_mapping(ctx, protocol, internal_port, external_port_request, lifetime) do
    {mod, ctx} = ctx
    mod.add_port_mapping(ctx, protocol, internal_port, external_port_request, lifetime)
  end

  # @spec delete_port_mapping(nat_ctx, nat_protocol, non_neg_integer, non_neg_integer) ::
  #         :ok
  #         | {:error, any | :timeout}
  def delete_port_mapping(ctx, protocol, internal_port, external_port) do
    {mod, ctx} = ctx
    mod.delete_port_mapping(ctx, protocol, internal_port, external_port)
  end

  defp discover_loop([], _ref), do: :no_nat

  defp discover_loop(workers, ref) do
    receive do
      {:nat, _ref, pid, ctx} ->
        demonitor_worker(pid)
        kill_workers(workers -- [pid])
        {:ok, ctx}

      {:DOWN, _, _, pid, _} ->
        demonitor_worker(pid)
        discover_loop(workers -- [pid], ref)
    after
      @discover_timeout ->
        kill_workers(workers)
        :no_nat
    end
  end

  defp discover_worker(backend, parent, ref) do
    case backend.discover() do
      {:ok, ctx} ->
        send(parent, {:nat, ref, self(), {backend, ctx}})

      _error ->
        :ok
    end
  end

  defp spawn_workers([], _parent, _ref, acc), do: acc

  defp spawn_workers([backend | rest], parent, ref, acc) do
    pid = spawn_link(fn -> discover_worker(backend, parent, ref) end)
    monitor_worker(pid)
    spawn_workers(rest, parent, ref, [pid | acc])
  end

  defp monitor_worker(pid) do
    mref = Process.monitor(pid)
    :erlang.put({:discover, pid}, mref)
  end

  defp demonitor_worker(pid) do
    case :erlang.erase({:discover, pid}) do
      :undefined -> :ok
      mref -> Process.demonitor(mref, flush: true)
    end

    :ok
  end

  defp kill_workers([]), do: :ok

  defp kill_workers([pid | rest]) do
    :erlang.unlink(pid)
    :erlang.exit(pid, :shutdown)

    receive do
      {:DOWN, _, _, pid, _} ->
        demonitor_worker(pid)
        :ok
    end

    kill_workers(rest)
  end
end
