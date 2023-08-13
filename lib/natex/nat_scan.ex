defmodule Natex.NATScan do
  @cache_file Application.compile_env(:natex, :cache_file, "nat_cache")

  alias Natex.NATCache
  alias Natex.Intercepts.GenUdp
  alias Natex.Intercepts.Httpc

  alias Natex.Intercepts
  alias Natex.NatupnpV1
  alias Natex.NatupnpV2
  alias Natex.Natpmp

  require Logger

  def start() do
    {:ok, host_name} = :inet.gethostname()
    NATCache.start([{:file, host_name}, {:get, false}])

    # ok = intercept:add(gen_udp, gen_udp_intercepts, [{{send, 4}, send}]),
    # ok = intercept:add(httpc, httpc_intercepts, [{{request, 1}, request}, {{request, 4}, request}]),
    # ok = intercept:add(inet_ext, inet_ext_intercepts, [{{get_internal_address, 1}, get_internal_address}]),
    # ok = intercept:clean(gen_udp),
    # ok = intercept:clean(httpc),
    # ok = intercept:clean(inet_ext),

    # _ = natupnp_v1(),
    # _ = natupnp_v2(),
    # _ = natpmp(),

    NATCache.stop()
  end

  def natupnp_v1() do
    Logger.debug("[NatupnpV1] discovering")

    case NatupnpV1.discover() do
      {:ok, context} ->
        Logger.debug("[NatupnpV1] discovered #{inspect(context)}")

        case NatupnpV1.add_port_mapping(context, :tcp, 8333, 8333, 3600) do
          {:ok, since, internal_port, external_port, mapping_lifetime} = ok ->
            Logger.debug("[NatupnpV1] added port mapping #{inspect(ok)}")

            case NatupnpV1.delete_port_mapping(context, :tcp, 8333, 8333) do
              :ok ->
                Logger.debug("[NatupnpV1] deleted port mapping")

              {:error, reason} ->
                Logger.debug("[NatupnpV1] failed to delete port mapping #{inspect(reason)}")
            end

          {:error, reason} ->
            Logger.debug("[NatupnpV1] failed to add port mapping #{inspect(reason)}")
        end

        case NatupnpV1.get_external_address(context) do
          {:ok, ext_address} ->
            Logger.debug("[NatupnpV1] got external address #{inspect(ext_address)}")

          {:error, reason} ->
            Logger.debug("[NatupnpV1] failed to get external address #{inspect(reason)}")
        end

        case NatupnpV1.get_internal_address(context) do
          {:ok, int_address} ->
            Logger.debug("[NatupnpV1] got internal address #{inspect(int_address)}")
        end

      {:error, reason} ->
        Logger.debug("[NatupnpV1] failed to discover #{inspect(reason)}")
    end
  end

  def natupnp_v2() do
    Logger.debug("[natupnp_v2] discovering")

    case NatupnpV2.discover() do
      {:ok, context} ->
        Logger.debug("[natupnp_v2] discovered #{inspect(context)}")

        case NatupnpV2.add_port_mapping(context, :tcp, 8333, 8333, 3600) do
          {:ok, since, internal_port, external_port, mapping_lifetime} = ok ->
            Logger.debug("[natupnp_v2] added port mapping #{inspect(ok)}")

            case NatupnpV2.delete_port_mapping(context, :tcp, 8333, 8333) do
              :ok ->
                Logger.debug("[natupnp_v2] deleted port mapping")

              {:error, reason} ->
                Logger.debug("[natupnp_v2] failed to delete port mapping #{inspect(reason)}")
            end

          {:error, reason} ->
            Logger.debug("[natupnp_v2] failed to add port mapping #{inspect(reason)}")
        end

        case NatupnpV2.get_external_address(context) do
          {:ok, ext_address} ->
            Logger.debug("[natupnp_v2] got external address #{inspect(ext_address)}")

          {:error, reason} ->
            Logger.debug("[natupnp_v2] failed to get external address #{inspect(reason)}")
        end

        case NatupnpV2.get_internal_address(context) do
          {:ok, int_address} ->
            Logger.debug("[natupnp_v2] got internal address #{inspect(int_address)}")
        end

      {:error, reason} ->
        Logger.debug("[natupnp_v2] failed to discover #{inspect(reason)}")
    end
  end

  def natpmp() do
    Logger.debug("[natpmp] discovering")

    case Natpmp.discover() do
      {:ok, context} ->
        Logger.debug("[natpmp] discovered #{inspect(context)}")

        case Natpmp.add_port_mapping(context, :tcp, 8333, 8333, 3600) do
          {:ok, since, internal_port, external_port, mapping_lifetime} = ok ->
            Logger.debug("[natpmp] added port mapping #{inspect(ok)}")

            case Natpmp.delete_port_mapping(context, :tcp, 8333, 8333) do
              :ok ->
                Logger.debug("[natpmp] deleted port mapping")

              {:error, reason} ->
                Logger.debug("[natpmp] failed to delete port mapping #{inspect(reason)}")
            end

          {:error, reason} ->
            Logger.debug("[natpmp] failed to add port mapping #{inspect(reason)}")
        end

        case Natpmp.get_external_address(context) do
          {:ok, ext_address} ->
            Logger.debug("[natpmp] got external address #{inspect(ext_address)}")

          {:error, reason} ->
            Logger.debug("[natpmp] failed to get external address #{inspect(reason)}")
        end

        case Natpmp.get_internal_address(context) do
          {:ok, int_address} ->
            Logger.debug("[natpmp] got internal address #{inspect(int_address)}")
        end

      {:error, :no_nat} ->
        Logger.debug("[natpmp] failed to discover not nat")
    end
  end
end
