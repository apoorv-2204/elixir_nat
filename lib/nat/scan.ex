defmodule Nat.NATScan do
  @cache_file Application.compile_env(:nat, :cache_file, "nat_cache")

  # alias Nat.NAT
  alias Nat.Upnpv1
  alias Nat.Upnpv2
  alias Nat.PMP

  require Logger

  def natupnp_v1() do
    Logger.debug("[Upnpv1] discovering")

    with {:ok, ctx} <- Upnpv1.discover(),
         {:ok, since, internal_port, external_port, mapping_lifetime} <-
           Upnpv1.add_port_mapping(ctx, :tcp, 8333, 8333, 3600),
         :ok <- Upnpv1.delete_port_mapping(ctx, :tcp, 8333, 8333),
         {:ok, ext_address} <- Upnpv1.get_external_address(ctx),
         {:ok, int_address} <- Upnpv1.get_internal_address(ctx) do
    else
      e ->
        Logger.debug("[Upnpv1] failed to add port mapping #{inspect(e)}")
    end

    # case Upnpv1.discover() do
    #   {:ok, context} ->
    #     Logger.debug("[Upnpv1] discovered #{inspect(context)}")

    #     case Upnpv1.add_port_mapping(context, :tcp, 8333, 8333, 3600) do
    #       {:ok, since, internal_port, external_port, mapping_lifetime} = ok ->
    #         Logger.debug("[Upnpv1] added port mapping #{inspect(ok)}")

    #         case Upnpv1.delete_port_mapping(context, :tcp, 8333, 8333) do
    #           :ok ->
    #             Logger.debug("[Upnpv1] deleted port mapping")

    #           {:error, reason} ->
    #             Logger.debug("[Upnpv1] failed to delete port mapping #{inspect(reason)}")
    #         end

    #       {:error, reason} ->
    #         Logger.debug("[Upnpv1] failed to add port mapping #{inspect(reason)}")
    #     end

    #     case Upnpv1.get_external_address(context) do
    #       {:ok, ext_address} ->
    #         Logger.debug("[Upnpv1] got external address #{inspect(ext_address)}")

    #       {:error, reason} ->
    #         Logger.debug("[Upnpv1] failed to get external address #{inspect(reason)}")
    #     end

    #     case Upnpv1.get_internal_address(context) do
    #       {:ok, int_address} ->
    #         Logger.debug("[Upnpv1] got internal address #{inspect(int_address)}")
    #     end

    #   {:error, reason} ->
    #     Logger.debug("[Upnpv1] failed to discover #{inspect(reason)}")
    # end
  end

  def natupnp_v2() do
    Logger.debug("[natupnp_v2] discovering")

    case Upnpv2.discover() do
      {:ok, context} ->
        Logger.debug("[natupnp_v2] discovered #{inspect(context)}")

        case Upnpv2.add_mapping(context, :tcp, 8333, 8333, 3600) do
          {:ok, since, internal_port, external_port, mapping_lifetime} = ok ->
            Logger.debug("[natupnp_v2] added port mapping #{inspect(ok)}")

            case Upnpv2.delete_port_mapping(context, :tcp, 8333, 8333) do
              :ok ->
                Logger.debug("[natupnp_v2] deleted port mapping")

              {:error, reason} ->
                Logger.debug("[natupnp_v2] failed to delete port mapping #{inspect(reason)}")
            end

          {:error, reason} ->
            Logger.debug("[natupnp_v2] failed to add port mapping #{inspect(reason)}")
        end

        case Upnpv2.get_external_address(context) do
          {:ok, ext_address} ->
            Logger.debug("[natupnp_v2] got external address #{inspect(ext_address)}")

          {:error, reason} ->
            Logger.debug("[natupnp_v2] failed to get external address #{inspect(reason)}")
        end

        case Upnpv2.get_internal_address(context) do
          {:ok, int_address} ->
            Logger.debug("[natupnp_v2] got internal address #{inspect(int_address)}")
        end

      {:error, reason} ->
        Logger.debug("[natupnp_v2] failed to discover #{inspect(reason)}")
    end
  end

  def natpmp() do
    Logger.debug("[natpmp] discovering")

    case PMP.discover() do
      {:ok, context} ->
        Logger.debug("[natpmp] discovered #{inspect(context)}")

        case PMP.add_port_mapping(context, :tcp, 8333, 8333, 3600) do
          {:ok, since, internal_port, external_port, mapping_lifetime} = ok ->
            Logger.debug("[natpmp] added port mapping #{inspect(ok)}")

            case PMP.delete_port_mapping(context, :tcp, 8333, 8333) do
              :ok ->
                Logger.debug("[natpmp] deleted port mapping")

              {:error, reason} ->
                Logger.debug("[natpmp] failed to delete port mapping #{inspect(reason)}")
            end

          {:error, reason} ->
            Logger.debug("[natpmp] failed to add port mapping #{inspect(reason)}")
        end

        case PMP.get_external_address(context) do
          {:ok, ext_address} ->
            Logger.debug("[natpmp] got external address #{inspect(ext_address)}")

          {:error, reason} ->
            Logger.debug("[natpmp] failed to get external address #{inspect(reason)}")
        end

        case PMP.get_internal_address(context) do
          {:ok, int_address} ->
            Logger.debug("[natpmp] got internal address #{inspect(int_address)}")
        end

      {:error, :no_nat} ->
        Logger.debug("[natpmp] failed to discover not nat")
    end
  end
end
