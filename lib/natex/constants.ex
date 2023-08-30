defmodule Natex.Constants do
  @moduledoc false

  defmacro __using__(_) do
    quote do
      @st1 "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
      @igd_device_upnp1 "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
      @wan_device_upnp1 "urn:schemas-upnp-org:device:WANDevice:1"
      # @supported_protocols [NatupnpV1, NatupnpV2, Natpmp]

      @discover_timeout 5_000
      # :inet.parse_address('239.255.255.250')
      @multicast_ip {239, 255, 255, 250}
      @multicast_port 1900
      @mx_secs "3"
      @default_mapping_lifetime 7200
      @nat_initial_ms 200
      @default_attempts 3

      @st2 "urn:schemas-upnp-org:device:InternetGatewayDevice:2"
      @igd_device_upnp2 "urn:schemas-upnp-org:device:InternetGatewayDevice:2"
      @wan_device_upnp2 "urn:schemas-upnp-org:device:WANDevice:2"

      require Logger

      @nat_tries 3
      @nat_initial_ms 250
      @lifetime 3600

      @pmp_port 5351
    end
  end
end
