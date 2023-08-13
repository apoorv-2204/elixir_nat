# defmodule Natex.NatupnpV1 do
#   @moduledoc """
#   The MX field in an SSDP (Simple Service Discovery Protocol) message is used to specify the maximum
#   number of seconds that a device should wait before responding to the message. It is used in M-SEARCH
#   messages to request that devices search for and return information about available services. In the
#   code you provided, the MX field is set to 3, which means that devices should wait a maximum of 3
#   seconds before responding to the M-SEARCH messag
#   The MAN field in the M-SEARCH message is an HTTP header field that specifies the type of the message.
#   In this case, it is set to "ssdp:discover"

#   M-SEARCH * HTTP/1.1
#   HOST: 239.255.255.250:1900
#   MAN: "ssdp:discover"
#   MX: seconds to delay response
#   ST: search target
#   USER-AGENT: OS/version UPnP/1.1 product/version

#   MAN
#   REQUIRED by HTTP Extension Framework. Unlike the NTS and ST field values, the field value of the MAN header
#   field is enclosed in double quotes; it defines the scope (namespace) of the extension. MUST be "ssdp:discover".

#   MX
#   REQUIRED. Field value contains maximum wait time in seconds. MUST be greater than or equal to 1 and SHOULD
#    be less than 5 inclusive.

#   ST
#   REQUIRED. Field value contains Search Target. MUST be one of the following. (See NT header field in NOTIFY with
#    ssdp:alive above.) Single URI.

#   `ssdp:all`  => Search for all devices and services.

#   `upnp:rootdevice` => Search for root devices only.

#   `uuid:device-UUID` => Search for a particular device. device-UUID specified by UPnP vendor.

#   `urn:schemas-upnp-org:device:deviceType:ver` => Search for any device of this type where deviceType and ver
#   are    defined by the UPnP Forum working committee.

#   `urn:schemas-upnp-org:service:serviceType:ver` => Search for any service of this type where serviceType and ver
#   are defined by the UPnP Forum working committee.

#   `urn:domain-name:device:deviceType:ver` => Search for any device of this typewhere domain-name (a Vendor Domain Name),
#    deviceType and ver are defined by the UPnP vendor and ver specifies the highest specifies the highest supported version
#     of the device type. Period characters in the Vendor Domain Name MUST be replaced with hyphens in accordance with
#      RFC 2141.

#   `urn:domain-name:service:serviceType:ver` => Search for any service of this type. Where domain-name
#   (a Vendor Domain Name), serviceType and ver are defined by the UPnP vendor and ver specifies the highest specifies
#    the highest supported version of the service type. Period characters in the Vendor Domain Name MUST be replaced
#     with hyphens in accordance with RFC 2141.

#     WANPPPConnection
#    PPP connections originating at the gateway or relayed or bridged through the    gateway

#   WANIPConnection
#   IP connections originating or relayed or bridged through the gateway

#   WANPOTSLinkConfig
#   Configuration parameters associated with a WAN link on a Plain Old Telephone Service (POTS) modem

#   WANDSLLinkConfig
#   Configuration parameters associated with a WAN link on a Digital Subscriber  Link (DSL) modem

#   WANCableLinkConfig
#    Configuration parameters associated with a WAN link on a cable modem

#   WANEthernetLinkConfig
#    Configuration parameters associated with an Ethernet- attached external modem
#   (cable or DSL). If proprietary mechanisms are available to discover and configure
#   an external modem, it is recommended that modem-specific LinkConfig services
#   be modeled instead of this service
#   """

#   require Logger
#   alias Natex.Utils
#   alias Natex.NatUPnP
#   use Natex.Constants

#   def msearch_msg() do
#     ~s(M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: #{@st1}\r\nMX: #{@mx_secs}\r\n\r\n)
#   end

#   @doc """
#     Starts the inets ( httpc(HTTP/1.1 client , httpd HTTP server API ) application.
#     Opens the port 0 and sets the options [:active, :inet, :binary] for the socket.
#     Sends the M-SEARCH request to the multicast address
#     St: defines server tyype for IGD:1 discovery.
#     Gen.udp: is used as a transport protocol for socket.

#   An Internet Gateway is a network connecting device/appliance that can be used to connect two devices in two different networks implementing different networking protocols and overall network architectures. The Internet Gateway Device (IGD) Standardized Device Control Protocol is a protocol for mapping ports in network address translation (NAT) setups, supported by some NAT-enabled routers. The protocol is standardized by the UPnP forum, and allows UPnP aware hosts to configure the device to allow incoming connections to the host.

#     HTTP/1.1 200 OK
#   CACHE-CONTROL: max-age = `seconds until advertisement expires`
#   DATE: `when response was generated`
#   EXT:
#   LOCATION: `URL for UPnP description for root device`
#   SERVER: `OS/version UPnP/1.1 product/version`
#   ST: `search target`
#   USN: `composite identifier for the advertisement BOOTID.UPNP.ORG: number increased each time device sends an initial
#    announce or an update message`

#   CONFIGID.UPNP.ORG: `number used for caching description information`
#   SEARCHPORT.UPNP.ORG: `number identifies port on which device responds to unicast M-SEARCH`
#   """
#   def discover do
#     Application.start(:inets)
#     {ok, sock} = :gen_udp.open(0, [:active, :inet, :binary])

#     # msearch = [
#     #   "M-SEARCH * HTTP/1.1\r\n",
#     #   "HOST: 239.255.255.250:1900\r\n",
#     #   "MAN: \"ssdp:discover\"\r\n",
#     #   "ST: #{@st1}\r\n",
#     #   "MX: 3\r\n\r\n"
#     # ]

#     try do
#       do_discover(sock, msearch_msg(), 3)
#     rescue
#       e -> Logger.error("Error: #{inspect(e)}")
#     after
#       :gen_udp.close(sock)
#     end
#   end

#   @doc """
#     Sends the M-SEARCH request to the multicast address(239.255.255.250,1900), from port 0.
#     timeout= simple exponential backoff.left shift operator incresing the value.
#     Wait for the reply from IGD via loop impls a recieve clause.

#   """
#   def do_discover(_sock, _m_search, 0), do: {:error, :timeout}

#   def do_discover(sock, m_search, attempts) do
#     # https://www.erlang.org/doc/man/inet#setopts-2
#     # https://www.erlang.org/doc/man/gen_udp#type-option
#     :inet.setopts(sock, [:once, active: true])

#     timeout = Utils.exponential_backoff(attempts)

#     # https://www.erlang.org/doc/man/gen_udp#send-4
#     :ok = :gen_udp.send(sock, _dest = @multicast_ip, @multicast_port, m_search)

#     with {:ok, ip, location} <- loop(sock, timeout),
#          {:ok, url} <- get_service_url(to_string(location)),
#          my_ip <- :inet.getaddr(ip, :inet) do
#       # https://www.erlang.org/doc/man/inet#getaddr-2
#       {:ok, %NatUPnP{service_url: url, ip: my_ip}}
#     else
#       {:error, reason} ->
#         {:error, reason}

#       :error ->
#         do_discover(sock, m_search, attempts - 1)
#     end
#   end

#   @doc """
#   Wait for reply frmo
#   """
#   def loop(sock, timeout) do
#     receive do
#       {:udp, sock, ip, _port, packet} ->
#         headers = Helpers.get_headers(packet)

#         with ^@st1 <- Map.get(headers, "Sts", :st_not_found),
#              location <- Map.get(headers, "Location", :location_not_found) do
#           {:ok, ip, String.trim(location)}
#         else
#           :st_not_found ->
#             Logger.info("ST Header not found")
#             loop(sock, timeout)

#           :location_not_found ->
#             Logger.info("ST Header not found")
#             loop(sock, timeout)
#         end
#     after
#       timeout ->
#         :error
#     end
#   end

#   def get_device_address(%NatUpnp{service_url: url}) do
#     # https://www.erlang.org/doc/man/uri_string#parse-1
#     # https://hexdocs.pm/elixir/1.14.1/URI.html#parse/1
#     with {:ok, %URI{host: host}} <- URI.parse(url),
#          {:ok, ip} <- :inet.getaddr(host, :inet) do
#       {:ok, :inet.ntoa(ip)}
#     else
#       {:error, posix()} ->
#         Logger.debug("[get_device_address][#{__MODULE__}] get_device_address#{inspect(e)}")

#       e ->
#         Logger.debug("[get_device_address][#{__MODULE__}] get_device_address#{inspect(e)}")
#         :error
#     end
#   end

#   @doc """
#   message => XML-formatted message that can be sent to a UPnP device to request its external IP address.
#   The message belongs to the UPnP service "WANIPConnection", which is used to manage internet
#   connection settings on the device.
#   `GetExternalIPAddress` => operation defined by upnp
#   ` WANIPConnection service. ` => service provided by some Internet Gateway Devices (IGDs) that
#   allow a device on a home network to request the public IP address of the IGD. pat of upnp protocol
#   allows a device to request the public IP address of the IGD, which can be used to set up port
#    forwarding or to allow the device to be accessed from the Internet.
#   """
#   def get_external_address(%NatUpnp{service_url: url}) do
#     message = """
#       <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
#       </u:GetExternalIPAddress>
#     """

#     case Helpers.soap_request(url, "GetExternalIPAddress", message) do
#       {:ok, body} ->
#         {xml, _} = :xmerl_scan.string(body, [{:space, :normalize}])

#         [infos | _] =
#           :xmerl_xpath.string(
#             "//s:Envelope/s:Body/*[local-name() = 'GetExternalIPAddressResponse']",
#             xml
#           )

#         ip = extract_txt(:xmerl_xpath.string("NewExternalIPAddress/text()", infos))

#         {:ok, ip}

#       error ->
#         error
#     end
#   end

#   def get_internal_address(%NatUpnp{ip: ip}) do
#     {:ok, ip}
#   end

#   @doc """
#   Add a port mapping and release after Timeout.
#   """
#   def add_port_mapping(
#         context,
#         protocol,
#         internal_port,
#         external_port,
#         lifetime \\ @recommended_mapping_lifetime_seconds
#       ) do
#     protocol = protocol(protocol)

#     case external_port do
#       0 -> random_port_mapping(context, protocol, internal_port, lifetime, nil, 3)
#       _ -> do_add_port_mapping(context, protocol, internal_port, external_port, lifetime)
#     end
#   end

#   defp random_port_mapping(_context, _protocol, _internal_port, _lifetime, error, 0),
#     do: error

#   defp random_port_mapping(context, protocol, internal_port, lifetime, _last_error, attempts) do
#     external_port = Helpers.random_port()

#     case do_add_port_mapping(context, protocol, internal_port, external_port, lifetime) do
#       {:ok, _, _, _, _} ->
#         {:ok, external_port}

#       error ->
#         random_port_mapping(context, protocol, internal_port, lifetime, error, attempts - 1)
#     end
#   end

#   defp do_add_port_mapping(
#          %NatUpnp{ip: ip, service_url: url} = nat_ctx,
#          protocol,
#          internal_port,
#          external_port,
#          lifetime
#        )
#        when is_integer(lifetime) and lifetime >= 0 do
#     description = "#{ip}_#{protocol}_#{Integer.to_string(internal_port)}"

#     msg = """
#       <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
#       <NewRemoteHost></NewRemoteHost>
#       <NewExternalPort>#{external_port}</NewExternalPort>
#       <NewProtocol>#{protocol}</NewProtocol>
#       <NewInternalPort>#{internal_port}</NewInternalPort>
#       <NewInternalClient>#{ip}</NewInternalClient>
#       <NewEnabled>1</NewEnabled>
#       <NewPortMappingDescription>#{description}</NewPortMappingDescription>
#       <NewLeaseDuration>#{lifetime}</NewLeaseDuration>
#       </u:AddPortMapping>
#     """

#     {ok, iaddr} = :inet.parse_address(ip)
#     start = Helpers.timestamp()

#     case Helpers.soap_request(url, "AddPortMapping", msg, socket_opts: [ip: iaddr]) do
#       {:ok, _} ->
#         now = Helpers.timestamp()

#         mapping_lifetime =
#           if lifetime > 0 do
#             lifetime - (now - start)
#           else
#             :infinity
#           end

#         {:ok, now, internal_port, external_port, mapping_lifetime}

#       error when lifetime > 0 ->
#         case only_permanent_lease_supported(error) do
#           true ->
#             Logger.error("#{__MODULE__}UPNP: only permanent lease supported")
#             do_add_port_mapping(nat_ctx, protocol, internal_port, external_port, 0)

#           false ->
#             error
#         end

#       error ->
#         error
#     end
#   end

#   defp only_permanent_lease_supported({error, {http_error, "500", body}}) do
#     {xml, _} = :xmerl_scan.string(body, space: :normalize)
#     [error_node | _] = :xmerl_xpath.string("//s:Envelope/s:Body/s:Fault/detail/UPnPError", xml)
#     error_code = extract_txt(:xmerl_xpath.string("errorCode/text()", error_node))

#     case error_code do
#       "725" -> true
#       _ -> false
#     end
#   end

#   defp only_permanent_lease_supported(_), do: false

#   def delete_port_mapping(
#         %NatUpnp{ip: ip, service_url: url},
#         protocol,
#         _internal_port,
#         external_port
#       ) do
#     protocol = protocol(protocol)

#     msg = """
#       <u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
#       <NewRemoteHost></NewRemoteHost>
#       <NewExternalPort>#{external_port}</NewExternalPort>
#       <NewProtocol>#{protocol}</NewProtocol>
#       </u:DeletePortMapping>
#     """

#     {ok, iaddr} = :inet.parse_address(ip)

#     case Helpers.soap_request(url, "DeletePortMapping", msg, socket_opts: [ip: iaddr]) do
#       {:ok, _} -> :ok
#       error -> error
#     end
#   end

#   def get_port_mapping(%NatUpnp{ip: ip, service_url: url}, protocol, external_port) do
#     protocol = protocol(protocol)

#     msg = """
#       <u:GetSpecificPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
#       <NewRemoteHost></NewRemoteHost>
#       <NewExternalPort>#{external_port}</NewExternalPort>
#       <NewProtocol>#{protocol}</NewProtocol>
#       </u:GetSpecificPortMappingEntry>
#     """

#     {ok, iaddr} = :inet.parse_address(ip)

#     case Helpers.soap_request(url, "GetSpecificPortMappingEntry", msg, socket_opts: [ip: iaddr]) do
#       {:ok, body} ->
#         {xml, _} = :xmerl_scan.string(body, space: :normalize)

#         [infos | _] =
#           :xmerl_xpath.string("//s:Envelope/s:Body/u:GetSpecificPortMappingEntryResponse", xml)

#         new_internal_port = extract_txt(:xmerl_xpath.string("NewInternalPort/text()", infos))
#         new_internal_client = extract_txt(:xmerl_xpath.string("NewInternalClient/text()", infos))

#         internal_port = String.to_integer(new_internal_port)
#         {:ok, internal_port, new_internal_client}

#       error ->
#         error
#     end
#   end

#   def status_info(%NatUPnP{service_url: url}) do
#     msg =
#       ~s(<u:GetStatusInfo xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:GetStatusInfo>)

#     case Helpers.soap_request(url, "GetStatusInfo", msg) do
#       {:ok, body} ->
#         {xml, _} = :xmerl_scan.string(body, space: :normalize)
#         [infos | _] = :xmerl_xpath.string("//s:Envelope/s:Body/u:GetStatusInfoResponse", xml)

#         status = extract_txt(:xmerl_xpath.string("NewConnectionStatus/text()", infos))

#         last_connection_error =
#           extract_txt(:xmerl_xpath.string("NewLastConnectionError/text()", infos))

#         uptime = extract_txt(:xmerl_xpath.string("NewUptime/text()", infos))
#         {status, last_connection_error, uptime}

#       e ->
#         Logger.debug("[status_info][#{__MODULE__}] #{inspect(e)}")
#         e
#     end
#   end

#   defp get_service_url(root_url) do
#     case :httpc.request(root_url) do
#       {ok, {{_, 200, _}, _, Body}} ->
#         {xml, _} = :xmerl_scan.string(body, [{:space, :normalize}])
#         [device | _] = :xmerl_xpath.string("//device", xml)

#         case device_type(device) do
#           "urn:schemas-upnp-org:device:InternetGatewayDevice:1" ->
#             get_wan_device(device, root_url)

#           _ ->
#             {:error, :no_gateway_device}
#         end

#       {:ok, %{status_code: status_code}} ->
#         {:error, Integer.to_string(status_code)}

#       {:error, _reason} ->
#         {:error, _reason}
#     end
#   end

#   defp get_wan_device(device, root_url) do
#     case get_device(device, "urn:schemas-upnp-org:device:WANDevice:1") do
#       {:ok, device1} ->
#         get_connection_device(device1, root_url)

#       _ ->
#         {:error, :no_wan_device}
#     end
#   end

#   defp get_connection_device(device, root_url) do
#     case get_device(device, "urn:schemas-upnp-org:device:WANConnectionDevice:1") do
#       {:ok, wan_conn_device} ->
#         get_connection_url(wan_conn_device, root_url)

#       _ ->
#         {:error, :no_wanconnection_device}
#     end
#   end

#   defp get_connection_url(d, root_url) do
#     with {:ok, service} <- get_service(d, "urn:schemas-upnp-org:service:WANIPConnection:1"),
#          url <- extract_txt(:xmerl_xpath.string("controlURL/text()", service)),
#          {:fetch_service, [scheme, rest]} <- {:fetch_service, String.split(root_url, "://")},
#          {:fetch_service, [net_loc | _]} <- {:fetch_service, String.split(rest, "/")} do
#       ctl_url = "#{scheme}://#{net_loc}#{url}"
#       {:ok, ctl_url}
#     else
#       {:fetch_service, e} ->
#         Logger.debug("[get_connection_url][#{__MODULE__}] #{inspect(e)}")
#         {:error, :invalid_control_url}

#       _ ->
#         Logger.debug("[get_connection_url][#{__MODULE__}] #{inspect(e)}")
#         {:error, :no_wanipconnection}
#     end
#   end

#   defp get_device(device, device_type) do
#     device_list = :xmerl_xpath.string("deviceList/device", device)
#     find_device(device_list, device_type)
#   end

#   defp find_device([], _device_type), do: false

#   defp find_device([device | rest], device_type) do
#     case device_type(device) do
#       device_type ->
#         {:ok, device}

#       _ ->
#         find_device(rest, device_type)
#     end
#   end

#   defp get_service(device, service_type) do
#     service_list = :xmerl_xpath.string("serviceList/service", device)
#     find_service(service_list, service_type)
#   end

#   defp find_service([], _service_type), do: false

#   defp find_service([s | rest], service_type) do
#     case extract_txt(:xmerl_xpath.string("serviceType/text()", s)) do
#       service_type ->
#         {:ok, s}

#       _ ->
#         find_service(rest, service_type)
#     end
#   end

#   defp device_type(device), do: extract_txt(:xmerl_xpath.string("deviceType/text()", device))

#   defp extract_txt(xml) do
#     # https://www.erlang.org/doc/man/erlang#is_record-2
#     [t | _] = [x.value || x <- xml, :erlang.is_record(x, :xmlText)]
#     t
#   end

#   def split(string, pattern), do: :re.split(string, pattern, return: :list)

#   def protocol(protocol) do
#     case protocol in [:tcp, :udp] do
#       true -> :ok
#       false -> {:error, :bad_protocol}
#     end

#     protocol |> String.upcase()
#   end
# end
