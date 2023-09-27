  The MX field in an SSDP (Simple Service Discovery Protocol) message is used to specify the maximum
  number of seconds that a device should wait before responding to the message. It is used in M-SEARCH
  messages to request that devices search for and return information about available services. In the
  code you provided, the MX field is set to 3, which means that devices should wait a maximum of 3
  seconds before responding to the M-SEARCH messag
  The MAN field in the M-SEARCH message is an HTTP header field that specifies the type of the message.
  In this case, it is set to "ssdp:discover"

  M-SEARCH * HTTP/1.1
  HOST: 239.255.255.250:1900
  MAN: "ssdp:discover"
  MX: seconds to delay response
  ST: search target
  USER-AGENT: OS/version UPnP/1.1 product/version

  MAN
  REQUIRED by HTTP Extension Framework. Unlike the NTS and ST field values, the field value of the MAN header
  field is enclosed in double quotes; it defines the scope (namespace) of the extension. MUST be "ssdp:discover".

  MX
  REQUIRED. Field value contains maximum wait time in seconds. MUST be greater than or equal to 1 and SHOULD
   be less than 5 inclusive.

  ST
  REQUIRED. Field value contains Search Target. MUST be one of the following. (See NT header field in NOTIFY with
   ssdp:alive above.) Single URI.

  `ssdp:all`  => Search for all devices and services.

  `upnp:rootdevice` => Search for root devices only.

  `uuid:device-UUID` => Search for a particular device. device-UUID specified by UPnP vendor.

  `urn:schemas-upnp-org:device:deviceType:ver` => Search for any device of this type where deviceType and ver
  are    defined by the UPnP Forum working committee.

  `urn:schemas-upnp-org:service:serviceType:ver` => Search for any service of this type where serviceType and ver
  are defined by the UPnP Forum working committee.

  `urn:domain-name:device:deviceType:ver` => Search for any device of this typewhere domain-name (a Vendor Domain Name),
   deviceType and ver are defined by the UPnP vendor and ver specifies the highest specifies the highest supported version
    of the device type. Period characters in the Vendor Domain Name MUST be replaced with hyphens in accordance with
     RFC 2141.

  `urn:domain-name:service:serviceType:ver` => Search for any service of this type. Where domain-name
  (a Vendor Domain Name), serviceType and ver are defined by the UPnP vendor and ver specifies the highest specifies
   the highest supported version of the service type. Period characters in the Vendor Domain Name MUST be replaced
    with hyphens in accordance with RFC 2141.

    WANPPPConnection
   PPP connections originating at the gateway or relayed or bridged through the    gateway

  WANIPConnection
  IP connections originating or relayed or bridged through the gateway

  WANPOTSLinkConfig
  Configuration parameters associated with a WAN link on a Plain Old Telephone Service (POTS) modem

  WANDSLLinkConfig
  Configuration parameters associated with a WAN link on a Digital Subscriber  Link (DSL) modem

  WANCableLinkConfig
   Configuration parameters associated with a WAN link on a cable modem

  WANEthernetLinkConfig
   Configuration parameters associated with an Ethernet- attached external modem
  (cable or DSL). If proprietary mechanisms are available to discover and configure
  an external modem, it is recommended that modem-specific LinkConfig services
  be modeled instead of this service

   Starts the inets ( httpc(HTTP/1.1 client , httpd HTTP server API ) application.
    Opens the port 0 and sets the options [:active, :inet, :binary] for the socket.
    Sends the M-SEARCH request to the multicast address
    St: defines server tyype for IGD:1 discovery.
    Gen.udp: is used as a transport protocol for socket.

  An Internet Gateway is a network connecting device/appliance that can be used to connect two devices in two different networks implementing different networking protocols and overall network architectures. The Internet Gateway Device (IGD) Standardized Device Control Protocol is a protocol for mapping ports in network address translation (NAT) setups, supported by some NAT-enabled routers. The protocol is standardized by the UPnP forum, and allows UPnP aware hosts to configure the device to allow incoming connections to the host.

    HTTP/1.1 200 OK
  CACHE-CONTROL: max-age = `seconds until advertisement expires`
  DATE: `when response was generated`
  EXT:
  LOCATION: `URL for UPnP description for root device`
  SERVER: `OS/version UPnP/1.1 product/version`
  ST: `search target`
  USN: `composite identifier for the advertisement BOOTID.UPNP.ORG: number increased each time device sends an initial
   announce or an update message`

  CONFIGID.UPNP.ORG: `number used for caching description information`
  SEARCHPORT.UPNP.ORG: `number identifies port on which device responds to unicast M-SEARCH`




  @doc """
  message => XML-formatted message that can be sent to a UPnP device to request its external IP address.
  The message belongs to the UPnP service "WANIPConnection", which is used to manage internet
  connection settings on the device.
  `GetExternalIPAddress` => operation defined by upnp
  ` WANIPConnection service. ` => service provided by some Internet Gateway Devices (IGDs) that
  allow a device on a home network to request the public IP address of the IGD. pat of upnp protocol
  allows a device to request the public IP address of the IGD, which can be used to set up port
   forwarding or to allow the device to be accessed from the Internet.
  """
  def get_external_address(%Nat.Protocol{service_url: url}) do