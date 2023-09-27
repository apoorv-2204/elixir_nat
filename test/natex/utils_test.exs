defmodule Nat.NatUpnpV1Test do
  @moduledoc false
  use ExUnit.Case

  alias Nat.Utils

  @reply ~s(HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Thu, 01 Jan 1970 04:51:45 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.1:59999/gatedesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: c0b642e8-1eec-1eb2-9e3f-dd5el02ta3ro\r\nSERVER: Linux, UPnP/1.0, Portable SDK for UPnP devices/1.6.22\r\nX-User-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:99665656-195e-3829-g8d8-28993426697f::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n)
  @root_url "http://192.168.1.1:59999/gatedesc.xml"
  # test "Find IGD location" do
  #   {:ok, "http://192.168.1.1:59999/gatedesc.xml"} = Utils.find_igd_location(@reply)
  # end

  test "scan xml page" do
    response =
      "<?xml version=\"1.0\"?>\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\n  <specVersion>\n    <major>1</major>\n    <minor>0</minor>\n  </specVersion>\n  <URLBase>http://192.168.1.1:52869</URLBase>\n  <device>\n    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\n    <friendlyName>UPNP IGD</friendlyName>\n    <manufacturer>ZTE</manufacturer>\n    <manufacturerURL>http://www.zte.com</manufacturerURL>\n    <modelDescription>ZTE Broadband Home Gateway</modelDescription>\n    <modelName>F670LV9.0</modelName>\n    <modelNumber>V1.0</modelNumber>\n    <modelURL>http://www.zte.com</modelURL>\n    <UDN>uuid:20809696-105a-3721-e8b8-28777726497e</UDN>\n    <UPC></UPC>\n    <serialNumber>ZTEVQJNN2T00829</serialNumber>\n    <iconList>\n      <icon>\n        <mimetype>image/gif</mimetype>\n        <width>118</width>\n        <height>119</height>\n        <depth>8</depth>\n        <url>/ligd.gif</url>\n      </icon>\n    </iconList>\n    <serviceList>\n      <service>\n        <serviceType>urn:schemas-microsoft-com:service:OSInfo:1</serviceType>\n        <serviceId>urn:microsoft-com:serviceId:OSInfo1</serviceId>\n        <controlURL>/upnp/control/OSInfo1</controlURL>\n        <eventSubURL>/upnp/event/OSInfo1</eventSubURL>\n        <SCPDURL>/gateinfoSCPD.xml</SCPDURL>\n      </service>\n    </serviceList>\n    <deviceList>\n      <device>\n        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\n        <friendlyName>UPNP IGD</friendlyName>\n        <manufacturer>ZTE</manufacturer>\n        <manufacturerURL>http://www.zte.com</manufacturerURL>\n        <modelDescription>WAN Device on Linux IGD</modelDescription>\n        <modelName>F670LV9.0</modelName>\n        <modelNumber>V1.0</modelNumber>\n        <modelURL>http://www.zte.com</modelURL>\n        <UDN>uuid:20809696-205a-3721-e8b8-28777726497e</UDN>\n        <UPC></UPC>\n        <serialNumber>ZTEVQJNN2T00829</serialNumber>\n        <serviceList>\n          <service>\n            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>\n            <serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>\n            <controlURL>/upnp/control/WANCommonIFC1</controlURL>\n            <eventSubURL>/upnp/control/WANCommonIFC1</eventSubURL>\n            <SCPDURL>/gateicfgSCPD.xml</SCPDURL>\n          </service>\n        </serviceList>\n        <deviceList>\n          <device>\n            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\n            <friendlyName>UPNP IGD</friendlyName>\n            <manufacturer>ZTE</manufacturer>\n            <manufacturerURL>http://www.zte.com</manufacturerURL>\n            <modelDescription>WanConnectionDevice ZTE HGW</modelDescription>\n            <modelName>F670LV9.0</modelName>\n            <modelNumber>V1.0</modelNumber>\n            <modelURL>http://www.zte.com</modelURL>\n            <UDN>uuid:20809696-305a-3721-e8b8-28777726497e</UDN>\n            <UPC></UPC>\n            <serialNumber>ZTEVQJNN2T00829</serialNumber>\n            <serviceList>\n              <service>\n                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\n                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>\n                <controlURL>/upnp/control/WANIPConn1</controlURL>\n                <eventSubURL>/upnp/control/WANIPConn1</eventSubURL>\n                <SCPDURL>/gateconnSCPD.xml</SCPDURL>\n              </service>\n              <service>\n                <serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType>\n                <serviceId>urn:upnp-org:serviceId:WANIPv6FwCtrl1</serviceId>\n                <controlURL>/upnp/control/WANIPv6FwCtrl1</controlURL>\n                <eventSubURL>/upnp/control/WANIPv6FwCtrl1</eventSubURL>\n                <SCPDURL>/gatev6fwctrlSCPD.xml</SCPDURL>\n              </service>\n            </serviceList>\n          </device>\n        </deviceList>\n      </device>\n    </deviceList>\n    <presentationURL>http://192.168.1.1</presentationURL>\n  </device>\n</root>\n"

    device = Utils.find_device(response)
    'urn:schemas-upnp-org:device:InternetGatewayDevice:1' = Utils.device_type(device)

    Utils.get_wan_device(device, @root_url)
    |> IO.inspect()
  end

end
defmodule temp do
  def tempdo() do
    with {:await_reply, {:ok, ip, location}} <- {:await_reply, await_reply(socket, timeout)},
         {:ok, url} <- Utils.get_service_url(location),
         my_ip <- :inet.getaddr(ip, :inet) do
      # https://www.erlang.org/doc/man/inet#getaddr-2
      {:ok, %Nat.Protocol{service_url: url, ip: my_ip}}
    else
      {:await_reply, {:ok, ip, location}} ->
      {:error, reason} ->
        {:error, reason}

      :error ->
        do_discover(socket, m_search, attempts - 1)
    end
  end

  def init do
    %{
        error: [],
        service_type: 'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        igd_device_st: 'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        wan_device_st: 'urn:schemas-upnp-org:device:WANDevice:1',
        wan_conn_device_st: 'urn:schemas-upnp-org:device:WANConnectionDevice:1',
        m_search_msg:    ~s(M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: #{@st1}\r\nMX: 3\r\n\r\n),
        port: 0,
        socket_options: [:inet, :binary, active: :once],
        service_type: "St",
        root_url: '',
        device_type_x_path:     'deviceType/text()',
        socket: nil,
        device_list_x_path: 'deviceList/device',
        st_list_x_path: 'serviceList/service',
        st_xpath: 'serviceType/text',

      }
  end
end
