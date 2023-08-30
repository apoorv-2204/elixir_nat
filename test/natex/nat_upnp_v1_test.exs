defmodule Natex.NatUpnpV1Test do
@moduledoc false
use ExUnit

  @reply     ~s(HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Thu, 01 Jan 1970 04:51:45 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.1:52869/gatedesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: e02642a8-1dec-11b2-9b3f-bb4cd02d4bbe\r\nSERVER: Linux, UPnP/1.0, Portable SDK for UPnP devices/1.6.22\r\nX-User-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:20809696-105a-3721-e8b8-28777726497e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n)

  test "Parse data" do

  end
end
