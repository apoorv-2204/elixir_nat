defmodule Nat.NatUpnpV1Test do
  @moduledoc false
  use ExUnit.Case

  alias Nat.Upnpv1

  @reply ~s(HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Thu, 01 Jan 1970 04:51:45 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.1:59999/gatedesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: c0b642e8-1eec-1eb2-9e3f-dd5el02ta3ro\r\nSERVER: Linux, UPnP/1.0, Portable SDK for UPnP devices/1.6.22\r\nX-User-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:99665656-195e-3829-g8d8-28993426697f::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n)

  test "Parse data" do
    {:ok, "http://192.168.1.1:59999/gatedesc.xml"} = Upnpv1.parse(@reply)
  end
end
