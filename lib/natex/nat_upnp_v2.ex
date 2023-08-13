defmodule Natex.NatupnpV2 do
  @moduledoc """

  """
  alias Natex.Utils
  alias Natex.NatUPnP
  alias Natex.Application
  use Natex.Constants

  def discover() do
    Application.start(:inets)

    # open port zero https://www.erlang.org/doc/man/gen_udp.html#type-option
    msearch_msg =
      ~s(M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: #{@st2}\r\nMX: 3\r\n\r\n)

    {:ok, socket} = :gen_udp.open(0, [:binary, :inet, active: true])

    try do
      do_discover(socket, msearch_msg, _attempts = 3)
    rescue
      e -> Logger.debug("Error: #{inspect(e)}")
    after
      :gen_udp.close(socket)
    end
  end

  def do_discover(_socket, _msg, 0), do: {:error, :timeout}

  def do_discover(socket, msg, attempts) do
    :inet.setopts(socket, active: true)
    :gen_udp.send(socket, @multicast_ip, @multicast_port, msg)

    with {:ok, device_external_ip, location} <- await_reply(socket, @discover_timeout),
         {:ok, url} <- get_service_url(location),
         internal_ip <- :inet_ext.get_internal_address(device_external_ip),
         :enabled <- get_natrsipstatus(url) do
      Logger.debug("Found device at #{internal_ip} with location #{location}")
      {:ok, %NatUPnP{service_url: url, ip: internal_ip, version: "2"}}
    else
      :disabled ->
        Logger.debug("Device found but NAT is disabled")
        {:error, :no_nat}

      {:error, :timeout} ->
        Logger.debug("No device found")
        do_discover(socket, msg, attempts - 1)

      e ->
        Logger.debug("Error: [#{__MODULE__}] [do_discover] #{inspect(e)}")
        do_discover(socket, msg, attempts - 1)
    end
  end

  # waits reply from the an IGD device
  @spec await_reply(socket :: :inet.socket(), timer :: non_neg_integer()) ::
          {:ok, :inet.ip4_address(), String.t()} | {:error, :timeout}
  def await_reply(socket, timer) do
    receive do
      {:udp, ^socket, device_internal_ip, _replying_port, packet} ->
        Logger.debug("Received: #{inspect(packet)}")

        case parse(packet) do
          {:error, _} ->
            await_reply(socket, timer)

          {:ok, location} ->
            {:ok, device_internal_ip, location}
        end
    after
      timer ->
        Logger.debug("Timeout")
        {:error, :timeout}
    end
  end

  def parse(data) do
    header = Utils.get_headers(data)
    service_type = Map.get(header, "ST", nil)
    location = Map.get(header, "LOCATION", nil)
    expected_st = @st2

    case {service_type, location} do
      {_service_type, nil} ->
        {:error, :no_location}

      {^expected_st, location} ->
        {:ok, location}

      _ ->
        {:error, :not_supported}
    end
  end

  def get_natrsipstatus(url) do
    # https://datatracker.ietf.org/doc/html/rfc3102
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-upigd/d675b3fe-f8c0-448c-a7cf-4f3895ba2e91
    msg = """
    <u:GetNATRSIPStatus xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:GetNATRSIPStatus>
    """

    case Utils.soap_request(url, "GetNATRSIPStatus", msg) do
      {:ok, body} ->
        # https://www.erlang.org/doc/man/xmerl_scan#string-2
        {xml, _} = :xmerl_scan.string(body, space: :normalize)

        # https://www.erlang.org/doc/man/xmerl_xpath#string-2
        [infos | _] = :xmerl_xpath.string("//s:Envelope/s:Body/u:GetNATRSIPStatusResponse", xml)

        case Utils.extract_txt(:xmerl_xpath.string("NewNATEnabled/text()", infos)) do
          "1" ->
            :enabled

          "0" ->
            :disabled
        end

      e ->
        Logger.debug("Error: [#{__MODULE__}] [] #{inspect(e)}")
        e
    end
  end

  def get_service_url(root_url) do
    igd_device_upnp1 = @igd_device_upnp1
    igd_device_upnp2 = @igd_device_upnp2

    case :httpc.request(root_url) do
      {ok, {{_, 200, _}, _, body}} ->
        {xml, _} = :xmerl_scan.string(body, [{:space, :normalize}])
        [device | _] = :xmerl_xpath.string("//device", xml)

        case Utils.device_type(Device) do
          ^igd_device_upnp1 ->
            Utils.get_wan_device(Device, RootUrl)

          ^igd_device_upnp2 ->
            Utils.get_wan_device(Device, RootUrl)

          e ->
            Logger.debug("Error: [#{__MODULE__}] [get_service_url] #{inspect(e)}")
            {:error, :no_gateway_device}
        end

      {:ok, %{status_code: status_code}} ->
        {:error, Integer.to_string(status_code)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def add_port_mapping(context, protocol, internal_port, external_port, mapping_lifetime) do
    {:ok, :since, :internal_port, :external_port, :mapping_lifetime}
  end

  def delete_port_mapping(context, protocol, internal_port, external_port) do
    :ok
  end

  def get_external_address(context) do
    {:ok, :ext_address}
  end

  def get_internal_address(context) do
    {:ok, :int_address}
  end
end
