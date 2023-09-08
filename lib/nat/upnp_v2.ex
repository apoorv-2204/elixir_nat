defmodule Nat.Upnpv2 do
  @moduledoc """

  """
  alias Nat.Utils
  use Nat.Constants

  def discover() do
    # Application.start(:inets)

    # open port zero https://www.erlang.org/doc/man/gen_udp.html#type-option
    msearch_msg =
      ~s(M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: #{@st2}\r\nMX: 3\r\n\r\n)

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
    # https://www.erlang.org/doc/man/inet#setopts-2
    # https://www.erlang.org/doc/man/gen_udp#type-option
    :inet.setopts(socket, active: true)
    :gen_udp.send(socket, @multicast_ip, @multicast_port, msg)

    with {:ok, device_external_ip, location} <- await_reply(socket, @discover_timeout),
         {:ok, url} <- get_service_url(location),
         internal_ip <- :inet_ext.get_internal_address(device_external_ip),
         :enabled <- get_natrsipstatus(url) do
      Logger.debug("Found device at #{internal_ip} with location #{location}")
      {:ok, %Nat.Protocol{service_url: url, ip: internal_ip, version: "2"}}
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
      {:udp, ^socket, igd_internal_ip, _replying_port, packet} ->
        Logger.debug("Received: #{inspect(packet)}")

        case parse(packet) do
          {:error, _} ->
            await_reply(socket, timer)

          {:ok, location} ->
            {:ok, igd_internal_ip, location}
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

    IO.inspect(binding())

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

    case :httpc.request(root_url) |> debug_log() do
      {:ok, {{_, 200, _}, _, body}} ->
        {xml, _} = :xmerl_scan.string(body, [{:space, :normalize}])
        [device | _] = :xmerl_xpath.string("//device", xml)

        case Utils.device_type(device) do
          ^igd_device_upnp1 ->
            Utils.get_wan_device(Device, RootUrl, "2")

          ^igd_device_upnp2 ->
            Utils.get_wan_device(Device, RootUrl, "2")

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

  def status_info(%Nat.Protocol{service_url: url}) do
    msg = """
    <u:GetStatusInfo xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:GetStatusInfo>
    """

    case Utils.soap_request(url, "GetStatusInfo", msg) do
      {:ok, body} ->
        {xml, _} = :xmerl_scan.string(body, space: :normalize)
        [infos | _] = :xmerl_xpath.string("//s:Envelope/s:Body/u:GetStatusInfoResponse", xml)
        status = Utils.extract_txt(:xmerl_xpath.string("NewConnectionStatus/text()", infos))

        last_conn_error =
          Utils.extract_txt(:xmerl_xpath.string("NewLastConnectionError/text()", infos))

        up_time = Utils.extract_txt(:xmerl_xpath.string("NewUptime/text()", infos))
        {status, last_conn_error, up_time}
        {:ok, status, last_conn_error}

      e ->
        Logger.debug("Error: [#{__MODULE__}] [status_info] #{inspect(e)}")
        e
    end
  end

  def add_mapping(
        context,
        protocol,
        internal_port,
        external_port,
        lifetime \\ @default_mapping_lifetime
      ) do
    case external_port do
      0 ->
        random_mapping(
          context,
          protocol,
          internal_port,
          lifetime,
          _error = nil,
          _attempts = @default_attempts
        )

      _ ->
        do_add_mapping(Ctx, Protocol, InternalPort, ExternalPort, Lifetime)
    end
  end

  def random_mapping(_, _, _, _lifetime, _error, 0), do: {:error, :no_available_port}

  def random_mapping(context, protocol, internal_port, lifetime, error, attempts) do
    external_port = Enum.random(41000..62000)

    case do_add_mapping(context, protocol, internal_port, external_port, lifetime) do
      {:ok, _} ->
        {:ok, external_port}

      {:error, :conflict} ->
        random_mapping(context, protocol, internal_port, lifetime, error, attempts - 1)

      e ->
        Logger.debug("Error: [#{__MODULE__}] [random_mapping] #{inspect(e)}")
        e
    end
  end

  def debug_log(ctx) do
    Utils.debug_log({"[UPNPV1]", ctx})
    ctx
  end

  def do_add_mapping(
        nat_ctx = %Nat.Protocol{ip: ip, service_url: url},
        protocol,
        internal_port,
        external_port,
        lifetime
      ) do
    description = "#{ip}_#{protocol}_#{Integer.to_string(internal_port)}"

    msg = """
      <u:AddAnyPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:2">
        <NewRemoteHost></NewRemoteHost>
        <NewExternalPort>#{Integer.to_string(external_port)}</NewExternalPort>
        <NewProtocol>#{protocol}</NewProtocol>
        <NewInternalPort>#{Integer.to_string(internal_port)}</NewInternalPort>
        <NewInternalClient>#{ip}</NewInternalClient>
        <NewEnabled>1</NewEnabled>
        <NewPortMappingDescription>#{description}</NewPortMappingDescription>
        <NewLeaseDuration>#{Integer.to_string(lifetime)}</NewLeaseDuration>
      </u:AddAnyPortMapping>
    """

    with {:ok, ip_addr} <- :inet.parse_address(ip),
         start <- Utils.timestamp(),
         {:ok, body} <-
           Utils.soap_request(url, "AddAnyPortMapping", msg, socket_opts: [ip: ip_addr]) do
      {xml, _} = :xmerl_scan.string(body, space: :normalize)

      [resp | _] = :xmerl_xpath.string("//s:Envelope/s:Body/u:AddAnyPortMappingResponse", xml)

      reserved_port = Utils.extract_txt(:xmerl_xpath.string("NewReservedPort/text()", resp))

      now = Utils.timestamp()
      mapping_lifetime = lifetime - (now - start)

      {:ok, now, internal_port, String.to_integer(reserved_port), mapping_lifetime}
    else
      {:error, :einval} ->
        {:error, :einval}

      error when lifetime > 0 ->
        case only_permanent_lease_supported(error) do
          true ->
            Logger.debug("UPNP: only permanent lease supported")
            do_add_mapping(nat_ctx, protocol, internal_port, external_port, 0)

          false ->
            error
        end

      e ->
        e
    end
  end

  def only_permanent_lease_supported({:error, {:http_error, "500", body}}) do
    {xml, _} = :xmerl_scan.string(body, space: :normalize)
    [error | _] = :xmerl_xpath.string("//s:Envelope/s:Body/s:Fault/detail/UPnPError", xml)
    err_code = Utils.extract_txt(:xmerl_xpath.string("errorCode/text()", error))

    err_code == "725"
  end

  def only_permanent_lease_supported(_), do: false

  def delete_port_mapping(
        %Nat.Protocol{ip: ip, service_url: url},
        protocol,
        _internal_port,
        external_port
      ) do
    proto = Utils.protocol(protocol)

    msg = """
    <u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>#{Integer.to_string(external_port)}</NewExternalPort>
      <NewProtocol>#{proto}</NewProtocol>
    </u:DeletePortMapping>
    """

    {:ok, igaddr} = :inet.parse_address(ip)

    case Utils.soap_request(url, "DeletePortMapping", msg, socket_opts: [ip: igaddr]) do
      {:ok, body} ->
        Logger.debug("DeletePortMapping: #{inspect(body)}")
        :ok

      e ->
        Logger.debug("Error: [#{__MODULE__}] [delete_port_mapping] #{inspect(e)}")
        e
    end
  end

  def get_port_mapping(%Nat.Protocol{ip: ip, service_url: url}, protocol, external_port) do
    proto = Utils.protocol(protocol)

    msg = """
    <u:GetSpecificPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>#{Integer.to_string(external_port)}</NewExternalPort>
      <NewProtocol>#{proto}</NewProtocol>
    </u:GetSpecificPortMappingEntry>
    """

    {:ok, igaddr} = :inet.parse_address(ip)

    case Utils.soap_request(url, "GetSpecificPortMappingEntry", msg, socket_opts: [ip: igaddr]) do
      {:ok, body} ->
        {xml, _} = :xmerl_scan.string(body, space: :normalize)

        [info | _] =
          :xmerl_xpath.string("//s:Envelope/s:Body/u:GetSpecificPortMappingEntryResponse", xml)

        new_internal_port = Utils.extract_txt(:xmerl_xpath.string("NewInternalPort/text()", info))

        new_internal_client =
          Utils.extract_txt(:xmerl_xpath.string("NewInternalClient/text()", info))

        {:ok, String.to_integer(new_internal_port), new_internal_client}

      e ->
        Logger.debug("Error: [#{__MODULE__}] [get_port_mapping] #{inspect(e)}")
        e
    end
  end
end
