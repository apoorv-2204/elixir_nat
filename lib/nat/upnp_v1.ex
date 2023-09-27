defmodule Nat.Upnpv1 do
  @moduledoc """
    Provides interfaces to open ports for upnp v1 enabled IGD/router
  """

  require Logger
  alias Nat.Utils
  use Nat.Constants

  def msearch_msg() do
    ~s(M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: #{@st1}\r\nMX: 3\r\n\r\n)
  end

  def init do
    %{
      errors: [],
      service_type: 'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
      igd_device_st: 'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
      wan_device_st: 'urn:schemas-upnp-org:device:WANDevice:1',
      wan_conn_device_st: 'urn:schemas-upnp-org:device:WANConnectionDevice:1',
      msearch_msg:
        ~s(M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: #{@st1}\r\nMX: 3\r\n\r\n),
      port: 0,
      socket_options: [:inet, :binary, active: :once],
      service_type: "St",
      root_url: '',
      socket: nil,
      device_list_x_path: 'deviceList/device',
      st_list_x_path: 'serviceList/service',
      st_xpath: 'serviceType/text',
      multicast_ip: @multicast_ip,
      multicast_port: @multicast_port,
      search_attempts: 3,
      igd_internal_ip: nil,
      igd_desc_url: nil
    }
  end

  def search_network() do
    init()
    |> discover()
    |> fetch_service_url()
    |> cleanup()
  end

  def cleanup(state) do
    :gen_udp.close(state[:socket])

    state
  end

  def discover(state = %{errors: [], socket_options: opts, port: port}) do
    {:ok, socket} = :gen_udp.open(port, opts)
    :inet.setopts(socket, active: :once)
    state = %{state | socket: socket}

    try do
      do_discover(state)
    rescue
      e ->
        Logger.error("errors: #{inspect(e)}")
        %{state | errors: [e]}
    after
      :gen_udp.close(state[:socket])
    end
  end

  def discover(state), do: state

  @doc """
    Sends the M-SEARCH request to the multicast address(239.255.255.250,1900), from port 0.
    timeout= simple exponential backoff.left shift operator incresing the value.
    Wait for the reply from IGD via loop impls a recieve clause.

  """
  def do_discover(state = %{search_attempts: 0}),
    do: %{state | errors: [{:timeout, :failed_to_locate_igd}]}

  def do_discover(state) do
    # https://www.erlang.org/doc/man/inet#setopts-2
    # https://www.erlang.org/doc/man/gen_udp#type-option

    timeout = Utils.exponential_backoff(state[:search_attempts])

    :ok =
      :gen_udp.send(
        state[:socket],
        _dest = state[:multicast_ip],
        state[:multicast_port],
        state[:msearch_msg]
      )

    case await_reply(state[:socket], timeout) do
      {:ok, igd_internal_ip, igd_desc_url} ->
        %{state | igd_internal_ip: igd_internal_ip, igd_desc_url: igd_desc_url}

      {:error, :timeout} ->
        do_discover(%{state | search_attempts: state[:search_attempts] - 1})
    end
  end

  # waits reply from the an IGD device
  @spec await_reply(socket :: :inet.socket(), timer :: non_neg_integer()) ::
          {:ok, :inet.ip4_address(), String.t()} | {:error, :timeout | :service_info_url}
  def await_reply(socket, timer) do
    receive do
      {:udp, ^socket, igd_internal_ip, _reply_ing_port, reply_msg} ->
        # {:udp, #Port<0.8>, {192, 168, 1, 1}, 39286,"msg"}
        Logger.debug("Received: #{inspect(reply_msg)}")

        case Utils.find_igd_location(reply_msg) do
          {:ok, service_info_url} ->
            debug_log({"await_reply", {igd_internal_ip, location}})

            {:ok, igd_internal_ip, service_info_url}

          {:error, e} ->
            Logger.debug("find_igd_location: #{inspect(e)}")
            await_reply(socket, timer)
        end
    after
      timer ->
        Logger.debug("Timeout")
        {:error, :timeout}
    end
  end

  def fetch_service_url(state = %{root_url: root_url}) do
    state
    |> fetch_igd_desc()
    |> get_device_type()
    |> get_wan_device()

    #   {:ok, url} <- Utils.get_service_url(location),
    #   my_ip <- :inet.getaddr(ip, :inet) do
    # # https://www.erlang.org/doc/man/inet#getaddr-2
    # {:ok, %Nat.Protocol{service_url: url, ip: my_ip}}
    # else
    # {:error, reason} ->
    #  {:error, reason}

    # :error ->
    #  do_discover(socket, m_search, attempts - 1)
    # end
  end

  def fetch_igd_desc(state = %{root_url: root_url, errors: []}) do
    case Utils.http_request(root_url) do
      {:ok, response} ->
        %{state | fetch_igd_desc: response}

      {:error, reason} ->
        %{state | errors: [{:fetch_igd_desc, reason}]}
    end
  end

  def fetch_igd_desc(state), do: state

  def get_device_type(state = %{errors: [], fetch_igd_desc: response}) do
    {xml, _} = body |> String.to_charlist() |> :xmerl_scan.string([{:space, :normalize}])
    [devices | _] = '//device' |> String.to_charlist() |> :xmerl_xpath.string(xml)

    device_type =
      'deviceType/text()'
      |> :xmerl_xpath.string(devices)
      |> Utils.extract_txt()

    %{state | igd_device_type: device_type, device_list: devices}
  end

  def get_device_type(state), do: state

  def get_wan_device(state = %{errors: [], igd_device_type: device_type}) do
    # 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'
    # should be a igd decice that support upnp1
    case device_type == state[:device_type] do
    end

    %{state | igd_device_type: device_type, device_list: devices}
  end

  def get_wan_device(state), do: state

  def debug_log(ctx) do
    Utils.debug_log({"[UPNPV1]", ctx})
    ctx
  end

  def get_device_address(%Nat.Protocol{service_url: url}) do
    # https://www.erlang.org/doc/man/uri_string#parse-1
    # https://hexdocs.pm/elixir/1.14.1/URI.html#parse/1
    with %URI{host: host} <- URI.parse(url),
         {:ok, ip} <- :inet.getaddr(host, :inet) do
      {:ok, :inet.ntoa(ip)}
    else
      {:error, e} ->
        Logger.debug("[get_device_address][#{__MODULE__}] get_device_address#{inspect(e)}")

      e ->
        Logger.debug("[get_device_address][#{__MODULE__}] get_device_address#{inspect(e)}")
        :error
    end
  end

  def get_external_address(%Nat.Protocol{service_url: url}) do
    message = """
      <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      </u:GetExternalIPAddress>
    """

    case Utils.soap_request(url, "GetExternalIPAddress", message) do
      {:ok, body} ->
        {xml, _} = :xmerl_scan.string(body, [{:space, :normalize}])

        [infos | _] =
          :xmerl_xpath.string(
            "//s:Envelope/s:Body/*[local-name() = 'GetExternalIPAddressResponse']",
            xml
          )

        ip = Utils.extract_txt(:xmerl_xpath.string("NewExternalIPAddress/text()", infos))

        {:ok, ip}

      error ->
        error
    end
  end

  def get_internal_address(%Nat.Protocol{ip: ip}) do
    {:ok, ip}
  end

  @doc """
  Add a port mapping and release after Timeout.
  """
  def add_port_mapping(
        context,
        protocol,
        internal_port,
        external_port,
        lifetime \\ @default_mapping_lifetime
      ) do
    protocol = Utils.protocol(protocol)

    case external_port do
      0 -> random_port_mapping(context, protocol, internal_port, lifetime, nil, 3)
      _ -> do_add_port_mapping(context, protocol, internal_port, external_port, lifetime)
    end
  end

  defp random_port_mapping(_context, _protocol, _internal_port, _lifetime, error, 0),
    do: error

  defp random_port_mapping(context, protocol, internal_port, lifetime, _last_error, attempts) do
    external_port = Utils.random_port()

    case do_add_port_mapping(context, protocol, internal_port, external_port, lifetime) do
      {:ok, _, _, _, _} ->
        {:ok, external_port}

      error ->
        random_port_mapping(context, protocol, internal_port, lifetime, error, attempts - 1)
    end
  end

  defp do_add_port_mapping(
         %Nat.Protocol{ip: ip, service_url: url} = nat_ctx,
         protocol,
         internal_port,
         external_port,
         lifetime
       )
       when is_integer(lifetime) and lifetime >= 0 do
    description = "#{ip}_#{protocol}_#{Integer.to_string(internal_port)}"

    msg = """
      <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>#{external_port}</NewExternalPort>
      <NewProtocol>#{protocol}</NewProtocol>
      <NewInternalPort>#{internal_port}</NewInternalPort>
      <NewInternalClient>#{ip}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>#{description}</NewPortMappingDescription>
      <NewLeaseDuration>#{lifetime}</NewLeaseDuration>
      </u:AddPortMapping>
    """

    {:ok, iaddr} = :inet.parse_address(ip)
    start = Utils.timestamp()

    case Utils.soap_request(url, "AddPortMapping", msg, socket_opts: [ip: iaddr]) do
      {:ok, _} ->
        now = Utils.timestamp()

        mapping_lifetime =
          if lifetime > 0 do
            lifetime - (now - start)
          else
            :infinity
          end

        {:ok, now, internal_port, external_port, mapping_lifetime}

      error when lifetime > 0 ->
        case only_permanent_lease_supported(error) do
          true ->
            Logger.error("#{__MODULE__}UPNP: only permanent lease supported")
            do_add_port_mapping(nat_ctx, protocol, internal_port, external_port, 0)

          false ->
            error
        end

      error ->
        error
    end
  end

  defp only_permanent_lease_supported({:error, {:http_error, "500", body}}) do
    {xml, _} = :xmerl_scan.string(body, space: :normalize)
    [error_node | _] = :xmerl_xpath.string("//s:Envelope/s:Body/s:Fault/detail/UPnPError", xml)
    error_code = Utils.extract_txt(:xmerl_xpath.string("errorCode/text()", error_node))

    case error_code do
      "725" -> true
      _ -> false
    end
  end

  defp only_permanent_lease_supported(_), do: false

  def delete_port_mapping(
        %Nat.Protocol{ip: ip, service_url: url},
        protocol,
        _internal_port,
        external_port
      ) do
    protocol = Utils.protocol(protocol)

    msg = """
      <u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>#{external_port}</NewExternalPort>
      <NewProtocol>#{protocol}</NewProtocol>
      </u:DeletePortMapping>
    """

    {:ok, iaddr} = :inet.parse_address(ip)

    case Utils.soap_request(url, "DeletePortMapping", msg, socket_opts: [ip: iaddr]) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  def get_port_mapping(%Nat.Protocol{ip: ip, service_url: url}, protocol, external_port) do
    protocol = Utils.protocol(protocol)

    msg = """
      <u:GetSpecificPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>#{external_port}</NewExternalPort>
      <NewProtocol>#{protocol}</NewProtocol>
      </u:GetSpecificPortMappingEntry>
    """

    {:ok, iaddr} = :inet.parse_address(ip)

    case Utils.soap_request(url, "GetSpecificPortMappingEntry", msg, socket_opts: [ip: iaddr]) do
      {:ok, body} ->
        {xml, _} = :xmerl_scan.string(body, space: :normalize)

        [infos | _] =
          :xmerl_xpath.string("//s:Envelope/s:Body/u:GetSpecificPortMappingEntryResponse", xml)

        new_internal_port =
          Utils.extract_txt(:xmerl_xpath.string("NewInternalPort/text()", infos))

        new_internal_client =
          Utils.extract_txt(:xmerl_xpath.string("NewInternalClient/text()", infos))

        internal_port = String.to_integer(new_internal_port)
        {:ok, internal_port, new_internal_client}

      error ->
        error
    end
  end

  def status_info(%Nat.Protocol{service_url: url}) do
    msg =
      ~s(<u:GetStatusInfo xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:GetStatusInfo>)

    case Utils.soap_request(url, "GetStatusInfo", msg) do
      {:ok, body} ->
        {xml, _} = :xmerl_scan.string(body, space: :normalize)
        [infos | _] = :xmerl_xpath.string("//s:Envelope/s:Body/u:GetStatusInfoResponse", xml)

        status = Utils.extract_txt(:xmerl_xpath.string("NewConnectionStatus/text()", infos))

        last_connection_error =
          Utils.extract_txt(:xmerl_xpath.string("NewLastConnectionError/text()", infos))

        uptime = Utils.extract_txt(:xmerl_xpath.string("NewUptime/text()", infos))
        {status, last_connection_error, uptime}

      e ->
        Logger.debug("[status_info][#{__MODULE__}] #{inspect(e)}")
        e
    end
  end
end
