defmodule Nat.Utils do
  @moduledoc false

  use Nat.Constants
  import Bitwise, only: [bsl: 2]
  use Nat.Errors

  @doc """
  Returns path in the mutable storage directory
  """
  @spec mut_dir(String.t() | nonempty_list(Path.t())) :: Path.t()
  def mut_dir(path) when is_binary(path) do
    [
      get_root_mut_dir(),
      Application.get_env(:nat, :mut_dir),
      path
    ]
    |> Path.join()
    |> Path.expand()
  end

  def mut_dir, do: mut_dir("")

  def get_root_mut_dir() do
    case Application.get_env(:nat, :root_mut_dir) do
      nil -> Application.app_dir(:nat)
      dir -> dir
    end
  end

  @doc """
  Configure supervisor children to be disabled if their configuration has a `enabled` option to false
  """
  @spec configurable_children(
          list(
            process ::
              atom()
              | {process :: atom(), args :: list()}
              | {process :: atom(), args :: list(), opts :: list()}
          )
        ) ::
          list(Supervisor.child_spec())
  def configurable_children(children) when is_list(children) do
    children
    |> Enum.filter(fn
      {process, _, _} -> should_start?(process)
      {process, _} -> should_start?(process)
      process -> should_start?(process)
    end)
    |> Enum.map(fn
      {process, args, opts} -> Supervisor.child_spec({process, args}, opts)
      {process, args} -> Supervisor.child_spec({process, args}, [])
      process -> Supervisor.child_spec({process, []}, [])
    end)
  end

  defp should_start?(nil), do: false

  defp should_start?(process) do
    case Application.get_env(Nat, process) do
      nil ->
        true

      conf when is_list(conf) ->
        Keyword.get(conf, :enabled, true)

      mod when is_atom(mod) ->
        Nat
        |> Application.get_env(mod, [])
        |> Keyword.get(:enabled, true)
    end
  end

  def soap_request(url, function, msg, options \\ []) do
    msg = """
      <?xml version="1.0"?>
      <s:Envelope
      xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
      s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <s:Body>#{msg}</s:Body></s:Envelope>
    """

    action = """
    urn:schemas-upnp-org:service:WANIPConnection:1##{function}
    """

    headers = [
      {"Content-Length", Integer.to_string(String.length(msg))},
      {"User-Agent", "Darwin/10.0.0, UPnP/1.0, MiniUPnPc/1.3"},
      {"SOAPAction", action},
      {"Connection", "close"},
      {"Cache-Control", "no-cache"},
      {"Pragma", "no-cache"}
    ]

    req = {url, headers, "text/xml; charset=\"utf-8\"", msg}

    case :httpc.request(:post, req, [], options) do
      {:ok, {{_, 200, _}, _, body}} ->
        {:ok, body}

      {:ok, {{_, status, _}, _, body}} ->
        Logger.error("UPNP SOAP error: ~p~n", status: status)

        {:error, {:http_error, Integer.to_string(status), body}}

      error ->
        error
    end
  end

  @spec random_port() :: pos_integer()
  def random_port() do
    :rand.uniform(62000)
  end

  def timestamp() do
    {unix_milli, sec, _} = :erlang.timestamp()
    unix_milli * 1_000_000 + sec
  end

  # {:udp, #Port<0.7>, {192, 168, 1, 1}, 49868,
  #  "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Fri, 02 Jan 1970 10:27:36 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.1:52869/gatedesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: e7978c52-1ef2-11b2-812a-8dbb4dbc0a0a\r\nSERVER: Linux, UPnP/1.0, Portable SDK for UPnP devices/1.6.22\r\nX-User-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:20809696-105a-3721-e8b8-28777726497e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"}

  @doc """

        iex> resp= "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Fri, 02 Jan 1970 10:27:36 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.1:52869/gatedesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: e7978c52-1ef2-11b2-812a-8dbb4dbc0a0a\r\nSERVER: Linux, UPnP/1.0, Portable SDK for UPnP devices/1.6.22\r\nX-User-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:20809696-105a-3721-e8b8-28777726497e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        iex> Utils.parse(resp)
        %{
          :"Cache-Control" => "max-age=1800",
          :Date => "Fri, 02 Jan 1970 10:27:36 GMT",
          :Location => "http://192.168.1.1:52869/gatedesc.xml",
          :Server => "Linux, UPnP/1.0, Portable SDK for UPnP devices/1.6.22",
          "01-Nls" => "e7978c52-1ef2-11b2-812a-8dbb4dbc0a0a",
          "Ext" => "",
          "Opt" => "\"http://schemas.upnp.org/upnp/1/0/\"; ns=01",
          "St" => "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
          "Usn" => "uuid:20809696-105a-3721-e8b8-28777726497e::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
          "X-User-Agent" => "redsonic"
         }
  """
  def get_headers(raw, headers \\ %{}) do
    # https://www.erlang.org/doc/man/erlang#decode_packet-3
    case :erlang.decode_packet(:httph_bin, raw, []) do
      {:ok, {:http_error, _}, rest} -> get_headers(rest, headers)
      {:ok, {:http_header, _, h, _, v}, rest} -> get_headers(rest, Map.put(headers, h, v))
      _ -> headers
    end
  end

  # @spec inet_get_addr(String.t()) :: {:ok, String.t()} | {:error,
  # def inet_get_addr(host) do
  #   case :inet.getaddr(host, :inet) do
  #     {:ok, ip} -> {:ok, :inet.ntoa(ip)}
  #     {:error, reason} -> {}:error,reason}
  #   end
  # end

  @doc """
  Returns the number of milliseconds to wait before retrying a request, based on nb of attempts and initial delay
  """
  @spec exponential_backoff(attempt :: non_neg_integer(), initial_ms :: non_neg_integer()) ::
          non_neg_integer()
  def exponential_backoff(attempt, initial_ms \\ @nat_initial_ms), do: bsl(initial_ms, attempt)

  # def get_internal_address(gateway) do
  #   [{_, {MyIp, _}}|_] = route(parse_address(Gateway)),
  #   inet_parse:ntoa(MyIp).
  # end

  # https://www.erlang.org/doc/man/re#split-3
  def split(string, pattern), do: :re.split(string, pattern, return: :list)

  def protocol(protocol) when is_atom(protocol) do
    case protocol in [:tcp, :udp] do
      true -> :ok
      false -> {:error, :bad_protocol}
    end

    protocol |> Atom.to_string() |> String.upcase()
  end

  def protocol(protocol) do
    case protocol in ["tcp", "udp"] do
      true -> :ok
      false -> {:error, :bad_protocol}
    end

    protocol |> String.upcase()
  end

  defp find_device([], _device_type), do: false

  defp find_device([device | rest], device_type) do
    case device_type(device) do
      device_type ->
        {:ok, device}

      _ ->
        find_device(rest, device_type)
    end
  end

  def device_type(device) do
    extract_txt(:xmerl_xpath.string("deviceType/text()", device))
  end

  @doc """
    Search for device:WANDevice:1/2
  """
  def get_wan_device(device, root_url, version) do
    case get_device(device, wan_device_tag(version)) do
      {:ok, device1} ->
        get_connection_device(device1, root_url, version)

      _ ->
        {:error, :no_wan_device}
    end
  end

  def wan_device_tag("1"), do: "urn:schemas-upnp-org:device:WANDevice:1"
  def wan_device_tag("2"), do: "urn:schemas-upnp-org:device:WANDevice:2"

  @doc """
    Search for device:WANConnectionDevice:1/2
  """
  def get_connection_device(device, root_url, version) do
    case get_device(device, wan_conn_device_tag(version)) do
      {:ok, wan_conn_device} ->
        get_connection_url(wan_conn_device, root_url, version)

      _ ->
        {:error, :no_wanconnection_device}
    end
  end

  def wan_conn_device_tag("1"), do: "urn:schemas-upnp-org:device:WANConnectionDevice:1"
  def wan_conn_device_tag("2"), do: "urn:schemas-upnp-org:device:WANConnectionDevice:2"

  def get_device(device, device_type) do
    device_list = :xmerl_xpath.string("deviceList/device", device)
    find_device(device_list, device_type)
  end

  def get_connection_url(device, root_url, version) do
    with {:ok, service} <- get_service(device, service_type_tag(version)),
         url <- extract_txt(:xmerl_xpath.string("controlURL/text()", service)),
         {:fetch_service, [scheme, rest]} <- {:fetch_service, String.split(root_url, "://")},
         {:fetch_service, [net_loc | _]} <- {:fetch_service, String.split(rest, "/")} do
      ctl_url = "#{scheme}://#{net_loc}#{url}"
      {:ok, ctl_url}
    else
      {:fetch_service, e} ->
        Logger.debug("[get_connection_url][#{__MODULE__}] #{inspect(e)}")
        {:error, :invalid_control_url}

      e ->
        Logger.debug("[get_connection_url][#{__MODULE__}] #{inspect(e)}")
        {:error, :no_wanipconnection}
    end
  end

  def service_type_tag("1"), do: "urn:schemas-upnp-org:service:WANIPConnection:1"
  def service_type_tag("2"), do: "urn:schemas-upnp-org:service:WANIPConnection:2"

  def get_service(device, service_type) do
    service_list = :xmerl_xpath.string("serviceList/service", device)
    find_service(service_list, service_type)
  end

  defp find_service([], _service_type), do: {:error, :not_found}

  defp find_service([st | rest], service_type) do
    case extract_txt(:xmerl_xpath.string("serviceType/text()", st)) do
      [] ->
        find_service(rest, service_type)

      _service_type ->
        {:ok, st}
    end
  end

  @doc """
  Takes a list of XML elements (xml), iterates through the elements, and extracts the text value
  from the first XML text node it encounters. This extracted text value is then assigned to the
  variable T, which is returned as the result of the function.

  or just search for value in the xml response from router
  """
  def extract_txt(xml) do
    extracted_text_values =
      xml
      # https://www.erlang.org/doc/man/erlang#is_record-2
      |> Enum.filter(fn x -> :erlang.is_record(x, :xmlText) end)
      |> Enum.map(& &1.xmlText.value)

    [first | _] = extracted_text_values
    first
  end

  def get_device_address(%Nat.Protocol{service_url: url}) do
    # https://www.erlang.org/doc/man/uri_string#parse-1
    # https://hexdocs.pm/elixir/1.14.1/URI.html#parse/1
    with %URI{host: host} when not is_nil(host) <- URI.parse(url),
         {:ok, ip} <- :inet.getaddr(host, :inet) do
      {:ok, :inet.ntoa(ip)}
    else
      # {:error, e} when e in posix() ->
      #   Logger.debug("[get_device_address][#{__MODULE__}] get_device_address#{inspect(e)}")

      e ->
        Logger.debug("[get_device_address][#{__MODULE__}] get_device_address#{inspect(e)}")
        :error
    end
  end

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
  def get_external_address(%Nat.Protocol{service_url: url, version: ver}) do
    message = """
      <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      </u:GetExternalIPAddress>
    """

    # case ver do
    #   "1" ->

    #   "2" ->
    #     nil
    # end

    case __MODULE__.soap_request(url, "GetExternalIPAddress", message) do
      {:ok, body} ->
        {xml, _} = :xmerl_scan.string(body, [{:space, :normalize}])

        [infos | _] =
          :xmerl_xpath.string(
            "//s:Envelope/s:Body/*[local-name() = 'GetExternalIPAddressResponse']",
            xml
          )

        ip = extract_txt(:xmerl_xpath.string("NewExternalIPAddress/text()", infos))

        {:ok, ip}

      error ->
        error
    end
  end

  def debug_log(contex) do
    Logger.debug("[#{inspect(contex)}]")
  end
end
