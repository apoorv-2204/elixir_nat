defmodule Natex.Utils do
  @moduledoc false

  use Natex.Constants
  import Bitwise, only: [bsl: 2]

  @doc """
  Returns path in the mutable storage directory
  """
  @spec mut_dir(String.t() | nonempty_list(Path.t())) :: Path.t()
  def mut_dir(path) when is_binary(path) do
    [
      get_root_mut_dir(),
      Application.get_env(:natex, :mut_dir),
      path
    ]
    |> Path.join()
    |> Path.expand()
  end

  def mut_dir, do: mut_dir("")

  def get_root_mut_dir() do
    case Application.get_env(:natex, :root_mut_dir) do
      nil -> Application.app_dir(:natex)
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
    case Application.get_env(Natex, process) do
      nil ->
        true

      conf when is_list(conf) ->
        Keyword.get(conf, :enabled, true)

      mod when is_atom(mod) ->
        Natex
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

  def random_port(), do: :rand.uniform(62000)

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

  def protocol(protocol) do
    case protocol in [:tcp, :udp] do
      true -> :ok
      false -> {:error, :bad_protocol}
    end

    protocol |> String.upcase()
  end

  @doc """
  Takes a list of XML elements (xml), iterates through the elements, and extracts the text value
  from the first XML text node it encounters. This extracted text value is then assigned to the
  variable T, which is returned as the result of the function.
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

  def get_device(device, device_type) do
    device_list = :xmerl_xpath.string("deviceList/device", device)
    find_device(device_list, device_type)
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

  # "urn:schemas-upnp-org:service:WANIPConnection:1"
  # "urn:schemas-upnp-org:service:WANIPConnection:2"

  def get_connection_url(device, root_url, version) do
    with {:ok, service} <- get_service(device, version),
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

  # "urn:schemas-upnp-org:device:WANConnectionDevice:1"
  # "urn:schemas-upnp-org:device:WANConnectionDevice:2"

  def get_connection_device(device, root_url, version) do
    case get_device(device, version) do
      {:ok, wan_conn_device} ->
        get_connection_url(wan_conn_device, root_url, version)

      _ ->
        {:error, :no_wanconnection_device}
    end
  end

  def get_wan_device(device, root_url, version) do
    case get_device(device, version) do
      {:ok, device1} ->
        get_connection_device(device1, root_url, version)

      _ ->
        {:error, :no_wan_device}
    end
  end
end
