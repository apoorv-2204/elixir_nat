defmodule NatEx.Helpers do
  @moduledoc false
  # natlib
  require Logger

  def soap_request(url, function, msg) do
    soap_request(url, function, msg, [])
  end

  def soap_request(url, function, msg, options) do
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

  def random_port() do
    :rand.uniform(65535 - 10000) + 10000
  end

  def timestamp() do
    {unix_milli, sec, _} = :erlang.timestamp()
    unix_milli * 1_000_000 + sec
  end

  def get_headers(raw) do
    get_headers(raw, %{})
  end

  def get_headers(raw, headers) do
    case :erlang.decode_packet(:httph_bin, raw, []) do
      {:ok, {:http_error, _}, rest} -> get_headers(rest, headers)
      {:ok, {:http_header, _, h, _, v}, rest} -> get_headers(rest, Map.put(headers, h, v))
      _ -> headers
    end
  end
end
