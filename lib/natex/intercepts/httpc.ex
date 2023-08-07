defmodule NatEx.Intercepts.Httpc do
  alias NatEx.NATCache

  require Logger

  def request(url) do
    key = {"httpc", "request", url}
    Logger.info("[#{inspect(__MODULE__)}] [REQ] #{inspect(key)}")

    case NATCache.get(key) do
      nil ->
        res = request(url)
        Logger.info("[#{inspect(__MODULE__)}] [RESP] [ORI] #{inspect(res)}")
        NATCache.put(key, res)
        res

      res ->
        Logger.info("[#{inspect(__MODULE__)}] [RESP] [CACHE] #{inspect(res)}")
        res
    end
  end

  def request(method, request, http_options, options) do
    key = {"httpc", request, [method, request, http_options, options]}
    Logger.info("[#{inspect(__MODULE__)}] [REQ] #{inspect(key)}")

    case NATCache.get(key) do
      nil ->
        res = request(method, request, http_options, options)
        Logger.info("[#{inspect(__MODULE__)}] [RESP] [ORI] #{inspect(res)}")
        NATCache.put(key, res)
        res

      res ->
        Logger.info("[#{inspect(__MODULE__)}] [RESP] [CACHE] #{inspect(res)}")
        res
    end
  end
end
