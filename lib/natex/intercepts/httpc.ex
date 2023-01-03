defmodule NatEx.Intercepts.Httpc do
  alias NatEx.NATCache

  def request(url) do
    key = {"httpc", "request", url}
    IO.puts("[#{inspect(__MODULE__)}] [REQ] #{inspect(key)}")

    case NATCache.get(key) do
      nil ->
        res = request(url)
        IO.puts("[#{inspect(__MODULE__)}] [RESP] [ORI] #{inspect(res)}")
        NATCache.put(key, res)
        res

      res ->
        IO.puts("[#{inspect(__MODULE__)}] [RESP] [CACHE] #{inspect(res)}")
        res
    end
  end

  def request(method, request, http_options, options) do
    key = {"httpc", request, [method, request, http_options, options]}
    IO.puts("[#{inspect(__MODULE__)}] [REQ] #{inspect(key)}")

    case NATCache.get(key) do
      nil ->
        res = request(method, request, http_options, options)
        IO.puts("[#{inspect(__MODULE__)}] [RESP] [ORI] #{inspect(res)}")
        NATCache.put(key, res)
        res

      res ->
        IO.puts("[#{inspect(__MODULE__)}] [RESP] [CACHE] #{inspect(res)}")
        res
    end
  end
end
