defmodule NatEx.Intercepts.InetExt do
  @moduledoc """
  This module defines a function that retrieves the internal address of a given IP address.
  The request is intercepted and passed through a cache before being sent.
  If the request is not present in the cache, it is made using the `get_internal_address_orig/1` function from the `inet_ext_orig` module.
  """
  alias NatEx.NATCache

  def get_internal_address(ip) do
    key = {:inet_ext, :get_internal_address, [ip]}
    IO.puts("[#{__MODULE__}] [REQ] #{key}")

    case NATCache.get(key) do
      nil ->
        data = get_internal_address(ip)
        IO.puts("#{__MODULE__} [RESP] [ORI] #{data}")
        NATCache.put(key, data)
        data

      internal_address ->
        IO.puts("[#{__MODULE__}] [RESP] [CACHE] #{internal_address}")
        internal_address
    end
  end
end
