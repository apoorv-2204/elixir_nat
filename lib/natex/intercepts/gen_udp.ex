defmodule NatEx.Intercepts.GenUdp do
  @moduledoc false
  alias NatEx.NATCache

  def send(socket, ip, port, msg) do
    key = {:gen_udp, :send, [ip, port, msg]}

    IO.puts("[#{inspect(__MODULE__)}] [REQ] #{inspect(key)}")

    res =
      case NATCache.get(key) do
        %{socket2: socket2, ip2: ip2, port2: port2, msg2: msg2} = cached ->
          IO.puts("[#{inspect(__MODULE__)}] [RESP] [CACHE] #{inspect(cached)}")
          send(self(), {:udp, socket2, ip2, port2, msg2})
          :ok

        nil ->
          send(socket, ip, port, msg)
      end

    res
  end

  def handle_trace(
        {:trace, _pid, "receive", %{udp: socket, ip: ip, port: port, msg: msg} = data},
        key
      ) do
    IO.puts("[#{inspect(__MODULE__)}] [RESP] [ORI] #{inspect(data)}")
    NATCache.put(key, %{socket: socket, ip: ip, port: port, msg: msg})
  end

  def handle_trace(_trace, _key), do: :ok
end
