defmodule NatEx.NATCache do
  use GenServer

  alias NatEx.Utils

  require Logger

  @table :intercept_cache
  @dir Utils.mut_dir()

  @file_name Application.compile_env(:natex, :cache_file, "nat_cache")

  require Logger

  # api
  def get(key) do
    GenServer.call(__MODULE__, {:get, key})
  end

  def put(key, value) do
    GenServer.cast(__MODULE__, {:put, key, value})
  end

  def print() do
    GenServer.cast(__MODULE__, :print)
  end

  def stop() do
    GenServer.stop(__MODULE__, :normal)
  end

  def start(args) do
    GenServer.start(__MODULE__, args, name: __MODULE__)
  end

  def start_link(args) do
    GenServer.start_link(__MODULE__, args, name: __MODULE__)
  end

  # Callbacks

  def init(args) do
    get = Keyword.get(args, :get, true)
    file = (@dir <> Keyword.get(args, :file, @file_name)) |> to_charlist()
    {:ok, dets} = :dets.open_file(@table, file: file)
    {:ok, %{dets: dets, get: get}}
  end

  def handle_call({:get, _}, _from, %{get: false} = state) do
    {:reply, nil, state}
  end

  def handle_call({:get, key}, _from, %{dets: dets} = state) do
    reply =
      case :dets.lookup(dets, key) do
        {:error, _} -> nil
        [] -> nil
        [{_, v} | _] -> v
      end

    {:reply, reply, state}
  end

  def handle_call(_, _from, state) do
    {:reply, :ok, state}
  end

  def handle_cast({:put, key, value}, %{dets: dets} = state) do
    :dets.insert(dets, {key, value})
    {:noreply, state}
  end

  def handle_cast(:print, %{dets: dets} = state) do
    :dets.foldl(fn {k, v}, _ -> Logger.info("#{k}: #{v}") end, :ok, dets)
    {:noreply, state}
  end

  def handle_cast(_, state) do
    {:noreply, state}
  end

  def handle_info(_, state) do
    {:noreply, state}
  end

  def terminate(_reason, %{dets: dets}) do
    :dets.close(dets)
  end

  def check_cache(:gen_udp, module, socket, ip, port, msg) do
    key = {:gen_udp, :send, [ip, port, msg]}

    Logger.info("[#{inspect(module)}] [REQ] #{inspect(key)}")

    case NATCache.get(key) do
      nil ->
        nil

      cached ->
        Logger.info("[#{inspect(module)}] [RESP] [CACHE] #{inspect(cached)}")
        cached
    end
  end

  def update_cache(:gen_udp, module, socket, ip, port, msg) do
    key = {:gen_udp, :send, [ip, port, msg]}

    Logger.info("[#{inspect(module)}] [RESP] [ORI] #{inspect(data)}")
    Logger.info("[#{inspect(module)}] [RESP] [ORI] #{inspect(data)}")
    NATCache.put(key, %{socket: socket, ip: ip, port: port, msg: msg})
  end

  def handle_trace(
        {:trace, _pid, "receive", %{udp: socket, ip: ip, port: port, msg: msg} = data},
        key
      ) do
    Logger.info("[#{inspect(__MODULE__)}] [RESP] [ORI] #{inspect(data)}")
    NATCache.put(key, %{socket: socket, ip: ip, port: port, msg: msg})
  end

  def handle_trace(_trace, _key), do: :ok
end
