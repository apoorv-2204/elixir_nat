# defmodule Nat.PMP do
#   @moduledoc """
#   # unsupported_version: The NAT device does not support the version of NAT-PMP being used.
#   # not_authorized: The NAT device did not authorize the request.
#   # network_failure: A network failure occurred.
#   # out_of_resource: The NAT device has run out of resources.
#   # unsupported_opcode: The NAT device does not support the requested operation.
#   # bad_response: The NAT device returned a bad response.

#     # It computes a list of potential IP addresses to search for NAT devices, either by using the list of system gateways
#     #    or by using a list of potential private network addresses (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16).
#     # It creates a reference and a list of parent processes. It spawns a new process for each potential NAT device IP address
#     #  and calls discover_with_addr/3 to try to find a NAT device at that address.It waits for a message of the form
#     #  {:nat, ref, pid, addr}, where ref is the reference it created earlier and pid and addr are the process ID and
#     #   IP address of a NAT device, respectively.When it receives such a message, it closes the process with the given
#     #    process ID, removes it from the list of parent processes, and returns the IP address of the NAT device if the
#     #    list of parent processes is empty. If the list of parent processes is not empty, it calls itself recursively to
#     #     wait for more NAT device discovery messages.

#     # Gateway: the IP address or hostname of the NAT gateway.
#     # Protocol:  :tcp or :udp
#     # InternalPort: the internal port on the network to which incoming traffic should be forwarded.
#     # ExternalPortRequest: the external port on the NAT gateway to which incoming traffic should be directed.
#     # Lifetime  the lifetime of the port mapping, in seconds.
#   """
#   import Bitwise

#   use Nat.Constants
#   use Nat.Errors
#   alias Nat.Utils

#   @spec get_device_address(gateway :: :inet.ip_address() | :inet.hostname()) ::
#           {:ok, ip :: :inet.ip_address() | :inet.hostname()} | {:error, pmp_error()}
#   def get_device_address(gateway) do
#     {:ok, gateway}
#   end

#   @spec get_external_address(gateway :: :inet.ip_address() | :inet.hostname()) ::
#           {:ok, ip :: :inet.ip_address() | :inet.hostname()} | {:error, pmp_error()}
#   def get_external_address(gateway) do
#     msg = <<0, 0>>
#     nat_rpc(gateway, msg, 0)
#   end

#   def nat_rpc(gateway0, msg, op_code) do
#     # Application.start(:inets)
#     gateway = :inet_ext.parse_address(gateway0)

#     {:ok, socket} = :gen_udp.open(0, [:inet, :binary, active: :once])

#     try do
#       do_nat_rpc(socket, gateway, msg, op_code, 0)
#     after
#       :gen_udp.close(socket)
#     end
#   end

#   defp do_nat_rpc(_socket, _gateway, _msg, _op_code, @nat_tries), do: :timeout

#   defp do_nat_rpc(socket, gateway, msg, op_code, nb_attempts) do
#     :inet.setopts(socket, active: :once)
#     timeout = Utils.exponential_backoff(nb_attempts)

#     case :gen_udp.send(socket, gateway, @pmp_port, msg) do
#       :ok ->
#         receive do
#           {:udp, _sock, _gateway, _port, packet} ->
#             parse_response(packet, op_code)

#           {:udp, _, _, _, _} ->
#             do_nat_rpc(socket, gateway, msg, op_code, nb_attempts + 1)
#         after
#           timeout -> do_nat_rpc(socket, gateway, msg, op_code, nb_attempts + 1)
#         end

#       _error ->
#         do_nat_rpc(socket, gateway, msg, op_code, nb_attempts + 1)
#     end
#   end

#   def parse_response(<<_version, response_code, status::16, _since::32, a, b, c, d>>, op_code) do
#     expected_code = op_code + 128

#     with true <- expected_code == response_code,
#          :ok <- parse_status(status) do
#       {:ok, :inet.ntoa({a, b, c, d})}
#     else
#       e ->
#         Logger.debug("parse_response: #{inspect(e)}")
#         e
#     end
#   end

#   def parse_response(
#         <<_v, response_code, status::16, since::32, internal_port::16, external_port::16,
#           lifetime::32>>,
#         op_code
#       ) do
#     expected_code = op_code + 128

#     with true <- expected_code == response_code,
#          :ok <- parse_status(status) do
#       {:ok, since, internal_port, external_port, lifetime}
#     else
#       e ->
#         Logger.debug("parse_response: #{inspect(e)}")
#         e
#     end
#   end

#   def parse_response(_, _), do: {:error, :bad_response}

#   def parse_status(0), do: :ok
#   def parse_status(1), do: {:error, :unsupported_version}
#   def parse_status(2), do: {:error, :not_authorized}
#   def parse_status(3), do: {:error, :network_failure}
#   def parse_status(4), do: {:error, :out_of_resource}
#   def parse_status(5), do: {:error, :unsupported_opcode}

#   @spec get_internal_address(gateway :: :inet.ip_address() | :inet.hostname()) ::
#           {:ok, ip :: :inet.ip_address() | :inet.hostname()} | {:error, pmp_error()}
#   def get_internal_address(gateway) do
#     {:ok, :inet_ext.get_internal_address(gateway)}
#   end

#   defp discover_with_addr(parent, ref, ip_addr) do
#     case get_external_address(ip_addr) do
#       {:ok, _ip} ->
#         send(parent, {:nat, ref, self(), ip_addr})

#       _ ->
#         :ok
#     end
#   rescue
#     _ ->
#       send(parent, {:error, ref, self()})
#   end

#   defp potential_gateways do
#     network_10 = :inet_cidr.parse("10.0.0.0/8")
#     network_10_172_16 = :inet_cidr.parse("172.16.0.0/12")
#     network_10_192_168 = :inet_cidr.parse("192.168.0.0/16")
#     networks = [network_10, network_10_172_16, network_10_192_168]

#     Enum.reduce(:inet_ext.routes(), [], fn
#       {_, {addr, mask}}, acc ->
#         with {true, :priv} <- {:inet_ext.is_private_address(networks), :priv},
#              {true, :v4} <- {:inet_cidr.is_ipv4(addr), :v4} do
#           ip0 = mask(addr, mask)

#           ip = put_elem(ip0, 4, bxor(elem(ip0, 4), 1))
#           [ip | acc]
#         else
#           {false, :priv} -> acc
#           {false, :v4} -> acc
#         end
#     end)
#   end

#   def mask({a, b, c, d}, {e, f, g, h}), do: {band(a, e), band(b, f), band(c, g), band(d, h)}

#   defp system_gateways() do
#     Enum.map(:inet_ext.gateways(), fn {_, ip} -> ip end)
#   end

#   def discover() do
#     ips =
#       case system_gateways() do
#         [] -> potential_gateways()
#         gateways -> gateways
#       end

#     ref = make_ref()
#     me = self()

#     worker_pids =
#       ips
#       |> Enum.sort()
#       |> Enum.uniq()
#       |> Enum.reduce(%{}, fn ip, acc ->
#         pid = spawn_link(fn -> discover_with_addr(me, ref, ip) end)
#         Map.put(acc, pid, ip)
#       end)

#     {worker_pids, res} =
#       Enum.reduce(1..length(worker_pids), {worker_pids, []}, fn _x, {worker_pids, res} ->
#         receive do
#           {:nat, ^ref, worker_pid, gateway_ip} ->
#             {Map.pop(worker_pids, worker_pid), [res | gateway_ip]}

#           {:error, ^ref, worker_pid} ->
#             {Map.pop(worker_pids, worker_pid), res}
#         end
#       end)

#     List.first(res)
#   end

#   @spec add_port_mapping(
#           gateway :: :inet.ip_address() | :inet.hostname(),
#           protocol :: :tcp | :udp,
#           internal_port :: non_neg_integer(),
#           external_port_req :: non_neg_integer(),
#           mapping_lifetime :: non_neg_integer()
#         ) ::
#           {:ok, since :: non_neg_integer(), internal_port :: non_neg_integer(),
#            external_port :: non_neg_integer(), lifetime :: non_neg_integer()}
#           | {:error, pmp_error()}
#           | :timeout
#   def add_port_mapping(
#         gateway,
#         protocol,
#         internal_port,
#         external_port_req,
#         mapping_lifetime \\ @lifetime
#       ) do
#     opcode = proto_opcode(protocol)

#     # Msg = << 0,
#     # OpCode,
#     # 0:16,
#     # InternalPort:16/unsigned-integer,
#     # ExternalPort:16/unsigned-integer,
#     # Lifetime:32/unsigned-integer >>,

#     msg = <<0, opcode, 0::16, internal_port::16, external_port_req::16, mapping_lifetime::32>>

#     nat_rpc(gateway, msg, opcode)
#   end

#   def proto_opcode(:udp), do: 1
#   def proto_opcode(:tcp), do: 2
#   def proto_opcode(_), do: {:error, :proto_errpr}

#   def delete_port_mapping(gateway, protocol, internal_port, _external_port) do
#     case add_port_mapping(gateway, protocol, internal_port, 0, 0) do
#       {:ok, _, ^internal_port, 0, 0} -> :ok
#       {:ok, _, _, _, _} -> {:error, :bad_response}
#       error -> raise error
#     end
#   end
# end
