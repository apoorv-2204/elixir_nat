defmodule Nat.Protocol do
  # @derive {Inspect, only: [:service_url, :ip]}
  defstruct service_url: "", ip: "", version: "", errors: []

  # @type version :: pos_integer() | atom()

  @type protocol_version :: :upnp_v1 | :upnp_v2 | :pmp

  @type t :: %__MODULE__{
          service_url: String.t(),
          ip: String.t() | tuple(),
          version: protocol_version()
        }
end
