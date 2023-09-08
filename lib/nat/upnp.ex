defmodule Nat.Protocol do
  @derive {Inspect, only: [:service_url, :ip]}
  defstruct service_url: "", ip: "", version: "", errors: []

  # @type version :: pos_integer() | atom()

  # @type Version :: 1 | 2 | :pmp

  @type t :: %__MODULE__{
          service_url: String.t(),
          ip: String.t() | tuple(),
          version: Version.t()
        }
end
