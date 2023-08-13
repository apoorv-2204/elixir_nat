defmodule Natex.NatUPnP do
  @derive {Inspect, only: [:service_url, :ip]}
  defstruct service_url: "", ip: "", version: "", errors: []

  @type t :: %__MODULE__{
          service_url: String.t(),
          ip: String.t()
        }
end
