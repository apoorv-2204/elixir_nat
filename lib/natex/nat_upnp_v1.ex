defmodule NatEx.NatupnpV1 do
  def discover() do
    {:ok, :context}
  end

  def add_port_mapping(context, protocol, internal_port, external_port, mapping_lifetime) do
    {:ok, :since, :internal_port, :external_port, :mapping_lifetime}
  end

  def delete_port_mapping(context, protocol, internal_port, external_port) do
    :ok
  end

  def get_external_address(context) do
    {:ok, :ext_address}
  end

  def get_internal_address(context) do
    {:ok, :int_address}
  end
end
