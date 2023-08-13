defmodule Natex.NATCacheTest do
  use ExUnit.Case

  alias Natex.NATCache

  test "cache operations" do
    NATCache.start_link(get: true)

    NATCache.put("key1", "value1")
    NATCache.put("key2", "value2")

    :sys.get_state(NATCache)

    assert NATCache.get("key1") == "value1"
    assert NATCache.get("key2") == "value2"
    assert NATCache.get("key3") == nil

    NATCache.stop()
  end

  test "disallow get requests" do
    NATCache.start_link(get: false)

    NATCache.put("key1", "value1")
    NATCache.put("key2", "value2")

    assert NATCache.get("key1") == nil
    assert NATCache.get("key2") == nil

    NATCache.stop()
  end

  test "persistence" do
    NATCache.start_link(get: true, file: "nat_scan_test")

    NATCache.put("key1", "value1")
    NATCache.put("key2", "value2")

    NATCache.stop()

    NATCache.start_link(get: true, file: "nat_scan_test")

    assert NATCache.get("key1") == "value1"
    assert NATCache.get("key2") == "value2"
    assert NATCache.get("key3") == nil

    NATCache.stop()
  end

  test "custom file name" do
    NATCache.start_link(get: true, file: "custom_file_name")

    NATCache.put("key1", "value1")
    NATCache.put("key2", "value2")

    NATCache.stop()

    NATCache.start_link(get: true, file: "custom_file_name")

    assert NATCache.get("key1") == "value1"
    assert NATCache.get("key2") == "value2"
    assert NATCache.get("key3") == nil

    NATCache.stop()
  end
end
