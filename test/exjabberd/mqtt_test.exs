defmodule Exjabberd.MqttTest do
  @moduledoc """
  Unit tests for the MQTT v3.1.1 codec (Fase 6) and the broker's
  subscription / retained / QoS 2 / session logic. No sockets here —
  the live server behaviour is covered by `test_mqtt_phase6.py`.
  """

  use ExUnit.Case, async: false

  alias Exjabberd.Mqtt.{Broker, Codec}

  # --- codec ----------------------------------------------------------

  test "CONNECT encodes and decodes (clean session, keep alive, will, auth)" do
    packet = %{
      type: :connect,
      client_id: "test-client",
      clean_session: true,
      keep_alive: 60,
      username: "alice",
      password: "secret",
      will_flag: true,
      will_topic: "status/alice",
      will_message: "offline",
      will_qos: 1,
      will_retain: false
    }

    raw = Codec.encode(packet)
    assert {:ok, ^packet, <<>>} = Codec.decode(raw)
  end

  test "CONNECT without auth or will round-trips" do
    packet = %{
      type: :connect,
      client_id: "anon-1",
      clean_session: false,
      keep_alive: 0,
      username: nil,
      password: nil,
      will_flag: false,
      will_topic: nil,
      will_message: nil,
      will_qos: 0,
      will_retain: false
    }

    raw = Codec.encode(packet)
    assert {:ok, ^packet, <<>>} = Codec.decode(raw)
  end

  test "PUBLISH QoS 0/1/2 round-trips, and split buffers report incomplete" do
    for qos <- [0, 1, 2] do
      packet = %{
        type: :publish,
        dup: false,
        qos: qos,
        retain: qos == 2,
        topic: "sensors/temp",
        packet_id: if(qos == 0, do: nil, else: 42),
        payload: "21.5"
      }

      raw = Codec.encode(packet)
      assert {:ok, ^packet, <<>>} = Codec.decode(raw)

      <<head::binary-size(3), _tail::binary>> = raw
      assert {:incomplete, ^head} = Codec.decode(head)
      assert {:ok, ^packet, <<>>} = Codec.decode(raw)
    end
  end

  test "SUBSCRIBE / SUBACK and UNSUBSCRIBE / UNSUBACK round-trip" do
    sub = %{type: :subscribe, packet_id: 9, topics: [{"a/+", 1}, {"b/#", 2}]}
    assert {:ok, ^sub, <<>>} = sub |> Codec.encode() |> Codec.decode()

    suback = %{type: :suback, packet_id: 9, granted: [1, 2]}
    assert {:ok, ^suback, <<>>} = suback |> Codec.encode() |> Codec.decode()

    unsub = %{type: :unsubscribe, packet_id: 10, topics: ["a/+"]}
    assert {:ok, ^unsub, <<>>} = unsub |> Codec.encode() |> Codec.decode()

    unsuback = %{type: :unsuback, packet_id: 10}
    assert {:ok, ^unsuback, <<>>} = unsuback |> Codec.encode() |> Codec.decode()
  end

  test "CONNACK round-trips, PINGREQ/PINGRESP/DISCONNECT encode empty" do
    connack = %{type: :connack, session_present: true, return_code: 0}
    assert {:ok, ^connack, <<>>} = connack |> Codec.encode() |> Codec.decode()
    assert Codec.encode(%{type: :pingreq}) == <<0xC0, 0x00>>
    assert Codec.encode(%{type: :pingresp}) == <<0xD0, 0x00>>
    assert Codec.encode(%{type: :disconnect}) == <<0xE0, 0x00>>
  end

  test "decode rejects unknown packet type, QoS 3 and a bad protocol version" do
    # Fixed header type 0 (reserved).
    assert {:error, :unknown_packet_type} = Codec.decode(<<0x00, 0x00>>)
    # PUBLISH with QoS 3.
    assert {:error, :bad_qos} = Codec.decode(<<0x36, 0x00>>)
    # CONNECT claiming protocol level 3 (MQTT 3.1) instead of 4.
    body = <<0, 4>> <> "MQTT" <> <<3, 0, 0, 0>> <> <<0, 1>> <> "x"
    assert {:error, :unacceptable_protocol_version} = Codec.decode(<<0x10, byte_size(body)>> <> body)
  end

  test "remaining length uses the multi-byte form past 127 bytes" do
    payload = String.duplicate("x", 300)
    packet = %{type: :publish, dup: false, qos: 0, retain: false, topic: "big", packet_id: nil, payload: payload}
    raw = Codec.encode(packet)
    assert {:ok, ^packet, <<>>} = Codec.decode(raw)
  end

  # --- topic filters ----------------------------------------------------

  test "topic filter validation follows MQTT 4.7" do
    assert Codec.valid_filter?("#")
    assert Codec.valid_filter?("sport/#")
    assert Codec.valid_filter?("sport/+/player")
    assert Codec.valid_filter?("a/b/c")
    refute Codec.valid_filter?("sport#")
    refute Codec.valid_filter?("sport/#/x")
    refute Codec.valid_filter?("a/b+")
    refute Codec.valid_filter?("")
    refute Codec.valid_topic?("a/#/b")
    refute Codec.valid_topic?("a/+")
    refute Codec.valid_topic?("")
    assert Codec.valid_topic?("a/b")
  end

  test "topic matching follows MQTT 4.7.1" do
    assert Codec.matches?("#", "a/b/c")
    assert Codec.matches?("sport/#", "sport")
    assert Codec.matches?("sport/#", "sport/tennis/player")
    assert Codec.matches?("sport/+", "sport/tennis")
    refute Codec.matches?("sport/+", "sport/tennis/player")
    refute Codec.matches?("sport/+", "sport")
    assert Codec.matches?("sport/+/player", "sport/tennis/player")
    refute Codec.matches?("a/b", "a/c")
    assert Codec.matches?("a/b", "a/b")
  end

  # --- broker -----------------------------------------------------------

  describe "broker" do
    setup do
      # The broker is a supervised child of the running application in
      # `mix test` (the app boots); these tests only use its public
      # API and their own client ids, so they stay isolated.
      :ok
    end

    test "subscribe + publish delivers, unsubscribe stops delivery" do
      cid = "ut-#{System.unique_integer([:positive])}"
      assert {:ok, false} = Broker.register(cid, self(), true)
      assert [1] = Broker.subscribe(cid, self(), [{"ut/topic", 1}])

      :ok = Broker.publish("ut/topic", "hello", 1, false)
      assert_receive {:mqtt_publish, %{topic: "ut/topic", payload: "hello", qos: 1}}, 1000

      :ok = Broker.unsubscribe(cid, ["ut/topic"])
      :ok = Broker.publish("ut/topic", "again", 0, false)
      refute_receive {:mqtt_publish, _}, 200

      :ok = Broker.client_gone(cid, :clean)
    end

    test "retained message is delivered to a late subscriber, and cleared by an empty retain" do
      topic = "ut/retained/#{System.unique_integer([:positive])}"
      :ok = Broker.publish(topic, "last-will-and-testament", 0, true)

      cid = "ut-r-#{System.unique_integer([:positive])}"
      assert {:ok, false} = Broker.register(cid, self(), true)
      assert [0] = Broker.subscribe(cid, self(), [{topic, 0}])
      assert_receive {:mqtt_publish, %{topic: ^topic, payload: "last-will-and-testament", retain: true}}, 1000

      :ok = Broker.publish(topic, "", 0, true)
      assert Broker.retained(topic) == nil

      :ok = Broker.client_gone(cid, :clean)
    end

    test "wildcard subscriptions receive matching publishes only" do
      cid = "ut-w-#{System.unique_integer([:positive])}"
      assert {:ok, false} = Broker.register(cid, self(), true)
      assert [1, 1] = Broker.subscribe(cid, self(), [{"ut/wild/+", 1}, {"ut/other/#", 1}])

      :ok = Broker.publish("ut/wild/one", "yes", 0, false)
      assert_receive {:mqtt_publish, %{topic: "ut/wild/one"}}, 1000
      :ok = Broker.publish("ut/wild/one/two", "no", 0, false)
      :ok = Broker.publish("ut/other/deep/x", "yes2", 0, false)
      assert_receive {:mqtt_publish, %{topic: "ut/other/deep/x"}}, 1000
      refute_receive {:mqtt_publish, %{topic: "ut/wild/one/two"}}, 200

      :ok = Broker.client_gone(cid, :clean)
    end

    test "invalid filter is refused with 0x80 in SUBACK" do
      cid = "ut-bad-#{System.unique_integer([:positive])}"
      assert {:ok, false} = Broker.register(cid, self(), true)
      assert [0x80] = Broker.subscribe(cid, self(), [{"bad/#/x", 0}])
      :ok = Broker.client_gone(cid, :clean)
    end

    test "inbound QoS 2 stores once, releases once" do
      cid = "ut-q2-#{System.unique_integer([:positive])}"
      packet = %{type: :publish, qos: 2, topic: "ut/q2", payload: "once", packet_id: 77, retain: false, dup: false}
      assert :ok = Broker.store_in_qos2(cid, 77, packet)
      assert :duplicate = Broker.store_in_qos2(cid, 77, packet)
      assert {:ok, ^packet} = Broker.release_in_qos2(cid, 77)
      assert :error = Broker.release_in_qos2(cid, 77)
    end

    test "persistent session keeps subscriptions and queues QoS 1 while offline" do
      cid = "ut-persist-#{System.unique_integer([:positive])}"
      parent = self()

      # The offline client is a real separate process: it registers a
      # persistent session, subscribes, then goes away cleanly. The
      # test process itself must not be the subscriber pid — it stays
      # alive, so the broker would (correctly) keep delivering to it.
      dummy =
        spawn(fn ->
          {:ok, false} = Broker.register(cid, self(), false)
          [1] = Broker.subscribe(cid, self(), [{"ut/persist", 1}])
          send(parent, :subscribed)

          receive do
            :go_offline -> :ok = Broker.client_gone(cid, :clean)
          end
        end)

      assert_receive :subscribed, 1000
      send(dummy, :go_offline)
      ref = Process.monitor(dummy)
      assert_receive {:DOWN, ^ref, :process, ^dummy, :normal}, 1000

      # Offline: QoS 1 publish is queued, not lost.
      :ok = Broker.publish("ut/persist", "queued-msg", 1, false)
      refute_receive {:mqtt_publish, _}, 200

      # Reconnect with clean_session false: session present, queued
      # message replayed to the new connection.
      assert {:ok, true} = Broker.register(cid, self(), false)
      assert_receive {:mqtt_publish, %{topic: "ut/persist", payload: "queued-msg", qos: 1}}, 1000

      :ok = Broker.client_gone(cid, :clean)
      # Clean reconnect wipes the session.
      assert {:ok, false} = Broker.register(cid, self(), true)
      :ok = Broker.client_gone(cid, :clean)
    end
  end
end
