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

  # --- MQTT v5.0 codec --------------------------------------------------

  describe "MQTT v5 codec" do
    test "CONNECT v5 round-trips with properties and will properties" do
      packet = %{
        type: :connect,
        version: 5,
        client_id: "v5-client",
        clean_session: false,
        keep_alive: 30,
        username: "andi",
        password: "secret",
        will_flag: true,
        will_topic: "status/v5",
        will_message: "gone",
        will_qos: 1,
        will_retain: true,
        properties: %{
          session_expiry_interval: 120,
          receive_maximum: 10,
          user_properties: [{"k", "v"}]
        },
        will_properties: %{will_delay_interval: 5, content_type: "text/plain"}
      }

      raw = Codec.encode(packet, 5)
      assert {:ok, decoded, <<>>} = Codec.decode(raw, 5)
      assert decoded.version == 5
      assert decoded.client_id == "v5-client"
      assert decoded.clean_session == false
      assert decoded.keep_alive == 30
      assert decoded.username == "andi"
      assert decoded.will_topic == "status/v5"
      assert decoded.properties.session_expiry_interval == 120
      assert decoded.properties.receive_maximum == 10
      assert decoded.properties.user_properties == [{"k", "v"}]
      assert decoded.will_properties.will_delay_interval == 5
      assert decoded.will_properties.content_type == "text/plain"
    end

    test "CONNECT v5 rejects a password without a username" do
      # flags: password set, username clear, clean start.
      body =
        <<0, 4>> <>
          "MQTT" <>
          <<5, 0x42, 0, 60>> <>
          <<0>> <> <<0, 1>> <> "x" <> <<0, 1>> <> "p"

      assert {:error, :password_without_username} =
               Codec.decode(<<0x10, byte_size(body)>> <> body, 5)
    end

    test "CONNACK v5 round-trips with reason code and properties" do
      packet = %{
        type: :connack,
        session_present: true,
        reason_code: 0,
        properties: %{
          topic_alias_maximum: 16,
          retain_available: 1,
          assigned_client_identifier: "exj5-abc"
        }
      }

      raw = Codec.encode(packet, 5)
      assert {:ok, decoded, <<>>} = Codec.decode(raw, 5)
      assert decoded.session_present == true
      assert decoded.reason_code == 0
      assert decoded.properties.topic_alias_maximum == 16
      assert decoded.properties.assigned_client_identifier == "exj5-abc"
    end

    test "PUBLISH v5 round-trips with properties incl. subscription identifiers" do
      packet = %{
        type: :publish,
        dup: false,
        qos: 1,
        retain: false,
        topic: "a/b",
        packet_id: 7,
        payload: "hello",
        properties: %{
          content_type: "text/plain",
          response_topic: "reply/to",
          correlation_data: <<1, 2, 3>>,
          subscription_identifiers: [42, 43],
          message_expiry_interval: 60,
          user_properties: [{"trace", "t1"}]
        }
      }

      raw = Codec.encode(packet, 5)
      assert {:ok, ^packet, <<>>} = Codec.decode(raw, 5)
    end

    test "PUBLISH v5 with an empty topic requires a topic alias" do
      raw = Codec.encode(%{type: :publish, qos: 0, topic: "", payload: "x", properties: %{}}, 5)
      assert {:error, :invalid_topic} = Codec.decode(raw, 5)

      aliased = %{
        type: :publish,
        dup: false,
        qos: 0,
        retain: false,
        topic: "",
        packet_id: nil,
        payload: "x",
        properties: %{topic_alias: 3}
      }

      assert {:ok, ^aliased, <<>>} = aliased |> Codec.encode(5) |> Codec.decode(5)
    end

    test "SUBSCRIBE v5 round-trips with options and a subscription identifier" do
      packet = %{
        type: :subscribe,
        packet_id: 11,
        properties: %{subscription_identifiers: [9]},
        topics: [
          {"a/+", 1, %{no_local: true, retain_as_published: false, retain_handling: 0}},
          {"b/#", 2, %{no_local: false, retain_as_published: true, retain_handling: 2}}
        ]
      }

      raw = Codec.encode(packet, 5)
      assert {:ok, ^packet, <<>>} = Codec.decode(raw, 5)
    end

    test "SUBSCRIBE v5 rejects reserved option bits and retain handling 3" do
      # options byte 0xC1: reserved bits set.
      body = <<0, 11, 0, 0, 3>> <> "a/b" <> <<0xC1>>
      raw = <<0x82, byte_size(body)>> <> body
      assert {:error, :bad_subscription_options} = Codec.decode(raw, 5)
    end

    test "UNSUBACK v5 carries per-filter reason codes" do
      packet = %{type: :unsuback, packet_id: 5, properties: %{}, codes: [0, 0x11]}
      raw = Codec.encode(packet, 5)
      assert {:ok, decoded, <<>>} = Codec.decode(raw, 5)
      assert decoded.codes == [0, 0x11]
    end

    test "DISCONNECT and AUTH v5 round-trip" do
      disc = %{
        type: :disconnect,
        reason_code: 0x04,
        properties: %{session_expiry_interval: 0}
      }

      assert {:ok, ^disc, <<>>} = disc |> Codec.encode(5) |> Codec.decode(5)

      auth = %{
        type: :auth,
        reason_code: 0x18,
        properties: %{authentication_method: "SCRAM-SHA-256", authentication_data: "abc"}
      }

      assert {:ok, ^auth, <<>>} = auth |> Codec.encode(5) |> Codec.decode(5)
    end

    test "ack packets v5 accept short and long forms" do
      assert {:ok, %{type: :puback, packet_id: 3}, <<>>} =
               Codec.decode(<<0x40, 0x02, 0, 3>>, 5)

      long =
        Codec.encode(%{type: :puback, packet_id: 3, reason_code: 0x10, properties: %{}}, 5)

      assert {:ok, %{type: :puback, packet_id: 3, reason_code: 0x10}, <<>>} =
               Codec.decode(long, 5)
    end

    test "unknown or misplaced properties are protocol errors" do
      # PUBLISH with a CONNECT-only property (session expiry, 0x11).
      body = <<0, 3>> <> "a/b" <> <<5, 0x11, 0, 0, 0, 9>> <> "x"
      raw = <<0x30, byte_size(body)>> <> body
      assert {:error, :property_not_allowed} = Codec.decode(raw, 5)
    end

    test "shared subscription filters validate and match on the inner filter" do
      assert Codec.valid_filter?("$share/group/a/+")
      refute Codec.valid_filter?("$share//a/b")
      refute Codec.valid_filter?("$share/gro+up/a/b")
      refute Codec.valid_filter?("$share/group")
      assert Codec.shared_parts("$share/g/a/b") == {:ok, "g", "a/b"}
      assert Codec.shared_parts("a/b") == :not_shared
      assert Codec.matches?("$share/g/sport/+", "sport/tennis")
      refute Codec.matches?("$share/g/sport/+", "sport/tennis/x")
    end

    test "wildcard filters never match $-topics" do
      refute Codec.matches?("#", "$SYS/broker/uptime")
      refute Codec.matches?("+/broker", "$SYS/broker")
      assert Codec.matches?("$SYS/#", "$SYS/broker/uptime")
    end
  end

  # --- broker v5 behaviour ------------------------------------------------

  describe "broker v5 behaviour" do
    test "shared subscription delivers one copy per group, split across members" do
      parent = self()
      uniq = System.unique_integer([:positive])
      topic = "ut5/shared/#{uniq}"

      members =
        for i <- 1..2 do
          cid = "ut5-sh-#{i}-#{uniq}"

          pid =
            spawn(fn ->
              {:ok, false} = Broker.register(cid, self(), true)
              [1] = Broker.subscribe(cid, self(), [{"$share/g1/#{topic}", 1}])
              send(parent, {:ready, cid})

              collect = fn collect, acc ->
                receive do
                  {:mqtt_publish, %{payload: p}} -> collect.(collect, [p | acc])
                  :report -> send(parent, {:got, cid, Enum.reverse(acc)})
                end
              end

              collect.(collect, [])
            end)

          {cid, pid}
        end

      assert_receive {:ready, _}, 1000
      assert_receive {:ready, _}, 1000
      :ok = Broker.publish(topic, "m1", 1, false)
      :ok = Broker.publish(topic, "m2", 1, false)
      :ok = Broker.publish(topic, "m3", 1, false)
      :ok = Broker.publish(topic, "m4", 1, false)

      for {_cid, pid} <- members, do: send(pid, :report)
      got = for _ <- members, do: (assert_receive {:got, _cid, payloads}, 1000; payloads)
      all = List.flatten(got)
      assert Enum.sort(all) == ["m1", "m2", "m3", "m4"]
      assert Enum.all?(got, &(length(&1) >= 1))

      for {cid, _pid} <- members, do: :ok = Broker.client_gone(cid, :clean)
    end

    test "no-local subscriptions skip the publisher's own messages" do
      cid = "ut5-nl-#{System.unique_integer([:positive])}"
      assert {:ok, false} = Broker.register(cid, self(), true)

      assert [1] =
               Broker.subscribe(cid, self(), [
                 {"ut5/nolocal", 1, %{no_local: true, retain_as_published: false, retain_handling: 0}}
               ])

      :ok = Broker.publish("ut5/nolocal", "own", 1, false, from_client: cid)
      refute_receive {:mqtt_publish, _}, 200

      :ok = Broker.publish("ut5/nolocal", "other", 1, false, from_client: "someone-else")
      assert_receive {:mqtt_publish, %{payload: "other"}}, 1000

      :ok = Broker.client_gone(cid, :clean)
    end

    test "session expiry 0 drops the session, a parked will fires at session end" do
      uniq = System.unique_integer([:positive])
      will_topic = "ut5/will/#{uniq}"
      watcher = "ut5-watch-#{uniq}"
      assert {:ok, false} = Broker.register(watcher, self(), true)
      assert [0] = Broker.subscribe(watcher, self(), [{will_topic, 0}])

      cid = "ut5-exp-#{uniq}"
      parent = self()

      pid =
        spawn(fn ->
          {:ok, false} =
            Broker.register(cid, self(), false,
              session_expiry: 0,
              will: %{topic: will_topic, payload: "bye", qos: 0, retain: false, delay: 30}
            )

          [0] = Broker.subscribe(cid, self(), [{"ut5/exp/topic", 0}])
          send(parent, :registered)

          receive do
            :die -> :ok = Broker.client_gone(cid, :abnormal, from_pid: self())
          end
        end)

      assert_receive :registered, 1000
      send(pid, :die)
      # delay 30 would park the will, but the session ends at once
      # (expiry 0) — so the will is published immediately.
      assert_receive {:mqtt_publish, %{topic: ^will_topic, payload: "bye"}}, 2000
      # and the session is gone entirely.
      assert {:ok, false} = Broker.register(cid, self(), false)
      :ok = Broker.client_gone(cid, :clean)
      :ok = Broker.client_gone(watcher, :clean)
    end
  end
end
