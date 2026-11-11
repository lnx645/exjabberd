defmodule Exjabberd.Mqtt.Bridge do
  @moduledoc """
  Bridge between MQTT topics and XMPP PubSub nodes (XEP-0060).

  Mapping: an MQTT topic maps to a PubSub node of the same name on the
  server's first host (an optional `mqtt.bridge.prefix` is stripped
  first). Both directions:

  * MQTT → XMPP: the broker calls `mqtt_to_pubsub/2` for every
    publish. The node is auto-created (open access / open publish
    model) when `mqtt.bridge.auto_create_node` is true and the node
    does not exist yet; the item payload is the raw MQTT payload
    bytes. The publish is made with `from_bridge: true`, so the
    PubSub hook below does not echo it back to MQTT (no loop).
  * XMPP → MQTT: the bridge registers the `:pubsub_publish_item`
    hook; every PubSub publish (from an XMPP client, or any other
    module) is forwarded to the broker as a QoS 0, non-retained
    publish on the node name as topic. The item payload is converted
    to bytes by extracting the text of the item's XML children.

  Loop safety: a bridged MQTT publish never re-enters the broker
  (the `from_bridge` flag), and a bridged PubSub publish is a plain
  broker publish with `from_bridge: true` — each message crosses the
  bridge exactly once, in each direction, at most once per hop.
  """

  require Logger

  alias Exjabberd.Mod.PubSub
  alias Exjabberd.Mqtt.Broker

  @doc "Register the PubSub → MQTT hook for `host`."
  @spec start(binary(), keyword()) :: :ok
  def start(host, _opts \\ []) do
    Exjabberd.Hooks.add(:pubsub_publish_item, host, __MODULE__, :on_pubsub_publish, 50)
    :ok
  end

  @doc "Remove the hook again."
  @spec stop(binary()) :: :ok
  def stop(host) do
    Exjabberd.Hooks.delete(:pubsub_publish_item, host, __MODULE__, :on_pubsub_publish)
    :ok
  end

  @doc "MQTT → XMPP: publish `payload` to the PubSub node named after `topic`."
  @spec mqtt_to_pubsub(binary(), binary()) :: :ok
  def mqtt_to_pubsub(topic, payload) do
    if Exjabberd.Mqtt.bridge_enabled?() do
      host = List.first(Exjabberd.Config.hosts()) || "localhost"
      node = topic_to_node(topic)

      if node == "" or node == nil do
        :ok
      else
        if PubSub.get_node(host, node) == nil do
          if bridge_opt(:auto_create_node, true) do
            case PubSub.create_node(host, node,
                   access_model: "open",
                   publish_model: "open",
                   owner: "mqtt-bridge@#{host}"
                 ) do
              :ok -> :ok
              {:error, :conflict} -> :ok
              {:error, reason} -> Logger.warning("mqtt bridge: cannot create node #{node}: #{inspect(reason)}")
            end
          else
            Logger.debug("mqtt bridge: no node #{node}, auto_create_node is off")
          end
        end

        case PubSub.publish(host, node, nil, payload, from_bridge: true) do
          :ok -> :ok
          {:error, reason} -> Logger.warning("mqtt bridge: publish to #{node} failed: #{inspect(reason)}")
        end
      end
    else
      :ok
    end
  end

  @doc false
  def on_pubsub_publish({node, _item_id, payload} = data, _host) do
    if Exjabberd.Mqtt.bridge_enabled?() do
      case payload_to_binary(payload) do
        nil ->
          :ok

        text ->
          topic = node_to_topic(node)
          Broker.publish(topic, text, 0, false, from_bridge: true)
      end
    end

    data
  end

  def on_pubsub_publish(data, _host), do: data

  @doc "MQTT topic → PubSub node name (strip the configured prefix)."
  @spec topic_to_node(binary()) :: binary()
  def topic_to_node(topic) do
    prefix = bridge_opt(:prefix, "")

    if is_binary(prefix) and prefix != "" and String.starts_with?(topic, prefix) do
      String.slice(topic, String.length(prefix)..-1//1)
    else
      topic
    end
  end

  @doc "PubSub node name → MQTT topic."
  @spec node_to_topic(binary()) :: binary()
  def node_to_topic(node) do
    prefix = bridge_opt(:prefix, "")

    if is_binary(prefix) and prefix != "" do
      prefix <> node
    else
      node
    end
  end

  @doc "Extract the text payload of a PubSub item as bytes, or `nil` when there is none."
  @spec payload_to_binary(term()) :: binary() | nil
  def payload_to_binary(payload) when is_binary(payload) do
    if payload == "", do: nil, else: payload
  end

  def payload_to_binary(payload) when is_list(payload) do
    text = Enum.map_join(payload, "", &element_text/1)

    if text == "", do: nil, else: text
  end

  def payload_to_binary(_), do: nil

  defp element_text(text) when is_binary(text), do: text

  defp element_text(%{children: children}) when is_list(children) do
    Enum.map_join(children, &element_text/1)
  end

  defp element_text(_), do: ""

  defp bridge_opt(key, default) do
    config = Exjabberd.Mqtt.bridge_config()
    Map.get(config, to_string(key), Map.get(config, key, default))
  end
end
