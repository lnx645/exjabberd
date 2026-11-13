defmodule Exjabberd.Mqtt do
  @moduledoc """
  MQTT broker (v3.1.1 Fase 6, v5.0 Fase 17) — configuration accessors.

  The `mqtt:` section of `exjabberd.yml` (all optional, defaults shown):

      mqtt:
        allow_anonymous: true   # CONNECT without username is accepted
        max_payload: 262144     # largest PUBLISH payload, bytes
        max_clients: 1000       # simultaneous MQTT connections
        max_queued: 100         # offline messages kept per persistent session
        bridge:
          enabled: true         # MQTT <-> XMPP PubSub bridge
          auto_create_node: true # create the PubSub node on first MQTT publish
          prefix: ""            # strip this topic prefix for the node name

  No credential lives here: when a username is given, the password is
  checked against the configured Auth backend
  (`Exjabberd.Auth.authenticate/3`) — the same accounts as XMPP.
  """

  @doc "One `mqtt:` option, or `default` when unconfigured."
  @spec config(atom(), term()) :: term()
  def config(key, default \\ nil) do
    mqtt = Exjabberd.Config.mqtt()

    case Map.get(mqtt, to_string(key), Map.get(mqtt, key)) do
      nil -> default
      value -> value
    end
  end

  @doc "The `mqtt.bridge:` map, or `%{}`."
  @spec bridge_config() :: map()
  def bridge_config do
    case config(:bridge, %{}) do
      map when is_map(map) -> map
      _ -> %{}
    end
  end

  @doc "Is the MQTT <-> PubSub bridge enabled?"
  @spec bridge_enabled?() :: boolean()
  def bridge_enabled? do
    case Map.get(bridge_config(), "enabled", Map.get(bridge_config(), :enabled, true)) do
      value when is_boolean(value) -> value
      _ -> true
    end
  end
end
