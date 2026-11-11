defmodule Exjabberd.Mod.Csi do
  @moduledoc """
  Client State Indication — `mod_client_state` (XEP-0352, `urn:xmpp:csi:0`).

  The client tells the server whether a human is actively using it
  (`<active/>` / `<inactive/>`); the server then optimises traffic
  to that client. This implementation's optimisation, chosen from
  the examples in XEP-0352 §3.2 (the exact behaviour is deliberately
  left to the server by the XEP):

  * while a client is `inactive`, inbound **message** and **presence**
    stanzas are queued in the C2S process instead of being written to
    the socket, and flushed in order when the client sends
    `<active/>` again;
  * **IQ stanzas and error stanzas are never queued** — delaying a
    request/response exchange (ping, roster push, disco) would break
    the protocol, and error stanzas are the high-priority signal
    that something already went wrong.

  The queue itself lives in `Exjabberd.C2S` state (per connection);
  this module owns the feature advertisement, the configuration and
  the queue-or-deliver policy decision (`deliver_now?/1`), so the
  policy stays in one testable place.

  Business rules from the XEP, honoured here:

  * a stream always starts `active` (§4.2);
  * there is no reply to `<active/>` / `<inactive/>` (§4.2);
  * CSI state is independent of presence (§5);
  * after a Stream Management resumption the CSI state resets to
    `active` and any queued stanzas are flushed (§5.2) — see
    `Exjabberd.C2S` `{:sm_resume, ...}`;
  * in-order processing (§5.1): the listener applies the state
    change with a synchronous call, so a stanza sent right after
    `<active/>` (e.g. a ping) is only answered once the flush has
    reached the wire.

  Option (from `modules:` in `exjabberd.yml`):

  * `max_queue` — how many stanzas are queued for an inactive
    client (default 100); when full, the oldest queued stanza is
    dropped so a client that never comes back cannot grow the queue
    without bound.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  @csi_ns "urn:xmpp:csi:0"

  @default_max_queue 100

  @doc "Client State Indication namespace (XEP-0352)."
  @spec namespace() :: binary()
  def namespace, do: @csi_ns

  @impl true
  def start(host, _opts) do
    Exjabberd.Xmpp.Feature.register_csi(host)
    Logger.info("mod_client_state started for #{host} (max_queue=#{max_queue(host)})")
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:c2s_stream_features, host, Exjabberd.Xmpp.Feature, :csi_feature)
    :ok
  end

  @impl true
  def mod_options(_host), do: [max_queue: @default_max_queue]

  @impl true
  def mod_doc,
    do: %{
      desc: "Client State Indication (XEP-0352): queue traffic while the client is inactive",
      doc: "https://xmpp.org/extensions/xep-0352.html"
    }

  @doc "Configured `max_queue` for the host (default #{@default_max_queue})."
  @spec max_queue(binary()) :: pos_integer()
  def max_queue(host) do
    case Keyword.get(
           Exjabberd.Mod.Supervisor.get_opts(host, __MODULE__),
           :max_queue,
           @default_max_queue
         ) do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_max_queue
    end
  end

  @doc """
  True when this stanza must reach an inactive client immediately
  instead of being queued: IQ stanzas (request/response) and any
  stanza of type `error`.

  Pure function, so it is unit-testable without a connection.
  """
  @spec deliver_now?(map()) :: boolean()
  def deliver_now?(%{name: :iq}), do: true
  def deliver_now?(%{type: "error"}), do: true
  def deliver_now?(_), do: false
end
