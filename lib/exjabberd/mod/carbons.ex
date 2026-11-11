defmodule Exjabberd.Mod.Carbons do
  @moduledoc """
  Message Carbons — `mod_carboncopy` (XEP-0280, `urn:xmpp:carbons:2`).

  A carbons-enabled resource sees both sides of its user's
  conversations: outbound messages are copied to the user's other
  enabled resources inside `<sent/>`, inbound messages inside
  `<received/>`, each wrapping the original message in a
  `<forwarded xmlns='urn:xmpp:forward:0'/>` element. Copies are
  always sent *from* the user's bare JID, as the XEP requires.

  Eligibility (XEP-0280 §6.1, recommended rules) — a message is
  copied only when it has no `<private/>` child and at least one of:

  * type `chat`;
  * type `normal` (or no type) with a `<body/>`;
  * a receipt, chat-state or chat-marker payload.

  Never copied: messages of type `error` or `groupchat`, messages
  sent by a MUC room/service, carbon copies themselves, and anything
  carrying `<private/>`. (The XEP's narrow exception — an `error`
  reply to a message that was itself eligible — is not implemented:
  it needs server-side correlation of message ids, and is documented
  here instead of faked.)

  Carbons are off by default and per resource: a resource enables
  them with an IQ-set (`<enable/>`) and disables them with
  `<disable/>`. A resource that never enabled carbons never receives
  a copy, and an enabled resource never receives more than one copy
  of the same message. Copies flow through the normal router, so
  Stream Management ack counting and CSI queueing apply to them
  exactly like any other outbound stanza.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @carbons_ns "urn:xmpp:carbons:2"
  @forward_ns "urn:xmpp:forward:0"
  @private_ns "urn:xmpp:carbons:2"

  # Enabled resources: {{bare_jid, resource}, true}.
  @table :exjabberd_carbons

  @doc "Message Carbons namespace (XEP-0280 v2)."
  @spec namespace() :: binary()
  def namespace, do: @carbons_ns

  @impl true
  def start(host, _opts) do
    ensure_table()
    Exjabberd.Xmpp.Feature.register_carbons(host)
    Exjabberd.Hooks.add(:user_send_packet, host, __MODULE__, :on_send, 45)
    Exjabberd.Hooks.add(:user_receive_packet, host, __MODULE__, :on_receive, 45)
    Exjabberd.Hooks.add(:user_unavailable, host, __MODULE__, :on_unavailable, 50)
    Exjabberd.Iq.register(host, @carbons_ns, __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:user_send_packet, host, __MODULE__, :on_send)
    Exjabberd.Hooks.delete(:user_receive_packet, host, __MODULE__, :on_receive)
    Exjabberd.Hooks.delete(:user_unavailable, host, __MODULE__, :on_unavailable)
    Exjabberd.Iq.unregister(host, @carbons_ns, :both)
    Exjabberd.Hooks.delete(:c2s_stream_features, host, Exjabberd.Xmpp.Feature, :carbons_feature)
    :ok
  end

  @impl true
  def mod_doc,
    do: %{
      desc: "Message Carbons (XEP-0280): copy messages to all enabled resources",
      doc: "https://xmpp.org/extensions/xep-0280.html"
    }

  @doc "True when carbons are enabled for this full JID (bare + resource)."
  @spec enabled?(binary(), binary()) :: boolean()
  def enabled?(bare, resource) when is_binary(bare) and is_binary(resource) do
    ensure_table()
    :ets.member(@table, {String.downcase(bare), resource})
  end

  @doc "Enable carbons for a full JID."
  @spec enable(binary(), binary()) :: :ok
  def enable(bare, resource) do
    ensure_table()
    :ets.insert(@table, {{String.downcase(bare), resource}, true})
    :ok
  end

  @doc "Disable carbons for a full JID."
  @spec disable(binary(), binary()) :: :ok
  def disable(bare, resource) do
    ensure_table()
    :ets.delete(@table, {String.downcase(bare), resource})
    :ok
  end

  @doc "Other carbons-enabled resources of this bare JID (excluding `resource`)."
  @spec other_enabled_resources(binary(), binary()) :: [binary()]
  def other_enabled_resources(bare, resource) when is_binary(bare) do
    Exjabberd.SessionManager.get_resources(bare)
    |> Enum.reject(&(&1 == resource))
    |> Enum.filter(&enabled?(bare, &1))
  end

  @doc """
  XEP-0280 §6.1 eligibility: is this message worth carbon-copying?

  Pure function, so it is unit-testable without a connection.
  """
  @spec eligible?(map()) :: boolean()
  def eligible?(%{name: :message} = stanza) do
    cond do
      stanza.type in ["error", "groupchat"] -> false
      has_child_ns?(stanza, "private", @private_ns) -> false
      is_carbon?(stanza) -> false
      muc_sent?(stanza) -> false
      stanza.type == "chat" -> true
      stanza.type in ["normal", nil] and has_body?(stanza) -> true
      has_im_marker?(stanza) -> true
      true -> false
    end
  end

  def eligible?(_), do: false

  @doc "True when the stanza already is a carbon copy (never copy it again)."
  @spec is_carbon?(map()) :: boolean()
  def is_carbon?(stanza) do
    has_child_ns?(stanza, "sent", @carbons_ns) or
      has_child_ns?(stanza, "received", @carbons_ns)
  end

  # --- hooks ---

  @doc false
  def on_send(%{name: :message} = stanza, _host, jid) do
    carbon_out(stanza, jid, :sent)
    stanza
  end

  def on_send(stanza, _host, _jid), do: stanza

  @doc false
  def on_receive(%{name: :message} = stanza, _host, jid) do
    carbon_out(stanza, jid, :received)
    stanza
  end

  def on_receive(stanza, _host, _jid), do: stanza

  @doc false
  def on_unavailable(jid, _host) do
    case full_jid_parts(jid) do
      {bare, resource} when is_binary(bare) and is_binary(resource) -> disable(bare, resource)
      _ -> :ok
    end

    jid
  end

  # --- IQ enable/disable ---

  @doc false
  def handle_iq(%{type: "set"} = iq, _host) do
    with {bare, resource} when is_binary(bare) and is_binary(resource) <-
           full_jid_parts(iq.from),
         el when not is_nil(el) <- Stanza.get_subtag(iq, @carbons_ns) do
      case el.name do
        "enable" ->
          enable(bare, resource)
          {:ok, %{iq | type: "result", payload: []}}

        "disable" ->
          disable(bare, resource)
          {:ok, %{iq | type: "result", payload: []}}

        _ ->
          {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
      end
    else
      _ -> {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  # --- internals ---

  # Copy an eligible message to the user's other enabled resources.
  # `kind` is `:sent` (own outbound message) or `:received` (inbound).
  defp carbon_out(stanza, jid, kind) do
    with {bare, resource} when is_binary(bare) and is_binary(resource) <-
           full_jid_parts(jid),
         true <- enabled?(bare, resource),
         true <- eligible?(stanza) do
      Enum.each(other_enabled_resources(bare, resource), fn target ->
        copy = carbon_copy(bare, bare <> "/" <> target, kind, stanza)
        Exjabberd.Router.route(copy)
      end)
    end

    :ok
  end

  defp carbon_copy(from_bare, to_full, kind, original) do
    forwarded = %{
      name: "message",
      attrs: stanza_attrs(original),
      children: original.payload || []
    }

    wrapper = %{
      name: Atom.to_string(kind),
      attrs: %{"xmlns" => @carbons_ns},
      children: [
        %{name: "forwarded", attrs: %{"xmlns" => @forward_ns}, children: [forwarded]}
      ]
    }

    Stanza.new(:message, from: from_bare, to: to_full, payload: [wrapper])
  end

  # The forwarded message keeps the original's addressing and id.
  defp stanza_attrs(stanza) do
    %{}
    |> maybe_attr("id", stanza.id)
    |> maybe_attr("from", jid_string(stanza.from))
    |> maybe_attr("to", jid_string(stanza.to))
    |> maybe_attr("type", stanza.type)
  end

  defp maybe_attr(attrs, _key, nil), do: attrs
  defp maybe_attr(attrs, _key, ""), do: attrs
  defp maybe_attr(attrs, key, value), do: Map.put(attrs, key, to_string(value))

  defp jid_string(nil), do: nil
  defp jid_string(%Jid{} = jid), do: Jid.to_string(jid)
  defp jid_string(bin) when is_binary(bin), do: bin

  defp has_body?(stanza), do: Stanza.child(stanza.payload || [], "body") != nil

  defp has_im_marker?(stanza) do
    Enum.any?(stanza.payload || [], fn
      %{attrs: %{"xmlns" => ns}} ->
        ns in [
          "urn:xmpp:receipts",
          "http://jabber.org/protocol/chatstates",
          "urn:xmpp:chat-markers:0"
        ]

      _ ->
        false
    end)
  end

  defp has_child_ns?(stanza, name, ns) do
    Enum.any?(stanza.payload || [], fn
      %{name: ^name, attrs: %{"xmlns" => ^ns}} -> true
      %{name: ^name, attrs: %{xmlns: ^ns}} -> true
      _ -> false
    end)
  end

  # A message sent by a MUC room/service is never carbon-copied.
  defp muc_sent?(%{from: %Jid{domain: domain}}) when is_binary(domain) do
    String.starts_with?(domain, "conference.")
  end

  defp muc_sent?(%{from: from}) when is_binary(from) do
    from |> String.split("@") |> List.last("") |> String.starts_with?("conference.")
  end

  defp muc_sent?(_), do: false

  defp full_jid_parts(%Jid{} = jid) do
    {Jid.bare(jid), jid.resource || ""}
  end

  defp full_jid_parts(bin) when is_binary(bin) do
    case String.split(bin, "/", parts: 2) do
      [bare, resource] -> {Jid.bare(bare), resource}
      [bare] -> {Jid.bare(bare), ""}
    end
  end

  defp full_jid_parts(_), do: {nil, nil}

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end
  end
end
