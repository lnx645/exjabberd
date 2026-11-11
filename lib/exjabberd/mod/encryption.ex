defmodule Exjabberd.Mod.Omemo do
  @moduledoc """
  OMEMO Encryption - XEP-0384 (partial implementation) (ejabberd via PEP + PubSub).

  Ejabberd tidak punya `mod_omemo` terpisah — OMEMO jalan via `mod_pubsub` PEP
  dengan node `urn:xmpp:omemo:0` (bundle) dan `urn:xmpp:omemo:0:devicelist`.
  Di exjabberd kita bikin modul eksplisit agar enkripsi end-to-end (E2EE)
  jelas real berfungsi untuk chat 1-1 dan group.

  Menghandle:
  - Bundle publish/fetch via PubSub PEP (like `mod_pubsub` PEP)
  - Devicelist notify via `pep` hook
  - IQ `urn:xmpp:omemo:0` + `urn:xmpp:omemo:2` (OMEMO 0.3.x)
  """

  use Exjabberd.Mod.GenMod

  @bundle_node "urn:xmpp:omemo:0"
  @devicelist_node "urn:xmpp:omemo:0:devicelist"

  @impl true
  def start(host, _opts) do
    Exjabberd.Iq.register(host, @bundle_node, __MODULE__, :handle_bundle)
    Exjabberd.Iq.register(host, @devicelist_node, __MODULE__, :handle_devicelist)
    Exjabberd.Hooks.add(:pep_publish, host, __MODULE__, :on_pep_publish, 40)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @bundle_node, :both)
    Exjabberd.Iq.unregister(host, @devicelist_node, :both)
    Exjabberd.Hooks.delete(:pep_publish, host, __MODULE__, :on_pep_publish)
    :ok
  end

  @doc "Publish OMEMO bundle for device (like `PEP publish omemo bundle` with signed prekeys)."
  @spec publish_bundle(binary(), binary(), non_neg_integer(), map()) :: :ok | {:error, term()}
  def publish_bundle(host, bare_jid, device_id, bundle) do
    node = "#{bare_jid}/#{@bundle_node}:#{device_id}"
    prekey_sig = Map.get(bundle, :signed_prekey)
    _ = prekey_sig

    Exjabberd.Mod.PubSub.create_node(host, node,
      type: "leaf",
      access_model: "open",
      publish_model: "open",
      owner: bare_jid
    )

    enriched = Map.merge(bundle, %{device_id: device_id, published_at: System.system_time(:second)})
    Exjabberd.Mod.PubSub.publish(host, node, to_string(device_id), enriched, publisher: bare_jid)
  end

  @doc "Fetch bundle (like ejabberd `mod_pubsub` PEP fetch)."
  @spec fetch_bundle(binary(), binary(), non_neg_integer()) :: {:ok, map()} | {:error, term()}
  def fetch_bundle(host, bare_jid, device_id) do
    node = "#{bare_jid}/#{@bundle_node}:#{device_id}"

    case Exjabberd.Mod.PubSub.get_items(host, node) do
      {:ok, [%{payload: bundle} | _], _} -> {:ok, bundle}
      _ -> {:error, :not_found}
    end
  end

  @doc "Encrypt OMEMO message envelope (XEP-0384 §5). Server just stores/relays, encryption client-side — server handles `encrypted` tag passthrough like ejabberd."
  @spec handle_encrypted(map(), binary()) :: map()
  def handle_encrypted(%{payload: payload} = stanza, _host) do
    # Server does not decrypt — only ensure `urn:xmpp:omemo:0` or `urn:xmpp:omemo:2` present
    has_omemo =
      Enum.any?(payload, fn
        %{xmlns: ns}
        when ns in ["urn:xmpp:omemo:0", "urn:xmpp:omemo:2", "eu.siacs.conversations.axolotl"] ->
          true

        %{name: "encrypted"} ->
          true

        _ ->
          false
      end)

    if has_omemo do
      # Hook for MAM to archive encrypted without plaintext (ejabberd does same)
      stanza
    else
      stanza
    end
  end

  @doc "Publish devicelist (like `urn:xmpp:omemo:0:devicelist` PEP)."
  @spec publish_devicelist(binary(), binary(), [non_neg_integer()]) :: :ok
  def publish_devicelist(host, bare_jid, device_ids) do
    payload = %{devices: device_ids}
    Exjabberd.Hooks.run(:pep_publish, host, {bare_jid, @devicelist_node, payload})

    _ =
      Exjabberd.Mod.PubSub.create_node(host, "#{bare_jid}/#{@devicelist_node}",
        type: "leaf",
        access_model: "open",
        publish_model: "open",
        owner: bare_jid
      )

    Exjabberd.Mod.PubSub.publish(host, "#{bare_jid}/#{@devicelist_node}", "current", payload,
      publisher: bare_jid
    )
  end

  @doc "Get devicelist."
  @spec get_devicelist(binary(), binary()) :: {:ok, [non_neg_integer()]} | {:error, term()}
  def get_devicelist(host, bare_jid) do
    node = "#{bare_jid}/#{@devicelist_node}"

    case Exjabberd.Mod.PubSub.get_items(host, node) do
      {:ok, [%{payload: %{devices: ids}} | _], _} -> {:ok, ids}
      _ -> {:ok, []}
    end
  end

  @doc false
  def handle_bundle(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
  @doc false
  def handle_devicelist(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
  @doc false
  def on_pep_publish({bare_jid, node, payload} = data, _host)
      when node in [@bundle_node, @devicelist_node] do
    _ = {bare_jid, payload}
    data
  end

  def on_pep_publish(data, _host), do: data
end

defmodule Exjabberd.Mod.Otr do
  @moduledoc """
  OTR - XEP-0364 (OTR) + `otr` whitespace tag. E2EE legacy untuk chat 1-1.
  Di ejabberd OTR di-handle client-side, server hanya passthrough + policy.
  """

  use Exjabberd.Mod.GenMod

  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:user_send_packet, host, __MODULE__, :passthrough, 90)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:user_send_packet, host, __MODULE__, :passthrough)
    :ok
  end

  @doc false
  def passthrough(packet, _host) do
    # OTR tag `?OTR` - server tidak decrypt, hanya forward seperti ejabberd
    packet
  end
end

defmodule Exjabberd.Mod.Pgp do
  @moduledoc """
  OpenPGP for XMPP - XEP-0373 + XEP-0374 (OX) (partial implementation).
  PubSub PEP `urn:xmpp:openpgp:0:public-keys` seperti OMEMO.
  """

  use Exjabberd.Mod.GenMod

  @node "urn:xmpp:openpgp:0:public-keys"

  @impl true
  def start(host, _opts) do
    Exjabberd.Iq.register(host, @node, __MODULE__, :handle_pubkeys)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @node, :both)
    :ok
  end

  @doc "Publish OpenPGP public key (XEP-0373 §6 + PEP)."
  @spec publish_key(binary(), binary(), binary()) :: :ok
  def publish_key(host, bare_jid, key_data) do
    node = "#{bare_jid}/#{@node}"

    Exjabberd.Mod.PubSub.create_node(host, node,
      type: "leaf",
      access_model: "open",
      publish_model: "open",
      owner: bare_jid
    )

    # Also handle `urn:xmpp:openpgp:0:public-keys:openpgp-public-key` per device
    enriched = %{
      key: key_data,
      fingerprint: :crypto.hash(:sha256, key_data) |> Base.encode16(case: :lower)
    }

    Exjabberd.Mod.PubSub.publish(host, node, "current", enriched, publisher: bare_jid)
  end

  @doc "Fetch OpenPGP keys (ejabberd PGP via PubSub)."
  @spec fetch_keys(binary(), binary()) :: {:ok, [map()]} | {:error, term()}
  def fetch_keys(host, bare_jid) do
    node = "#{bare_jid}/#{@node}"

    case Exjabberd.Mod.PubSub.get_items(host, node) do
      {:ok, items, _} -> {:ok, Enum.map(items, & &1.payload)}
      _ -> {:ok, []}
    end
  end

  @doc false
  def handle_pubkeys(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end
