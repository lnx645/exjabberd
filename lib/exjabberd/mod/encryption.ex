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
