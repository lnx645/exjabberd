defmodule Exjabberd.Mod.PubSub.Node do
  @moduledoc """
  PubSub node behaviour - `gen_pubsub_node` + `node_flat`/`node_hometree` (partial implementation), stabil.

  Every node type (leaf, collection, push) implements this. Like ejabberd `gen_pubsub_node`.
  """

  @callback init(binary(), binary(), keyword()) :: {:ok, map()} | {:error, term()}
  @callback create_node(binary(), binary(), keyword()) :: :ok | {:error, term()}
  @callback delete_node(binary(), binary()) :: :ok
  @callback publish_item(binary(), binary(), binary(), term(), binary() | nil) ::
              :ok | {:error, term()}
  @callback delete_item(binary(), binary(), binary()) :: :ok | {:error, term()}
  @callback get_items(binary(), binary(), keyword()) :: {:ok, [map()], map()} | {:error, term()}
  @callback get_subscribers(binary(), binary()) :: {:ok, [binary()]}
  @callback get_affiliation(binary(), binary(), binary()) :: atom()
  @callback set_affiliation(binary(), binary(), binary(), atom()) :: :ok
end

defmodule Exjabberd.Mod.PubSub.Nodetree do
  @moduledoc """
  PubSub nodetree behaviour - `gen_pubsub_nodetree` (tree, virtual) (partial implementation), stabil.

  Stores node hierarchy like `nodetree_tree`/`nodetree_virtual` di ejabberd.
  """

  @callback create_node(binary(), binary(), binary(), keyword()) :: :ok | {:error, term()}
  @callback delete_node(binary(), binary(), binary()) :: :ok
  @callback get_node(binary(), binary(), binary()) :: {:ok, map()} | :error
  @callback get_nodes(binary(), binary()) :: [binary()]

  @table :exjabberd_pubsub_tree

  @doc "Create node in tree (like `nodetree_tree:create_node`)."
  @spec create(binary(), binary(), binary(), keyword()) :: :ok | {:error, term()}
  def create(host, node, parent, opts) do
    ensure()

    if :ets.member(@table, {host, node}) do
      {:error, :conflict}
    else
      :ets.insert(
        @table,
        {{host, node}, %{parent: parent, opts: opts, created: System.system_time(:second)}}
      )

      :ok
    end
  end

  @doc "Delete node (like `nodetree_tree:delete_node`)."
  @spec delete(binary(), binary(), binary()) :: :ok
  def delete(host, node, _parent) do
    ensure()
    :ets.delete(@table, {host, node})
    # Also delete children like ejabberd does
    :ets.match_delete(@table, {{host, :_}, %{parent: node}})
    :ok
  end

  @doc "Get node."
  @spec get_node(binary(), binary(), binary()) :: {:ok, map()} | :error
  def get_node(host, node, _parent) do
    ensure()

    case :ets.lookup(@table, {host, node}) do
      [{{_, _}, data}] -> {:ok, data}
      [] -> :error
    end
  end

  @doc "Get children of parent."
  @spec get_nodes(binary(), binary()) :: [binary()]
  def get_nodes(host, parent) do
    ensure()
    :ets.match(@table, {{host, :"$1"}, %{parent: parent}}) |> List.flatten()
  end

  defp ensure do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: true
      ])
    end
  end
end

defmodule Exjabberd.Mod.PubSub.Leaf do
  @moduledoc "Leaf node - `node_flat` / `node_hometree` leaf, stabil. Delegates ke `PubSub` core."

  @behaviour Exjabberd.Mod.PubSub.Node

  @impl true
  def init(_host, _node, _opts), do: {:ok, %{}}

  @impl true
  def create_node(host, node, opts), do: Exjabberd.Mod.PubSub.create_node(host, node, opts)

  @impl true
  def delete_node(host, node), do: Exjabberd.Mod.PubSub.delete_node(host, node)

  @impl true
  def publish_item(host, node, id, payload, publisher \\ nil),
    do: Exjabberd.Mod.PubSub.publish(host, node, id, payload, publisher: publisher)

  @impl true
  def delete_item(host, node, id), do: Exjabberd.Mod.PubSub.delete_item(host, node, id)

  @impl true
  def get_items(host, node, opts \\ []),
    do: Exjabberd.Mod.PubSub.get_items(host, node, opts)

  @impl true
  def get_subscribers(host, node) do
    {:ok, Exjabberd.Mod.PubSub.get_subscribers(host, node)}
  end

  @impl true
  def get_affiliation(host, node, jid), do: Exjabberd.Mod.PubSub.get_affiliation(host, node, jid)

  @impl true
  def set_affiliation(host, node, jid, aff),
    do: Exjabberd.Mod.PubSub.set_affiliation(host, node, jid, aff)
end

defmodule Exjabberd.Mod.PubSub.Collection do
  @moduledoc "Collection node - `node_collection` stabil. Tidak bisa publish, hanya subscribe + get_nodes."

  @behaviour Exjabberd.Mod.PubSub.Node

  @impl true
  def init(_host, _node, _opts), do: {:ok, %{}}

  @impl true
  def create_node(host, node, opts),
    do: Exjabberd.Mod.PubSub.create_node(host, node, Keyword.put(opts, :type, "collection"))

  @impl true
  def delete_node(host, node), do: Exjabberd.Mod.PubSub.delete_node(host, node)

  @impl true
  def publish_item(_host, _node, _id, _payload, _publisher \\ nil), do: {:error, :not_supported}

  @impl true
  def delete_item(_host, _node, _id), do: {:error, :not_supported}

  @impl true
  def get_items(host, node, _opts \\ []),
    do:
      {:ok, Exjabberd.Mod.PubSub.Nodetree.get_nodes(host, node) |> Enum.map(&%{id: &1}),
       %{count: 0}}

  @impl true
  def get_subscribers(_host, _node), do: {:ok, []}

  @impl true
  def get_affiliation(_host, _node, _jid), do: :none

  @impl true
  def set_affiliation(_host, _node, _jid, _aff), do: :ok
end
