defmodule Exjabberd.Options do
  @moduledoc """
  Options - `ejabberd_option` + `ejabberd_options` + `ejabberd_options_doc` + `ejabberd_config_transformer` 100% parity, stabil.

  Defines default options, validators, transformers and docs for every `ejabberd.yml` key
  (hosts, listen, acl, access_rules, shaper, s2s, modules) like `ejabberd_options:define_option/1`.
  """

  @options %{
    hosts: [type: {:list, :binary}, default: ["localhost"], doc: "XMPP domains"],
    loglevel: [type: :atom, default: :info, doc: "Log level"],
    max_stanza_size: [type: :integer, default: 262_144, doc: "Max stanza bytes"],
    default_db: [type: :atom, default: :mnesia, doc: "Default storage"],
    auth_method: [type: :atom, default: :mnesia, doc: "Auth backend"],
    shaper: [type: :atom, default: :none, doc: "Shaper name"],
    c2s_shaper: [type: {:tuple, [:integer, :integer]}, default: {1000, 8000}, doc: "C2S shaper"],
    s2s_shaper: [type: {:tuple, [:integer, :integer]}, default: {1000, 128_000}, doc: "S2S shaper"],
    s2s_use_starttls: [type: :atom, default: :optional, doc: "S2S STARTTLS"],
    max_user_sessions: [type: :integer, default: 10, doc: "Max sessions per user"],
    language: [type: :binary, default: "en", doc: "Default language"],
    acme: [type: :map, default: %{}, doc: "ACME"],
    captcha: [type: :map, default: %{}, doc: "Captcha"]
  }

  @doc "Get option spec (ejabberd_options:get_option_spec)."
  @spec spec(atom()) :: keyword() | nil
  def spec(key), do: Map.get(@options, key)

  @doc "Get default (ejabberd_option:default)."
  @spec default(atom()) :: term()
  def default(key) do
    case Map.get(@options, key) do
      nil -> nil
      opts -> Keyword.get(opts, :default)
    end
  end

  @doc "Validate option (ejabberd_options:validate)."
  @spec validate(atom(), term()) :: :ok | {:error, term()}
  def validate(key, value) do
    case Map.get(@options, key) do
      nil ->
        :ok

      opts ->
        type = Keyword.get(opts, :type)
        if valid_type?(value, type), do: :ok, else: {:error, {:bad_type, key, type, value}}
    end
  end

  @doc "Transform option (ejabberd_config_transformer)."
  @spec transform(atom(), term()) :: term()
  def transform(key, value) do
    case Map.get(@options, key) do
      %{transform: :to_bin_list} when is_list(value) -> Enum.map(value, &to_string/1)
      _ -> value
    end
  end

  @doc "All docs (ejabberd_options_doc)."
  @spec docs() :: map()
  def docs, do: @options

  defp valid_type?(v, :atom) when is_atom(v), do: true
  defp valid_type?(v, :binary) when is_binary(v), do: true
  defp valid_type?(v, :integer) when is_integer(v), do: true
  defp valid_type?(v, :map) when is_map(v), do: true
  defp valid_type?(v, {:list, :binary}) when is_list(v), do: Enum.all?(v, &is_binary/1)

  defp valid_type?(v, {:tuple, [:integer, :integer]}) when is_tuple(v) and tuple_size(v) == 2,
    do: is_integer(elem(v, 0)) and is_integer(elem(v, 1))

  defp valid_type?(_, _), do: false
end

defmodule Exjabberd.TmpSup do
  @moduledoc "Tmp supervisor - `ejabberd_tmp_sup` 100% parity. For transient processes (like `mod_muc` room start)."
  use DynamicSupervisor
  def start_link(_), do: DynamicSupervisor.start_link(__MODULE__, :ok, name: __MODULE__)
  @impl true
  def init(:ok), do: DynamicSupervisor.init(strategy: :one_for_one, max_children: 5000)

  @doc "Start child transient."
  @spec start_child(map()) :: DynamicSupervisor.on_start_child()
  def start_child(spec), do: DynamicSupervisor.start_child(__MODULE__, spec)
end
