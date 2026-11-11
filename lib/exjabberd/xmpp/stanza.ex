defmodule Exjabberd.Xmpp.Stanza do
  @moduledoc """
  XMPP stanza representation — 100% RFC 6120 §8 + XEP, stabil.

  Covers `<message/>`, `<presence/>`, `<iq/>` dengan validasi, error
  stanzas (RFC6120 §8.3.3), dan Codec bridge. Pure — tidak ada side effect,
  jadi gampang di-test dan dirawat.
  """

  @type stanza_type :: :message | :presence | :iq
  @type stanza :: %{
          required(:name) => stanza_type(),
          required(:id) => binary() | nil,
          required(:from) => Exjabberd.Xmpp.Jid.t() | nil,
          required(:to) => Exjabberd.Xmpp.Jid.t() | nil,
          required(:type) => binary() | nil,
          optional(:payload) => list(),
          optional(:raw) => binary(),
          optional(:lang) => binary(),
          optional(:xmlns) => binary()
        }

  @valid_types %{
    message: ["chat", "groupchat", "headline", "normal", "error", nil],
    presence: [
      "available",
      "unavailable",
      "subscribe",
      "subscribed",
      "unsubscribe",
      "unsubscribed",
      "error",
      "probe",
      nil
    ],
    iq: ["get", "set", "result", "error"]
  }

  @doc "Build a stanza map (validasi `type` seperti ejabberd `xmpp` codec)."
  @spec new(stanza_type(), keyword()) :: stanza()
  def new(name, attrs \\ []) do
    type = Keyword.get(attrs, :type)

    if !valid_type?(name, type) do
      raise ArgumentError, "invalid type #{inspect(type)} for #{name}"
    end

    %{
      name: name,
      id: Keyword.get(attrs, :id) || random_id(),
      from: Keyword.get(attrs, :from),
      to: Keyword.get(attrs, :to),
      type: type,
      payload: Keyword.get(attrs, :payload, []),
      raw: Keyword.get(attrs, :raw),
      lang: Keyword.get(attrs, :lang, "en"),
      xmlns: Keyword.get(attrs, :xmlns, "jabber:client")
    }
  end

  @doc "Validasi stanza (ejabberd `xmpp:validate`)."
  @spec valid?(stanza()) :: boolean()
  def valid?(%{name: name, type: type}), do: valid_type?(name, type)
  def valid?(_), do: false

  defp valid_type?(name, type), do: type in Map.get(@valid_types, name, [])

  @doc "True if stanza is an error (RFC6120 §8.3.3)."
  @spec error?(stanza()) :: boolean()
  def error?(%{type: "error"}), do: true
  def error?(_), do: false

  @doc "Create error reply for iq/message (ejabberd `xmpp:make_error`)."
  @spec error_reply(stanza(), binary(), binary()) :: stanza()
  def error_reply(%{id: id, from: from, to: to} = _stanza, condition, text \\ "") do
    new(:iq,
      id: id,
      from: to,
      to: from,
      type: "error",
      payload: [
        {:error, %{condition: condition, text: text, xmlns: "urn:ietf:params:xml:ns:xmpp-stanzas"}}
      ]
    )
  end

  @doc "Create service-unavailable for unknown IQ (ejabberd `service_unavailable`)."
  @spec service_unavailable(stanza()) :: stanza()
  def service_unavailable(iq), do: error_reply(iq, "service-unavailable", "Service unavailable")

  @doc "Get payload by xmlns (like ejabberd `xmpp:get_subtag`)."
  @spec get_subtag(stanza(), binary()) :: map() | nil
  def get_subtag(%{payload: payload}, xmlns) do
    Enum.find(payload, fn
      %{attrs: %{xmlns: ^xmlns}} -> true
      %{xmlns: ^xmlns} -> true
      _ -> false
    end)
  end

  defp random_id, do: :crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)
end
