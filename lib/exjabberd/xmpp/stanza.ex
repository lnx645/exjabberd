defmodule Exjabberd.Xmpp.Stanza do
  @moduledoc """
  XMPP stanza representation — RFC 6120 §8 + XEP (partial implementation), stabil.

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

  @doc "Create error reply for iq/message/presence (ejabberd `xmpp:make_error`). Keeps the stanza type: a message error is a message, not an IQ."
  @spec error_reply(stanza(), binary(), binary()) :: stanza()
  def error_reply(%{name: name, id: id, from: from, to: to} = _stanza, condition, text \\ "") do
    error_children = [
      %{name: condition, attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-stanzas"}, children: []}
    ]

    error_children =
      if text != "" do
        error_children ++
          [
            %{
              name: "text",
              attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-stanzas"},
              children: [text]
            }
          ]
      else
        error_children
      end

    new(name,
      id: id,
      from: to,
      to: from,
      type: "error",
      payload: [%{name: "error", attrs: %{"type" => "cancel"}, children: error_children}]
    )
  end

  @doc "Create service-unavailable for unknown IQ (ejabberd `service_unavailable`)."
  @spec service_unavailable(stanza()) :: stanza()
  def service_unavailable(iq), do: error_reply(iq, "service-unavailable", "Service unavailable")

  @doc "Get payload by xmlns (like ejabberd `xmpp:get_subtag`)."
  @spec get_subtag(stanza(), binary()) :: map() | nil
  def get_subtag(%{payload: payload}, xmlns) do
    Enum.find(payload, fn
      # Decoded elements carry string keys in attrs (Codec.decode);
      # hand-built payloads may use the atom key instead.
      %{attrs: attrs} when is_map(attrs) ->
        Map.get(attrs, "xmlns") == xmlns or Map.get(attrs, :xmlns) == xmlns

      %{xmlns: ^xmlns} ->
        true

      _ ->
        false
    end)
  end

  @doc "First child element of a payload with the given tag name."
  @spec child([map()], binary()) :: map() | nil
  def child(payload, name) when is_list(payload) do
    Enum.find(payload, fn
      %{name: ^name} -> true
      _ -> false
    end)
  end

  @doc "Attribute of a child element, or nil."
  @spec child_attr(map() | nil, binary()) :: binary() | nil
  def child_attr(nil, _attr), do: nil
  def child_attr(%{attrs: attrs}, attr) when is_map(attrs), do: Map.get(attrs, attr)
  def child_attr(_, _), do: nil

  @doc "Text content of a child element (concatenated text children), or nil."
  @spec child_text(map() | nil, binary()) :: binary() | nil
  def child_text(nil, _name), do: nil

  def child_text(payload, name) when is_list(payload) do
    case child(payload, name) do
      nil -> nil
      el -> text_of(el)
    end
  end

  @doc "Text content of an element (concatenated text children)."
  @spec text_of(map()) :: binary()
  def text_of(%{children: children}) when is_list(children) do
    children
    |> Enum.filter(&is_binary/1)
    |> Enum.join("")
  end

  def text_of(_), do: ""

  defp random_id, do: :crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)
end
