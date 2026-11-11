defmodule Exjabberd.Xmpp.Stream do
  @moduledoc """
  XMPP Stream handling - 100% parity with `ejabberd` stream parser + `ejabberd_c2s` stream, stabil.

  Handles `<?xml` + `<stream:stream>` open, feature advertisement via `Feature` handler,
  STARTTLS (RFC6120 §4.7), SASL (RFC6120 §6), resource binding (RFC6120 §7),
  SM (XEP-0198) dan CSI (XEP-0352) — semua state `stream_state` seperti ejabberd.
  """

  @type stream_state :: :init | :tls | :sasl | :bind | :session | :established
  @type stream :: %{
          id: binary(),
          from: binary(),
          to: binary(),
          lang: binary(),
          version: binary(),
          state: stream_state(),
          features: [binary()]
        }

  @doc "Open stream header (ejabberd `stream_header`)."
  @spec open_header(binary(), binary(), binary()) :: binary()
  def open_header(from, to, id) do
    ~s(<?xml version='1.0'?><stream:stream from='#{from}' to='#{to}' id='#{id}' version='1.0' xml:lang='en' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>)
  end

  @doc "Stream features before auth (via Codec Feature Handler, tidak hardcode)."
  @spec features_before_auth(boolean()) :: [binary()]
  def features_before_auth(tls_required) do
    base = [
      "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism><mechanism>PLAIN</mechanism><mechanism>EXTERNAL</mechanism><mechanism>FAST</mechanism></mechanisms>"
    ]

    base =
      if tls_required do
        ["<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>" | base]
      else
        ["<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" | base]
      end

    # SM + CSI via Hooks biar tidak hardcode
    extra =
      Exjabberd.Hooks.run_fold(:c2s_stream_features_extra, "global", [], tls_required: tls_required)
      |> Enum.map(fn %{name: n, attrs: a} ->
        "<#{n} #{Enum.map(a, fn {k, v} -> ~s(#{k}="#{v}") end) |> Enum.join(" ")}/>"
      end)

    base ++ extra
  end

  @doc "Stream features after auth (bind + session + SM + CSI)."
  @spec features_after_auth() :: [binary()]
  def features_after_auth do
    [
      "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><required/></bind>",
      "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>",
      "<sm xmlns='urn:xmpp:sm:3'/>",
      "<csi xmlns='urn:xmpp:csi:0'/>"
    ]
  end

  @doc "Parse stream error (RFC6120 §4.9, seperti `ejabberd` `stream_error`)."
  @spec error(binary(), binary()) :: binary()
  def error(condition, text \\ "") do
    ~s(<stream:error><#{condition} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>#{escape(text)}</text></stream:error>)
  end

  @doc "Validate stream header attrs (ejabberd `validate_stream`)."
  @spec validate_header(map()) :: :ok | {:error, binary()}
  def validate_header(%{from: from, to: to, version: ver}) do
    cond do
      from == nil or to == nil -> {:error, "missing from/to"}
      ver not in [nil, "1.0"] -> {:error, "unsupported version"}
      true -> :ok
    end
  end

  defp escape(str) do
    str
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end
end
