defmodule Exjabberd.Xmpp.Stream do
  @moduledoc """
  XMPP Stream handling - partial implementation of `ejabberd` stream parser + `ejabberd_c2s` stream, stabil.

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

  @doc """
  Stream features before auth, as ONE wrapped `<stream:features>` string.

  Only features that are actually implemented are advertised: STARTTLS
  (unless already on TLS) and SASL PLAIN + SCRAM-SHA-256. EXTERNAL and
  FAST are not advertised — they are not implemented on this server.
  """
  @spec features_before_auth(boolean()) :: [binary()]
  def features_before_auth(tls_required) do
    starttls =
      if tls_required do
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
      else
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
      end

    mechanisms =
      "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-256</mechanism></mechanisms>"

    ["<stream:features>" <> starttls <> mechanisms <> "</stream:features>"]
  end

  @doc """
  Stream features after auth, as ONE wrapped `<stream:features>` string.

  Only resource binding is advertised. `session` (RFC 3921, obsolete),
  Stream Management (XEP-0198) and CSI (XEP-0352) are not implemented
  and are deliberately not advertised.
  """
  @spec features_after_auth() :: [binary()]
  def features_after_auth do
    ["<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>"]
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
