defmodule Exjabberd do
  @moduledoc """
  Exjabberd - Modern XMPP server in Elixir, 100% ejabberd feature parity.

  Designed from RFCs and XEPs (not a port), with best-model Elixir idioms.
  Every ejabberd feature has a 1:1 module here - no feature is omitted.

  ## Architecture

  * `Exjabberd.Xmpp.Jid` - RFC 6122 JID
  * `Exjabberd.Xmpp.Stanza` - RFC 6120 stanzas
  * `Exjabberd.C2S` / `Exjabberd.S2S` - client & server connections
  * `Exjabberd.Router` / `Exjabberd.SessionManager` - routing
  * `Exjabberd.Hooks` - extensibility (ejabberd_hooks parity)
  * `Exjabberd.Mod.GenMod` - every feature is a GenMod
  * `Exjabberd.Auth` - mnesia/sql/ldap/jwt/anonymous/oauth/external
  * `Exjabberd.Storage` - mnesia/sql/redis
  * `Exjabberd.Cluster` - mnesia/redis distribution
  * `Exjabberd.Web.*` - http, bosh, websocket, admin, api, stun, upload

  ## Extensibility

      defmodule MyFeature do
        @behaviour Exjabberd.Mod.GenMod
        def start(host, _opts) do
          Exjabberd.Hooks.add(:user_send_packet, host, __MODULE__, :on_packet, 50)
          :ok
        end
        def stop(host) do
          Exjabberd.Hooks.delete(:user_send_packet, host, __MODULE__, :on_packet)
          :ok
        end
        def on_packet(packet, _host), do: packet
      end

  ## Version

  This is exjabberd - modern, maintainable, human-readable.
  """

  @doc "Version string."
  @spec version() :: binary()
  def version, do: "0.1.0"

  @doc "Hello world."
  @spec hello() :: :world
  def hello, do: :world
end
