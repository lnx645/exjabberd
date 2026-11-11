defmodule Exjabberd do
  @moduledoc """
  Exjabberd - XMPP server in Elixir, partial ejabberd feature compatibility.

  Designed from RFCs and XEPs (not a port), with best-model Elixir idioms.
  It implements the core of ejabberd's C2S path; many ejabberd features
  are partial implementations or not implemented at all. See README.md
  for the verified feature list - no module in this codebase claims
  full ejabberd parity.

  ## Architecture

  * `Exjabberd.Xmpp.Jid` - RFC 6122 JID
  * `Exjabberd.Xmpp.Stanza` - RFC 6120 stanzas
  * `Exjabberd.C2S` / `Exjabberd.S2S` - client & server connections
    (S2S is a stub: no second server, no federation)
  * `Exjabberd.Router` / `Exjabberd.SessionManager` - routing
  * `Exjabberd.Hooks` - extensibility (ejabberd_hooks compatible)
  * `Exjabberd.Mod.GenMod` - every feature is a GenMod
  * `Exjabberd.Auth` - Mnesia backend is real (SCRAM credentials);
    SQL/LDAP/JWT/anonymous/OAuth/external backends are stubs
  * `Exjabberd.Cluster` - single node only; clustering is not wired up

  There is no HTTP stack (no Plug/Cowboy/Bandit/Phoenix): no web admin,
  BOSH, WebSocket, file upload, STUN/TURN or MQTT listener exists yet.
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
