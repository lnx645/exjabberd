defmodule Exjabberd.Mod.Adhoc.Full do
  @moduledoc """
  Ad-Hoc Commands — XEP-0050, the real protocol flow.

  Handles IQ `set` with a `<command xmlns='http://jabber.org/protocol/commands'>`
  element: actions `execute` / `next` / `prev` / `complete` / `cancel`,
  server-issued `sessionid`s for multi-step commands, and `jabber:x:data`
  forms both ways — the same flow ejabberd's `mod_adhoc` speaks.

  Commands are registered in `Exjabberd.Mod.Adhoc`'s registry. This
  module registers two commands backed by live server state:

    * `http://jabber.org/protocol/admin#get-online-users` — completes
      immediately with a result form listing the online users
      (`jid-multi`), like `mod_admin_extra`.
    * `http://jabber.org/protocol/admin#announce` — two-step: the
      first `execute` returns a form (subject + message); `complete`
      with the submitted form sends the announcement as a headline
      message from the server to every online user.
  """

  use Exjabberd.Mod.GenMod
  use GenServer

  require Logger

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @ns "http://jabber.org/protocol/commands"
  @data_ns "jabber:x:data"
  @sessions :exjabberd_adhoc_sessions

  @cmd_online_users "http://jabber.org/protocol/admin#get-online-users"
  @cmd_announce "http://jabber.org/protocol/admin#announce"

  @impl true
  def start(host, _opts) do
    ensure_sessions()
    Exjabberd.Mod.Adhoc.start(host, [])
    Exjabberd.Mod.Adhoc.register_command(host, @cmd_online_users, "Get online users", __MODULE__, :cmd_online_users)
    Exjabberd.Mod.Adhoc.register_command(host, @cmd_announce, "Announce to online users", __MODULE__, :cmd_announce)
    Exjabberd.Iq.register(host, @ns, __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @ns, :both)
    :ok
  end

  def start_link(_), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  @impl true
  def init(state) do
    ensure_sessions()
    {:ok, state}
  end

  defp ensure_sessions do
    if :ets.whereis(@sessions) == :undefined do
      :ets.new(@sessions, [:named_table, :public, :set])
    end
  end

  # ------------------------------------------------------------------
  # IQ handling
  # ------------------------------------------------------------------

  @doc "Handle an ad-hoc command IQ (XEP-0050)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "set"} = iq, host) do
    case Stanza.child(iq.payload, "command") do
      nil ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      cmd_el ->
        node = Stanza.child_attr(cmd_el, "node")
        action = Stanza.child_attr(cmd_el, "action") || "execute"
        sessionid = Stanza.child_attr(cmd_el, "sessionid")
        fields = parse_fields(cmd_el)

        cond do
          is_nil(node) or node == "" ->
            {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

          action == "cancel" ->
            if sessionid, do: :ets.delete(@sessions, sessionid)
            {:ok, reply(iq, node, sessionid, "canceled", [])}

          action in ["execute", "next", "prev", "complete"] ->
            run_command(iq, host, node, action, sessionid, fields)

          true ->
            {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
        end
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  # A `complete` (or a follow-up step) must reference a live session;
  # a first `execute` starts one when the command needs more input.
  defp run_command(iq, host, node, action, sessionid, fields) do
    cond do
      action == "complete" and (is_nil(sessionid) or not session?(sessionid, node)) ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      action in ["next", "prev"] and (is_nil(sessionid) or not session?(sessionid, node)) ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      true ->
        case Exjabberd.Mod.Adhoc.execute(host, node, [host, iq, sessionid, fields]) do
          {:completed, children} ->
            if sessionid, do: :ets.delete(@sessions, sessionid)
            {:ok, reply(iq, node, sessionid, "completed", children)}

          {:form, children} ->
            sid = sessionid || new_session(node, iq)
            {:ok, reply(iq, node, sid, "executing", children)}

          {:error, :item_not_found} ->
            {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}

          {:error, :bad_request} ->
            {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

          other ->
            Logger.warning("adhoc command #{node} returned #{inspect(other)}")
            {:error, :internal, Exjabberd.Iq.error_iq(iq, "internal-server-error")}
        end
    end
  end

  defp session?(sessionid, node) do
    ensure_sessions()

    case :ets.lookup(@sessions, sessionid) do
      [{_, %{node: ^node}}] -> true
      _ -> false
    end
  end

  defp new_session(node, iq) do
    ensure_sessions()
    sid = :crypto.strong_rand_bytes(12) |> Base.encode16(case: :lower)

    :ets.insert(@sessions, {sid, %{node: node, from: bare_of(iq.from), created: System.system_time(:second)}})
    sid
  end

  defp reply(iq, node, sessionid, status, children) do
    attrs =
      %{"xmlns" => @ns, "node" => node, "status" => status}
      |> then(fn a -> if sessionid, do: Map.put(a, "sessionid", sessionid), else: a end)

    %{iq | type: "result", payload: [%{name: "command", attrs: attrs, children: children}]}
  end

  # Parse a submitted `jabber:x:data` form into %{var => [values]}.
  defp parse_fields(cmd_el) do
    case Stanza.child(cmd_el.children, "x") do
      nil ->
        %{}

      x_el ->
        x_el.children
        |> Enum.filter(&match?(%{name: "field"}, &1))
        |> Map.new(fn field ->
          var = Stanza.child_attr(field, "var") || ""

          values =
            field.children
            |> Enum.filter(&match?(%{name: "value"}, &1))
            |> Enum.map(&Stanza.text_of/1)

          {var, values}
        end)
    end
  end

  defp bare_of(%Jid{} = jid), do: Jid.bare(jid)
  defp bare_of(bin) when is_binary(bin), do: bin |> String.split("/") |> hd()
  defp bare_of(_), do: nil

  # ------------------------------------------------------------------
  # Commands
  # ------------------------------------------------------------------

  @doc false
  def cmd_online_users(_host, _iq, _sessionid, _fields) do
    users =
      Exjabberd.SessionManager.all_sessions()
      |> Enum.map(fn {bare, resource, _pid} -> "#{bare}/#{resource}" end)
      |> Enum.uniq()
      |> Enum.sort()

    x = %{
      name: "x",
      attrs: %{"xmlns" => @data_ns, "type" => "result"},
      children: [
        %{name: "title", attrs: %{}, children: ["Online users"]},
        %{
          name: "field",
          attrs: %{"var" => "online_users", "type" => "jid-multi", "label" => "Online users"},
          children: Enum.map(users, &%{name: "value", attrs: %{}, children: [&1]})
        }
      ]
    }

    {:completed, [x]}
  end

  @doc false
  def cmd_announce(host, _iq, sessionid, fields) do
    if is_nil(sessionid) do
      # Step 1: ask for subject + body.
      x = %{
        name: "x",
        attrs: %{"xmlns" => @data_ns, "type" => "form"},
        children: [
          %{name: "title", attrs: %{}, children: ["Announce to online users"]},
          %{name: "instructions", attrs: %{}, children: ["Fill in the announcement to send to all online users."]},
          %{
            name: "field",
            attrs: %{"var" => "subject", "type" => "text-single", "label" => "Subject"},
            children: [%{name: "required", attrs: %{}, children: []}]
          },
          %{
            name: "field",
            attrs: %{"var" => "body", "type" => "text-multi", "label" => "Message"},
            children: [%{name: "required", attrs: %{}, children: []}]
          }
        ]
      }

      {:form, [x]}
    else
      subject = fields |> Map.get("subject", []) |> List.first() || ""
      body = fields |> Map.get("body", []) |> Enum.join("\n")

      if body == "" do
        {:error, :bad_request}
      else
        announce(host, subject, body)
        {:completed, []}
      end
    end
  end

  defp announce(host, subject, body) do
    payload =
      if subject != "" do
        [%{name: "subject", attrs: %{}, children: [subject]}]
      else
        []
      end ++ [%{name: "body", attrs: %{}, children: [body]}]

    Exjabberd.SessionManager.all_sessions()
    |> Enum.map(fn {bare, _res, _pid} -> bare end)
    |> Enum.uniq()
    |> Enum.each(fn bare ->
      stanza =
        Exjabberd.Xmpp.Stanza.new(:message,
          from: host,
          to: bare,
          type: "headline",
          payload: payload
        )

      Exjabberd.Router.route(stanza)
    end)

    :ok
  end
end
