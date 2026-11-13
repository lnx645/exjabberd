defmodule Exjabberd.Mod.Push do
  @moduledoc """
  Push Notifications — XEP-0357 (`mod_push`).

  Mobile clients register an app-server push service with their
  account:

      <iq type='set' to='<server domain>'>
        <enable xmlns='urn:xmpp:push:0' jid='<push service JID>'
                node='<node on that service>'>
          [<options><x xmlns='jabber:x:data' type='submit'>…</x></options>]
        </enable>
      </iq>

  and remove it with the matching `<disable/>`. When a chat
  message for the user is about to be stored offline (the
  `:offline_message` hook, priority 30 — just before
  `mod_offline` stores it at 40), the server publishes a
  `<notification xmlns='urn:xmpp:push:0'/>` item to every
  registered (service, node) pair: the item carries the summary
  data form of XEP-0357 §4 (`message-count` including the new
  message, `last-message-sender`, `last-message-body`), and any
  `<options/>` fields from the enable are passed through as a
  second form (`urn:xmpp:push:options`), as the XEP intends them
  for the push service. The publish is sent from the user's own
  bare JID, so on the push service the user is the node owner —
  exactly the XEP's trust shape.

  Guards (XEP-0357 §4 + ejabberd behaviour): only `chat`/`normal`
  messages with a `<body/>` notify; a `<no-store/>` hint
  (urn:xmpp:hints) suppresses the notification; error messages
  and messages from the push service itself never trigger one.

  Storage: registrations live in an ETS table — node-local and
  lost on restart. That is a deliberate, documented limit
  (ejabberd persists them); clients re-enable on login, which is
  what real mobile clients do anyway.

  NOT implemented: push for MUC (ejabberd's mod_push_muc),
  mod_push_keepalive, and the "push only when no session is
  active" refinements beyond the offline trigger.
  """

  use Exjabberd.Mod.GenMod
  require Logger

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @ns "urn:xmpp:push:0"
  @table :exjabberd_push_registrations

  @impl true
  def start(host, _opts) do
    ensure_table()
    Exjabberd.Iq.register(host, @ns, __MODULE__, :handle_push_iq, type: :set)
    Exjabberd.Hooks.add(:offline_message, host, __MODULE__, :on_offline_message, 30)
    Logger.info("mod_push started for #{host} (XEP-0357)")
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @ns, :set)
    Exjabberd.Hooks.delete(:offline_message, host, __MODULE__, :on_offline_message)
    :ok
  end

  # --- registration store ---

  @doc "All push registrations of a user: [%{service, node, options}]."
  @spec registrations(binary()) :: [map()]
  def registrations(bare) when is_binary(bare) do
    ensure_table()

    case :ets.lookup(@table, bare) do
      [{^bare, regs}] -> regs
      [] -> []
    end
  end

  @doc "Add (or replace) one registration for a user."
  @spec register(binary(), binary(), binary(), map()) :: :ok
  def register(bare, service, node, options \\ %{})
      when is_binary(bare) and is_binary(service) and is_binary(node) do
    ensure_table()
    reg = %{service: service, node: node, options: options}

    regs =
      Enum.reject(registrations(bare), fn r ->
        r.service == service and r.node == node
      end)

    :ets.insert(@table, {bare, regs ++ [reg]})
    :ok
  end

  @doc """
  Remove registrations of a user: one (service, node) pair, or
  all of them when both are nil (XEP-0357 `<disable/>` semantics).
  """
  @spec unregister(binary(), binary() | nil, binary() | nil) :: :ok
  def unregister(bare, service \\ nil, node \\ nil) do
    ensure_table()

    if service == nil and node == nil do
      :ets.delete(@table, bare)
    else
      regs =
        Enum.reject(registrations(bare), fn r ->
          (service == nil or r.service == service) and (node == nil or r.node == node)
        end)

      if regs == [], do: :ets.delete(@table, bare), else: :ets.insert(@table, {bare, regs})
    end

    :ok
  end

  # --- <enable/> / <disable/> IQ handling ---

  @doc false
  def handle_push_iq(%{payload: payload} = iq, _host) do
    el = Enum.find(payload, fn e -> is_map(e) and e.name in ["enable", "disable"] end)
    bare = bare_from(iq)

    cond do
      el == nil ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      bare in [nil, ""] ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      el.name == "enable" ->
        service = el.attrs["jid"]
        node = el.attrs["node"]

        if is_binary(service) and service != "" and is_binary(node) and node != "" do
          register(bare, service, node, options_from(el))
          {:ok, %{iq | type: "result", payload: []}}
        else
          {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
        end

      el.name == "disable" ->
        unregister(bare, el.attrs["jid"], el.attrs["node"])
        {:ok, %{iq | type: "result", payload: []}}
    end
  end

  # --- the offline trigger ---

  @doc false
  def on_offline_message(%{name: :message} = stanza, host) do
    notify(stanza, host)
    stanza
  end

  def on_offline_message(stanza, _host), do: stanza

  @doc """
  Publish a notification for `stanza` to every push registration
  of its recipient, when the stanza is notifiable. Returns the
  number of publishes sent. (Called by the hook; also the unit
  tests' entry point.)
  """
  @spec notify(map(), binary()) :: non_neg_integer()
  def notify(%{name: :message} = stanza, host) do
    with true <- notifiable?(stanza),
         bare when is_binary(bare) <- bare_to(stanza),
         regs when regs != [] <- registrations(bare),
         true <- local_user?(host, bare) do
      count = Exjabberd.Mod.Offline.count(bare) + 1
      sender = bare_from_stanza(stanza)
      body = body_text(stanza)

      Enum.each(regs, fn reg ->
        if sender_domain(sender) != reg.service do
          Exjabberd.Router.route(publish_iq(bare, reg, count, sender, body))
        end
      end)

      length(regs)
    else
      _ -> 0
    end
  end

  def notify(_stanza, _host), do: 0

  @doc "The `<notification/>` publish IQ for one registration (pure builder)."
  @spec publish_iq(binary(), map(), pos_integer(), binary(), binary()) :: map()
  def publish_iq(bare, %{service: service, node: node, options: options}, count, sender, body) do
    summary =
      form("urn:xmpp:push:summary", [
        {"message-count", Integer.to_string(count)},
        {"last-message-sender", sender},
        {"last-message-body", body}
      ])

    forms =
      if map_size(options) > 0 do
        [summary, form("urn:xmpp:push:options", Map.to_list(options))]
      else
        [summary]
      end

    Stanza.new(:iq,
      from: bare,
      to: service,
      type: "set",
      payload: [
        %{
          name: "pubsub",
          attrs: %{"xmlns" => "http://jabber.org/protocol/pubsub"},
          children: [
            %{
              name: "publish",
              attrs: %{"node" => node},
              children: [
                %{
                  name: "item",
                  attrs: %{},
                  children: [
                    %{name: "notification", attrs: %{"xmlns" => @ns}, children: forms}
                  ]
                }
              ]
            }
          ]
        }
      ]
    )
  end

  # --- helpers ---

  defp notifiable?(stanza) do
    type = stanza.type

    (type in [nil, "chat", "normal"]) and body_text(stanza) != "" and
      not has_child?(stanza, "no-store")
  end

  defp has_child?(stanza, name) do
    Enum.any?(stanza.payload || [], fn
      %{name: ^name} -> true
      _ -> false
    end)
  end

  defp body_text(stanza) do
    Enum.find_value(stanza.payload || [], "", fn
      %{name: "body", children: children} ->
        children |> Enum.filter(&is_binary/1) |> Enum.join("")

      _ ->
        nil
    end) || ""
  end

  defp local_user?(host, bare) do
    user = bare |> String.split("@") |> hd()
    Exjabberd.Auth.user_exists(host, user)
  rescue
    _ -> false
  end

  defp sender_domain(sender) when is_binary(sender) do
    case Jid.parse(sender) do
      {:ok, %Jid{domain: domain}} -> domain
      _ -> nil
    end
  end

  defp sender_domain(_), do: nil

  defp bare_from_stanza(%{from: %Jid{} = jid}), do: Jid.bare(jid)
  defp bare_from_stanza(%{from: bin}) when is_binary(bin), do: Jid.bare(bin)
  defp bare_from_stanza(_), do: ""

  defp bare_to(%{to: %Jid{} = to}), do: Jid.bare(to)
  defp bare_to(%{to: to}) when is_binary(to), do: Jid.bare(to)
  defp bare_to(_), do: nil

  defp bare_from(iq) do
    case iq.from do
      %Jid{} = jid -> Jid.bare(jid)
      bin when is_binary(bin) -> Jid.bare(bin)
      _ -> nil
    end
  end

  # The <options> child of <enable/> holds one data form; keep its
  # fields (except FORM_TYPE) as a flat map for the pass-through.
  defp options_from(el) do
    form_el =
      el.children
      |> Enum.filter(&is_map/1)
      |> Enum.find(fn e -> e.name == "options" end)
      |> case do
        nil -> nil
        options -> Enum.find(options.children || [], fn e -> is_map(e) and e.name == "x" end)
      end

    case form_el do
      nil ->
        %{}

      x ->
        x.children
        |> Enum.filter(fn e -> is_map(e) and e.name == "field" end)
        |> Enum.reject(fn f -> f.attrs["var"] == "FORM_TYPE" end)
        |> Map.new(fn f ->
          value =
            f.children
            |> Enum.filter(fn e -> is_map(e) and e.name == "value" end)
            |> Enum.flat_map(fn v -> Enum.filter(v.children || [], &is_binary/1) end)
            |> Enum.join("")

          {f.attrs["var"], value}
        end)
    end
  end

  defp form(form_type, fields) do
    field_els =
      [
        %{
          name: "field",
          attrs: %{"var" => "FORM_TYPE", "type" => "hidden"},
          children: [%{name: "value", attrs: %{}, children: [form_type]}]
        }
      ] ++
        Enum.map(fields, fn {var, value} ->
          %{
            name: "field",
            attrs: %{"var" => var},
            children: [%{name: "value", attrs: %{}, children: [value]}]
          }
        end)

    %{name: "x", attrs: %{"xmlns" => "jabber:x:data", "type" => "submit"}, children: field_els}
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      try do
        :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
      rescue
        ArgumentError -> :ok
      end
    end

    :ok
  end
end
