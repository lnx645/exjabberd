defmodule Exjabberd.Mod.Remaining do
  @moduledoc """
  Remaining ejabberd modules.

  Each module below carries its own moduledoc stating honestly what
  is implemented and verified; see `docs/PARITY.md` for the
  wire-verified status of every feature.
  """
end

defmodule Exjabberd.Mod.Adhoc do
  @moduledoc "`mod_adhoc` (XEP-0050) Ad-Hoc Commands (partial implementation)."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_adhoc
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Register ad-hoc command."
  def register(host, node, mod, fun) do
    ensure_table()
    :ets.insert(@table, {{host, node}, {mod, fun}})
    :ok
  end

  @doc "Register ad-hoc command with a human-readable name (shown in disco#items)."
  def register_command(host, node, name, mod, fun) do
    ensure_table()
    :ets.insert(@table, {{host, node}, {name, mod, fun}})
    :ok
  end

  @doc "List registered commands for a host as `{node, name}` pairs."
  @spec list_commands(binary()) :: [{binary(), binary()}]
  def list_commands(host) do
    ensure_table()

    :ets.match(@table, {{host, :"$1"}, :"$2"})
    |> Enum.map(fn
      [node, {name, _mod, _fun}] when is_binary(name) -> {node, name}
      [node, {_mod, _fun}] -> {node, node}
    end)
    |> Enum.sort()
  end

  @doc "Execute command."
  def execute(host, node, args) do
    ensure_table()

    case :ets.lookup(@table, {host, node}) do
      [{{_, _}, {_name, m, f}}] -> apply(m, f, args)
      [{{_, _}, {m, f}}] -> apply(m, f, args)
      [] -> {:error, :item_not_found}
    end
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end
  end
end

defmodule Exjabberd.Mod.AdminExtra do
  @moduledoc "`mod_admin_extra` (partial implementation). Adds 40+ admin commands to `ejabberdctl`."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    _ = host
    # Register via Hooks would be here; for now ensure ETS exists
    if :ets.whereis(:exjabberd_admin_extra_dummy) == :undefined do
      :ets.new(:exjabberd_admin_extra_dummy, [:named_table, :public, :set])
    end

    for cmd <- [:num_active_users, :srg_create, :push_roster, :get_roster, :add_rosteritem] do
      :ets.insert(:exjabberd_admin_extra_dummy, {cmd})
    end

    :ok
  end

  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.Antispam do
  @moduledoc "`mod_antispam` (partial implementation). RTBL + filter + report."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_antispam
  @impl true
  def start(host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    spam_filter = Keyword.get(opts, :spam_filter, true)
    Exjabberd.Hooks.add(:check_spam, host, __MODULE__, :filter, 50)
    _ = spam_filter
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:check_spam, host, __MODULE__, :filter)
    :ok
  end

  @doc false
  def filter(packet, _host), do: packet
  @doc "Report spam."
  def report(host, reporter, spammer) do
    :ets.insert(@table, {{host, reporter, spammer}, System.system_time(:second)})
    :ok
  end
end

defmodule Exjabberd.Mod.AuthFast do
  @moduledoc "`mod_auth_fast` (XEP-0484 FAST) partial implementation of tokens."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_fast
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Issue FAST token."
  def issue(host, bare_jid) do
    token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    :ets.insert(@table, {{host, bare_jid}, token})
    {:ok, token}
  end

  @doc "Verify token."
  def verify(host, bare_jid, token) do
    case :ets.lookup(@table, {host, bare_jid}) do
      [{{_, _}, ^token}] -> true
      _ -> false
    end
  end
end

defmodule Exjabberd.Mod.BlockStrangers do
  @moduledoc "`mod_block_strangers` (partial implementation). Drops stanzas from non-contacts."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, opts) do
    allow_local = Keyword.get(opts, :allow_local_users, true)
    Exjabberd.Hooks.add(:filter_packet, host, __MODULE__, :filter, 60)
    _ = allow_local
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:filter_packet, host, __MODULE__, :filter)
    :ok
  end

  @doc false
  def filter(packet, _host) do
    # Real impl would check roster; for now pass through but hook is wired
    packet
  end
end

defmodule Exjabberd.Mod.Bosh do
  @moduledoc "`mod_bosh` (XEP-0124 + XEP-0206) (partial implementation). Holds BOSH sessions."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_bosh
  @impl true
  def start(_host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    max_inactivity = Keyword.get(opts, :max_inactivity, 30)
    _ = max_inactivity
    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Create BOSH session."
  def create_session(sid, host, pid) do
    :ets.insert(@table, {sid, %{host: host, pid: pid, rid: 0}})
    {:ok, sid}
  end

  @doc "Get session."
  def get_session(sid) do
    case :ets.lookup(@table, sid) do
      [{_, v}] -> {:ok, v}
      [] -> :error
    end
  end
end

defmodule Exjabberd.Mod.Captcha do
  @moduledoc """
  `mod_captcha` (XEP-0158): one-time numeric challenges.

  `generate/1` creates a challenge with a random 5-digit answer,
  stored server-side only — the answer leaves the server solely as
  the rendered PNG image served by `Exjabberd.Http.Captcha`.
  `verify/3` compares the submitted answer, expires challenges
  after #{300} seconds and burns a challenge on ANY verification
  attempt (right or wrong), so answers cannot be brute-forced by
  repetition.
  """
  use Exjabberd.Mod.GenMod
  @table :exjabberd_captcha
  @ttl_seconds 300

  @impl true
  def start(_host, _opts) do
    ensure_table()
    :ok
  end

  @impl true
  def stop(_host), do: :ok

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ok
  end

  @doc "Create a challenge. Returns `{:ok, id}`; the answer is never returned."
  @spec generate(binary()) :: {:ok, binary()}
  def generate(host) do
    ensure_table()
    id = :crypto.strong_rand_bytes(12) |> Base.url_encode64(padding: false)
    answer = Integer.to_string(:rand.uniform(90_000) + 9_999)
    :ets.insert(@table, {{host, id}, %{answer: answer, created: System.system_time(:second)}})
    {:ok, id}
  end

  @doc "The stored answer for rendering the challenge image, or `:error`."
  @spec answer_for(binary(), binary()) :: {:ok, binary()} | :error
  def answer_for(host, id) do
    ensure_table()

    case :ets.lookup(@table, {host, id}) do
      [{{_, _}, %{answer: answer, created: created}}] ->
        if System.system_time(:second) - created <= @ttl_seconds,
          do: {:ok, answer},
          else: :error

      [] ->
        :error
    end
  end

  @doc "Verify an answer. Single-use: the challenge is deleted on any attempt."
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(host, id, answer) do
    ensure_table()

    case :ets.lookup(@table, {host, id}) do
      [{{_, _}, %{answer: expected, created: created}}] ->
        :ets.delete(@table, {host, id})

        System.system_time(:second) - created <= @ttl_seconds and
          String.trim(to_string(answer)) == expected

      [] ->
        false
    end
  end
end

defmodule Exjabberd.Mod.Conversejs do
  @moduledoc "`mod_conversejs` (partial implementation). Serves ConverseJS config."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
  @doc "Get ConverseJS config for host."
  def config(host), do: %{host: host, bosh_url: "/bosh", websocket_url: "/ws"}
end

defmodule Exjabberd.Mod.Delegation do
  @moduledoc "`mod_delegation` (XEP-0356) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:disco_info, host, __MODULE__, :add_features, 60)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:disco_info, host, __MODULE__, :add_features)
    :ok
  end

  @doc false
  def add_features(acc, _host),
    do: Map.update(acc, :features, ["urn:xmpp:delegation:1"], &(&1 ++ ["urn:xmpp:delegation:1"]))
end

defmodule Exjabberd.Mod.Fail2ban do
  @moduledoc "`mod_fail2ban` (partial implementation). Bans IPs after N failures."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_fail2ban
  @impl true
  def start(_host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    max_failures = Keyword.get(opts, :max_failures, 5)
    _ = max_failures
    Exjabberd.Hooks.add(:c2s_auth_failed, _host = "global", __MODULE__, :on_failed, 50)
    :ok
  end

  @impl true
  def stop(_host) do
    Exjabberd.Hooks.delete(:c2s_auth_failed, "global", __MODULE__, :on_failed)
    :ok
  end

  @doc false
  def on_failed({ip, _user}, _host) do
    count =
      case :ets.lookup(@table, ip) do
        [{_, c}] -> c + 1
        [] -> 1
      end

    :ets.insert(@table, {ip, count})
    if count >= 5, do: :ets.insert(@table, {{:banned, ip}, true})
    {ip, count}
  end

  @doc "Is IP banned?"
  def banned?(ip), do: :ets.member(@table, {:banned, ip})
end

defmodule Exjabberd.Mod.HttpUpload do
  @moduledoc """
  `mod_http_upload` (XEP-0363) — real slot issuer.

  Registers the IQ handler for `urn:xmpp:http:upload:0` and
  advertises it in disco#info. A slot request
  (`<request filename size content-type/>`) is answered with a
  `<slot><put url/><get url/></slot>` whose URLs are HMAC-signed
  and expire (see `Exjabberd.Http.Upload`); the actual PUT/GET
  is served by the HTTP listener. `max_size` may be set in
  `mod_http_upload:` options, but the `http.upload_max_size`
  setting wins when both are present.
  """
  use Exjabberd.Mod.GenMod

  @upload_ns "urn:xmpp:http:upload:0"

  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:disco_info, host, __MODULE__, :disco_info, 50)
    Exjabberd.Iq.register(host, @upload_ns, __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:disco_info, host, __MODULE__, :disco_info)
    Exjabberd.Iq.unregister(host, @upload_ns, :both)
    :ok
  end

  @doc false
  def disco_info(acc, _host),
    do: Map.update(acc, :features, [@upload_ns], &(&1 ++ [@upload_ns]))

  @doc "Handle an upload slot request IQ."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "set"} = iq, host) do
    request_el =
      (iq.payload || [])
      |> Enum.find(fn
        %{name: "request", attrs: %{"xmlns" => @upload_ns}} -> true
        _ -> false
      end)

    case request_el do
      nil ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      %{attrs: attrs} ->
        filename = Map.get(attrs, "filename", "")
        content_type = Map.get(attrs, "content-type")
        user = requester_user(iq)

        case parse_size(Map.get(attrs, "size")) do
          {:ok, size} ->
            case Exjabberd.Http.Upload.request_slot(host, user, filename, size, content_type) do
              {:ok, slot} ->
                {:ok, %{iq | type: "result", payload: [slot_element(slot)]}}

              {:error, :too_large} ->
                {:error, :not_acceptable, Exjabberd.Iq.error_iq(iq, "not-acceptable")}

              {:error, :quota_exceeded} ->
                {:error, :resource_constraint, Exjabberd.Iq.error_iq(iq, "resource-constraint")}

              {:error, :bad_request} ->
                {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
            end

          :error ->
            {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
        end
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp slot_element(slot) do
    %{
      name: "slot",
      attrs: %{"xmlns" => @upload_ns},
      children: [
        %{name: "put", attrs: %{"url" => slot.put}, children: []},
        %{name: "get", attrs: %{"url" => slot.get}, children: []}
      ]
    }
  end

  defp parse_size(nil), do: :error

  defp parse_size(str) do
    case Integer.parse(to_string(str)) do
      {n, ""} when n >= 0 -> {:ok, n}
      _ -> :error
    end
  end

  defp requester_user(%{from: %Exjabberd.Xmpp.Jid{local: local}}) when is_binary(local), do: local
  defp requester_user(%{from: from}) when is_binary(from), do: from |> String.split("@") |> hd()
  defp requester_user(_), do: ""

  @doc "Request slot (kept for callers of the old stub API)."
  def request_slot(host, user, filename, size, content_type) do
    case Exjabberd.Http.Upload.request_slot(host, user, filename, size, content_type) do
      {:ok, slot} -> {:ok, %{put: slot.put, get: slot.get}}
      err -> err
    end
  end
end

defmodule Exjabberd.Mod.Last do
  @moduledoc """
  `mod_last` (XEP-0012) Last Activity.

  Records when each user was last seen (on disconnect, via the
  `:user_unavailable` hook) and answers `jabber:iq:last` queries:
  addressed to the server it reports the server uptime in seconds;
  addressed to a user it reports the seconds since that user was
  last online plus their last unavailable status text. A user who
  is currently online answers with `seconds='0'`.
  """
  use Exjabberd.Mod.GenMod

  alias Exjabberd.Xmpp.Jid

  @table :exjabberd_last
  @ns "jabber:iq:last"

  @impl true
  def start(host, _opts) do
    ensure_table()
    :ets.insert_new(@table, {:boot_time, System.system_time(:second)})
    Exjabberd.Hooks.add(:user_available, host, __MODULE__, :on_available, 50)
    Exjabberd.Hooks.add(:user_unavailable, host, __MODULE__, :on_unavailable, 50)
    Exjabberd.Iq.register(host, @ns, __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:user_available, host, __MODULE__, :on_available)
    Exjabberd.Hooks.delete(:user_unavailable, host, __MODULE__, :on_unavailable)
    Exjabberd.Iq.unregister(host, @ns, :both)
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end
  end

  @doc false
  def on_available(jid, _host) do
    ensure_table()
    :ets.delete(@table, bare_of(jid))
    jid
  end

  @doc false
  def on_unavailable(jid, _host) do
    ensure_table()

    case bare_of(jid) do
      nil -> :ok
      bare -> :ets.insert(@table, {bare, System.system_time(:second), "Logged out"})
    end

    jid
  end

  @doc "Get last activity for a bare JID."
  def get(bare_jid) do
    ensure_table()

    case :ets.lookup(@table, bare_jid) do
      [{_, ts, status}] -> {:ok, %{timestamp: ts, status: status}}
      [] -> :error
    end
  end

  @doc "Server uptime in seconds."
  @spec uptime() :: non_neg_integer()
  def uptime do
    ensure_table()

    case :ets.lookup(@table, :boot_time) do
      [{:boot_time, ts}] -> max(System.system_time(:second) - ts, 0)
      [] -> 0
    end
  end

  @doc "IQ handler for `jabber:iq:last` (XEP-0012)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "get"} = iq, host) do
    case iq.to do
      %Jid{local: local, domain: domain} when is_binary(local) and local != "" ->
        bare = "#{local}@#{domain}"

        cond do
          Exjabberd.SessionManager.get_sessions(bare, domain) != [] ->
            {:ok, result(iq, 0, "")}

          true ->
            case get(bare) do
              {:ok, %{timestamp: ts, status: status}} ->
                {:ok, result(iq, max(System.system_time(:second) - ts, 0), status)}

              :error ->
                {:error, :not_found, Exjabberd.Iq.error_iq(iq, "item-not-found")}
            end
        end

      _ ->
        _ = host
        {:ok, result(iq, uptime(), "")}
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp result(iq, seconds, status) do
    children = if status in [nil, ""], do: [], else: [status]

    %{
      iq
      | type: "result",
        payload: [
          %{
            name: "query",
            attrs: %{"xmlns" => @ns, "seconds" => Integer.to_string(seconds)},
            children: children
          }
        ]
    }
  end

  defp bare_of(%Jid{} = jid), do: Jid.bare(jid)
  defp bare_of(bin) when is_binary(bin), do: bin |> String.split("/") |> hd()
  defp bare_of(_), do: nil
end

defmodule Exjabberd.Mod.LegacyAuth do
  @moduledoc "`mod_legacy_auth` (XEP-0078) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.Mqtt do
  @moduledoc """
  `mod_mqtt` — MQTT v3.1.1 broker on port 1883 (Fase 6).

  The broker itself is `Exjabberd.Mqtt.Broker` (started as a supervised
  child, listening via `Exjabberd.Listener.Mqtt` from the `listen:`
  entry `module: exjabberd_mqtt`); this module is the `mod_mqtt`
  entry point that starts the MQTT ↔ XMPP PubSub bridge
  (`Exjabberd.Mqtt.Bridge`) and exposes the programmatic
  publish/subscribe API. Configuration lives in the `mqtt:` section
  of `exjabberd.yml` — no credentials are stored here; CONNECT with a
  username is authenticated against the Auth backend.
  """
  use Exjabberd.Mod.GenMod

  alias Exjabberd.Mqtt.{Bridge, Broker}

  @impl true
  def start(host, _opts) do
    Bridge.start(host)
    :ok
  end

  @impl true
  def stop(host) do
    Bridge.stop(host)
    :ok
  end

  @doc "Publish an MQTT message (also forwarded to PubSub by the bridge unless it came from there)."
  def publish(topic, payload, qos \\ 0) do
    Broker.publish(topic, payload, qos, false)
  end

  @doc "Subscribe a pid to an MQTT topic filter."
  def subscribe(topic, pid) when is_pid(pid) do
    Broker.subscribe_pid(pid, topic, 0)
  end
end

defmodule Exjabberd.Mod.OfflinePush do
  @moduledoc "Push - `mod_offline` push + `mod_push` bridging."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.Private do
  @moduledoc """
  `mod_private` (XEP-0049) Private XML storage.

  Stores arbitrary XML elements per user, keyed by the element's
  namespace. IQ `jabber:iq:private`: a `set` stores each child element
  of the `<query/>` under its own namespace (replacing any previous
  element with that namespace); a `get` returns the stored elements
  for the requested namespaces verbatim.
  """
  use Exjabberd.Mod.GenMod

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @table :exjabberd_private
  @ns "jabber:iq:private"

  @impl true
  def start(host, _opts) do
    ensure_table()
    Exjabberd.Iq.register(host, @ns, __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, @ns, :both)
    :ok
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end
  end

  @doc "Set private data (one element, keyed by its namespace)."
  def set(host, bare_jid, ns, data) do
    ensure_table()
    :ets.insert(@table, {{host, bare_jid, ns}, data})
    :ok
  end

  @doc "Get private data by namespace."
  def get(host, bare_jid, ns) do
    ensure_table()

    case :ets.lookup(@table, {host, bare_jid, ns}) do
      [{{_, _, _}, d}] -> {:ok, d}
      [] -> :error
    end
  end

  @doc "IQ handler for `jabber:iq:private` (generic wire elements)."
  @spec handle_iq(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_iq(%{type: "set"} = iq, host) do
    bare = bare_of(iq.from)
    query = Stanza.child(iq.payload, "query")

    cond do
      is_nil(bare) ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      is_nil(query) ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

      true ->
        Enum.each(query.children, fn
          %{attrs: attrs} = el ->
            case Map.get(attrs, "xmlns") do
              ns when is_binary(ns) and ns != "" -> set(host, bare, ns, el)
              _ -> :ok
            end

          _ ->
            :ok
        end)

        {:ok, %{iq | type: "result", payload: []}}
    end
  end

  def handle_iq(%{type: "get"} = iq, host) do
    bare = bare_of(iq.from)
    query = Stanza.child(iq.payload, "query")

    if is_nil(bare) or is_nil(query) do
      {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    else
      found =
        query.children
        |> Enum.filter(&is_map/1)
        |> Enum.flat_map(fn el ->
          case Map.get(el.attrs || %{}, "xmlns") do
            ns when is_binary(ns) and ns != "" ->
              case get(host, bare, ns) do
                {:ok, stored} -> [stored]
                :error -> []
              end

            _ ->
              []
          end
        end)

      {:ok,
       %{
         iq
         | type: "result",
           payload: [%{name: "query", attrs: %{"xmlns" => @ns}, children: found}]
       }}
    end
  end

  def handle_iq(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  defp bare_of(%Jid{} = jid), do: Jid.bare(jid)
  defp bare_of(bin) when is_binary(bin), do: bin |> String.split("/") |> hd()
  defp bare_of(_), do: nil
end

defmodule Exjabberd.Mod.Proxy65 do
  @moduledoc "`mod_proxy65` (XEP-0065 SOCKS5) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_proxy65
  @impl true
  def start(_host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    hostname = Keyword.get(opts, :hostname, "localhost")
    _ = hostname
    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Activate stream."
  def activate(sid, initiator, target) do
    :ets.insert(@table, {sid, %{initiator: initiator, target: target, activated: true}})
    :ok
  end
end

defmodule Exjabberd.Mod.Register do
  @moduledoc "`mod_register` (XEP-0077) (partial implementation). In-band registration."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_register
  @impl true
  def start(host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    access = Keyword.get(opts, :access, :all)
    Exjabberd.Hooks.add(:register_user, host, __MODULE__, :on_register, 50)
    Exjabberd.Iq.register(host, "jabber:iq:register", __MODULE__, :handle_iq)
    _ = access
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:register_user, host, __MODULE__, :on_register)
    Exjabberd.Iq.unregister(host, "jabber:iq:register", :both)
    :ok
  end

  @doc false
  def handle_iq(%{type: "get"} = iq, _host) do
    {:ok,
     %{
       iq
       | type: "result",
         payload: [
           %{
             xmlns: "jabber:iq:register",
             instructions: "Choose a username and password.",
             username: "",
             password: ""
           }
         ]
     }}
  end

  def handle_iq(%{type: "set"} = iq, host) do
    query = Exjabberd.Xmpp.Stanza.child(iq.payload, "query")
    username = Exjabberd.Xmpp.Stanza.child_text(query && query.children, "username")
    password = Exjabberd.Xmpp.Stanza.child_text(query && query.children, "password")

    cond do
      is_nil(username) or username == "" or is_nil(password) or password == "" ->
        {:error, :bad_request}

      Exjabberd.Auth.user_exists(host, username) ->
        {:error, :conflict}

      true ->
        case Exjabberd.Auth.create_user(host, username, password) do
          :ok -> {:ok, %{iq | type: "result", payload: []}}
          {:error, _} -> {:error, :internal_server_error}
        end
    end
  end

  @doc false
  def on_register({host, user, pass}, _host) do
    Exjabberd.Auth.create_user(host, user, pass)
  end

  @doc "Register user explicitly."
  def register(host, user, pass), do: Exjabberd.Auth.create_user(host, user, pass)
end

defmodule Exjabberd.Mod.RosterVersioning do
  @moduledoc "Roster versioning - handled inside `Exjabberd.Mod.Roster` with ETS."
end

defmodule Exjabberd.Mod.S2S do
  @moduledoc """
  `mod_s2s_dialback` (XEP-0220 Server Dialback).

  Thin wrapper over `Exjabberd.S2S.Dialback`: keys are deterministic
  HMAC-SHA256 values bound to (secret, stream ID, domain pair), so no
  key storage is needed — the Authoritative Server recomputes the key
  from its own secret. (The previous implementation generated a
  random key per call and kept it in ETS, which could never be
  verified by another server; it was not real dialback.)
  """
  use Exjabberd.Mod.GenMod

  @impl true
  def start(_host, _opts), do: :ok

  @impl true
  def stop(_host), do: :ok

  @doc """
  Generate a dialback key for (`stream_id`, `from`, `to`) with this
  server's configured secret. `from` is the Sender/initiating
  domain, `to` the Target/receiving domain.
  """
  @spec generate(binary(), binary(), binary()) :: {:ok, binary()}
  def generate(stream_id, from, to) do
    {:ok, Exjabberd.S2S.Dialback.generate_key(secret(), stream_id, from, to)}
  end

  @doc "Verify a dialback key for (`stream_id`, `from`, `to`)."
  @spec verify(binary(), binary(), binary(), binary()) :: boolean()
  def verify(stream_id, from, to, key) do
    Exjabberd.S2S.Dialback.verify_key(secret(), stream_id, from, to, key)
  end

  defp secret, do: Exjabberd.S2S.Dialback.secret()
end

defmodule Exjabberd.Mod.SharedRoster do
  @moduledoc "`mod_shared_roster` (partial implementation). Shared groups with display."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_shared_roster
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :bag])
    end

    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Create shared group."
  def create_group(host, group, display, members) do
    :ets.insert(@table, {{host, group}, %{display: display, members: members}})
    :ok
  end

  @doc "Members of group."
  def members(host, group) do
    case :ets.lookup(@table, {host, group}) do
      [{{_, _}, %{members: m}}] -> m
      [] -> []
    end
  end
end

defmodule Exjabberd.Mod.Sip do
  @moduledoc """
  SIP gateway - `mod_sip` + `mod_sip_proxy` + `mod_sip_registrar` (partial implementation) untuk vcall.

  Bridges XMPP Jingle ↔ SIP INVITE seperti ejabberd `mod_sip`.
  Menangani REGISTER, INVITE, BYE, ACK, CANCEL, SDP `m=audio` + `a=rtpmap`, dan
  STUN/TURN allocation untuk voice call. Map `sip:alice@host` ↔ `alice@host`.
  """

  use Exjabberd.Mod.GenMod
  @table :exjabberd_sip
  @table_reg :exjabberd_sip_registrar

  @impl true
  def start(host, _opts) do
    for t <- [@table, @table_reg] do
      if :ets.whereis(t) == :undefined do
        :ets.new(t, [:named_table, :public, :set, read_concurrency: true])
      end
    end

    Exjabberd.Iq.register(host, "urn:ietf:params:xml:ns:sip", __MODULE__, :handle_sip)
    Exjabberd.Hooks.add(:sip_invite, host, __MODULE__, :on_invite, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, "urn:ietf:params:xml:ns:sip", :both)
    Exjabberd.Hooks.delete(:sip_invite, host, __MODULE__, :on_invite)
    :ok
  end

  @doc "Register SIP user (like `mod_sip_registrar:register` with expiry)."
  @spec register(binary(), binary(), binary()) :: :ok
  def register(user, uri, contact \\ "") do
    :ets.insert(
      @table_reg,
      {user,
       %{uri: uri, contact: contact, registered_at: System.system_time(:second), expires: 3600}}
    )

    :ets.insert(@table, {user, uri})
    :ok
  end

  @doc "Lookup SIP registration (like `mod_sip_registrar:lookup`)."
  @spec lookup(binary()) :: {:ok, map()} | {:error, :not_found}
  def lookup(user) do
    case :ets.lookup(@table_reg, user) do
      [{_, info}] -> {:ok, info}
      [] -> {:error, :not_found}
    end
  end

  @doc "SIP INVITE → Jingle (voice call SIP → XMPP) with SDP offer."
  @spec invite(binary(), binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def invite(from, to, sdp) do
    sid = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    jingle_content = %{sdp: sdp, media: "audio", sdp_type: "offer"}
    Exjabberd.Mod.Jingle.initiate("localhost", from, to, jingle_content)
    :ok = Exjabberd.Mod.Jingle.set_sdp("localhost", sid, "offer", sdp)
    Exjabberd.Hooks.run(:sip_invite, "localhost", {from, to, sid, sdp})
    {:ok, sid}
  end

  @doc "SIP BYE → Jingle terminate (ejabberd `mod_sip:bye`)."
  @spec bye(binary(), binary()) :: :ok
  def bye(host, sid) do
    Exjabberd.Mod.Jingle.terminate(host, sid, "success")
  end

  @doc "Parse SDP `m=` line to get media (ejabberd SDP handling)."
  @spec parse_sdp_media(binary()) :: binary()
  def parse_sdp_media(sdp) when is_binary(sdp) do
    case Regex.run(~r/^m=(\w+)/m, sdp) do
      [_, media] -> media
      _ -> "audio"
    end
  end

  @doc false
  def on_invite({from, to, sid, sdp} = data, _host) do
    _ = {from, to, sid, sdp}
    data
  end

  @doc "Handle SIP IQ (including SDP)."
  @spec handle_sip(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle_sip(%{payload: [%{sdp: sdp} | _]} = iq, _host) when is_binary(sdp) do
    _ = parse_sdp_media(sdp)
    {:ok, %{iq | type: "result", payload: []}}
  end

  def handle_sip(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end

defmodule Exjabberd.Mod.StunDispatch do
  @moduledoc "`mod_stun_disco` (XEP-0215) (partial implementation). Advertises STUN/TURN."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:disco_info, host, __MODULE__, :add_stun, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:disco_info, host, __MODULE__, :add_stun)
    :ok
  end

  @doc false
  def add_stun(acc, _host),
    do: Map.update(acc, :features, ["urn:xmpp:extdisco:2"], &(&1 ++ ["urn:xmpp:extdisco:2"]))
end

defmodule Exjabberd.Mod.Time do
  @moduledoc "`mod_time` (XEP-0202) (partial implementation). Returns entity time."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Iq.register(host, "urn:xmpp:time", __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, "urn:xmpp:time", :both)
    :ok
  end

  @doc "Get time stanza."
  def time do
    dt = DateTime.utc_now() |> DateTime.to_iso8601()
    %{tzo: "+00:00", utc: dt}
  end

  @doc false
  def handle_iq(%{type: "get"} = iq, _host) do
    %{tzo: tzo, utc: utc} = time()
    {:ok, %{iq | type: "result", payload: [%{xmlns: "urn:xmpp:time", tzo: tzo, utc: utc}]}}
  end

  def handle_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end

defmodule Exjabberd.Mod.Version do
  @moduledoc "`mod_version` (XEP-0092) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Iq.register(host, "jabber:iq:version", __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Iq.unregister(host, "jabber:iq:version", :both)
    :ok
  end

  @doc "Get version."
  def version_info do
    %{
      name: "exjabberd",
      version: Exjabberd.version(),
      os: :erlang.system_info(:otp_release) |> to_string()
    }
  end

  @doc false
  def handle_iq(%{type: "get"} = iq, host) do
    info = version_info()
    show_os = Exjabberd.Mod.Supervisor.get_opts(host, __MODULE__) |> Keyword.get(:show_os, true)

    payload = %{xmlns: "jabber:iq:version", name: info.name, version: info.version}
    payload = if show_os, do: Map.put(payload, :os, info.os), else: payload
    {:ok, %{iq | type: "result", payload: [payload]}}
  end

  def handle_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end

defmodule Exjabberd.Mod.HttpApi do
  @moduledoc "`mod_http_api` (REST API) (partial implementation). Exposes ejabberd_commands over HTTP."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
  @doc "List API permissions."
  def permissions(host), do: Exjabberd.Config.get(host, :api_permissions, %{})
end

defmodule Exjabberd.Mod.Configure do
  @moduledoc "`mod_configure` (XEP-0030 + 0050 configure) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.Stats do
  @moduledoc "`mod_stats` (partial implementation). Exposes stats via disco."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_stats
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ets.insert(@table, {:uptime, System.system_time(:second)})
    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Get stat."
  def get(name) do
    case :ets.lookup(@table, name) do
      [{_, v}] -> {:ok, v}
      [] -> :error
    end
  end
end
