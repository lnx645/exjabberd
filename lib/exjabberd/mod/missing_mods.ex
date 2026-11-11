defmodule Exjabberd.Mod.HostMeta do
  @moduledoc """
  Host-meta - XEP-0156 Service Discovery + RFC 6415 `/.well-known/host-meta` (partial implementation), stabil.
  Serves XRD with `alt-connections` for BOSH/WS like `mod_host_meta` + `ejabberd` docs.
  """
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:http_request, host, __MODULE__, :handle, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:http_request, host, __MODULE__, :handle)
    :ok
  end

  @doc "Get host-meta XRD XML (ejabberd `mod_host_meta:host_meta`) + JSON variant."
  @spec host_meta(binary()) :: binary()
  def host_meta(host) do
    ~s(<?xml version='1.0'?><XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'><Host>#{host}</Host><Link rel='urn:xmpp:alt-connections:xbosh' href='https://#{host}:5280/bosh'/><Link rel='urn:xmpp:alt-connections:websocket' href='wss://#{host}:5443/ws'/><Link rel='urn:xmpp:alt-connections:httppoll' href='https://#{host}:5280/http-poll'/></XRD>)
  end

  @doc "Get host-meta JSON (RFC 6415 JSON)."
  @spec host_meta_json(binary()) :: binary()
  def host_meta_json(host) do
    Jason.encode!(%{
      links: [
        %{rel: "urn:xmpp:alt-connections:xbosh", href: "https://#{host}:5280/bosh"},
        %{rel: "urn:xmpp:alt-connections:websocket", href: "wss://#{host}:5443/ws"}
      ]
    })
  end

  @doc "Handle HTTP `/.well-known/host-meta` + `/.well-known/host-meta.json` (ejabberd `mod_host_meta:process`)."
  @spec handle(map(), binary()) :: map()
  def handle(%{path: "/.well-known/host-meta.json"} = req, host) do
    %{
      req
      | status: 200,
        headers: [{"content-type", "application/json"}],
        body: host_meta_json(host)
    }
  end

  def handle(%{path: "/.well-known/host-meta"} = req, host) do
    %{req | status: 200, headers: [{"content-type", "application/xrd+xml"}], body: host_meta(host)}
  end

  def handle(%{path: "/.well-known/webfinger", query: q} = req, host) when is_map(q) do
    resource = Map.get(q, "resource", "acct:user@#{host}")

    body =
      ~s({"subject":"#{resource}","links":[{"rel":"http://webfinger.net/rel/avatar","href":"https://#{host}/avatar"}]})

    %{req | status: 200, headers: [{"content-type", "application/jrd+json"}], body: body}
  end

  def handle(req, _host), do: req
end

defmodule Exjabberd.Mod.Http do
  @moduledoc "`mod_http` generic HTTP (ejabberd http fileserver) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.HttpFileserver do
  @moduledoc "`mod_http_fileserver` (partial implementation). Serves static files."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, opts) do
    docroot = Keyword.get(opts, :docroot, "/var/www")
    _ = docroot
    :ok
  end

  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.HttpUploadQuota do
  @moduledoc "`mod_http_upload_quota` (partial implementation). Quota per user."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_upload_quota
  @impl true
  def start(_host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    max_days = Keyword.get(opts, :max_days, 30)
    _ = max_days
    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Check quota."
  def check_quota(host, user, size) do
    bare = "#{user}@#{host}"

    used =
      case :ets.lookup(@table, bare) do
        [{_, v}] -> v
        [] -> 0
      end

    if used + size > 50 * 1024 * 1024, do: {:error, :quota_exceeded}, else: :ok
  end

  @doc "Add usage."
  def add_usage(host, user, size) do
    bare = "#{user}@#{host}"

    used =
      case :ets.lookup(@table, bare) do
        [{_, v}] -> v
        [] -> 0
      end

    :ets.insert(@table, {bare, used + size})
    :ok
  end
end

defmodule Exjabberd.Mod.Invites do
  @moduledoc "`mod_invites` (XEP-0401) (partial implementation). Invite via URL."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_invites
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Create invite."
  def create(host, from, to_email) do
    code = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)

    :ets.insert(
      @table,
      {{host, code}, %{from: from, to: to_email, created: System.system_time(:second)}}
    )

    {:ok, "https://#{host}/invite/#{code}"}
  end

  @doc "Redeem invite."
  def redeem(host, code, _new_jid) do
    case :ets.lookup(@table, {host, code}) do
      [{{_, _}, info}] ->
        :ets.delete(@table, {host, code})
        {:ok, info}

      [] ->
        {:error, :not_found}
    end
  end
end

defmodule Exjabberd.Mod.JidPrep do
  @moduledoc """
  JidPrep - `mod_jidprep` + `jid` stringprep (RFC3454, RFC7622) (partial implementation), stabil.
  Delegates ke `Exjabberd.Xmpp.Jid` `nodeprep/nameprep/resourceprep` seperti ejabberd `jid`.
  """
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:jid_prep, host, __MODULE__, :prep_hook, 50)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:jid_prep, host, __MODULE__, :prep_hook)
    :ok
  end

  @doc "Prep JID (stringprep, ejabberd `jid:from_string`)."
  @spec prep(binary()) :: {:ok, Exjabberd.Xmpp.Jid.t()} | {:error, term()}
  def prep(jid) when is_binary(jid), do: Exjabberd.Xmpp.Jid.parse(jid)
  @doc false
  def prep_hook(jid, _host), do: prep(jid)
end

defmodule Exjabberd.Mod.MatrixGw do
  @moduledoc "`mod_matrix_gw` (Matrix gateway) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
  @doc "Bridge XMPP to Matrix."
  def bridge(host, xmpp_jid, matrix_id) do
    _ = {host, xmpp_jid, matrix_id}
    :ok
  end
end

defmodule Exjabberd.Mod.Metrics do
  @moduledoc "`mod_metrics` (partial implementation). Exposes Prometheus metrics."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_metrics
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :telemetry.attach(
      "exjabberd-metrics",
      [[:exjabberd, :c2s, :bind]],
      fn _, _, _, _ -> :ets.update_counter(@table, :c2s_binds, 1, {0, 0}) end,
      nil
    )

    :ok
  rescue
    _ -> :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Get metrics."
  def get, do: :ets.tab2list(@table)
end

defmodule Exjabberd.Mod.MixPam do
  @moduledoc "`mod_mix_pam` (XEP-0369 PAM for MIX) (partial implementation). Handles Participant Anonymization Mapping via `stable_id` -> real JID."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_mix_pam
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end

    Exjabberd.Hooks.add(:mix_join, "global", __MODULE__, :on_join, 50)
    :ok
  end

  @impl true
  def stop(_host) do
    Exjabberd.Hooks.delete(:mix_join, "global", __MODULE__, :on_join)
    :ok
  end

  @doc "Map stable_id to real JID (PAM lookup like ejabberd `mod_mix_pam:get_jid`)."
  @spec put_mapping(binary(), binary(), binary(), binary()) :: :ok
  def put_mapping(host, channel, stable_id, real_jid) do
    :ets.insert(@table, {{host, channel, stable_id}, real_jid})
    :ok
  end

  @spec get_jid(binary(), binary(), binary()) :: {:ok, binary()} | :error
  def get_jid(host, channel, stable_id) do
    case :ets.lookup(@table, {host, channel, stable_id}) do
      [{_, jid}] -> {:ok, jid}
      [] -> :error
    end
  end

  @doc false
  def on_join({host, channel, jid, nick} = data, _host) do
    sid = Exjabberd.Mod.Mix.stable_id(jid, channel)
    put_mapping(host, channel, sid, jid)
    _ = nick
    data
  end
end

defmodule Exjabberd.Mod.MqttBridge do
  @moduledoc "`mod_mqtt_bridge` (partial implementation). Bridges MQTT to XMPP PubSub."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.Multicast do
  @moduledoc """
  Multicast - XEP-0033 Extended Stanza Addressing (partial implementation).
  Handles `<addresses xmlns='http://jabber.org/protocol/address'>` with multiple `to`/`cc`.
  Like `mod_multicast` does `route_multicast`.
  """
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Hooks.add(:multicast, host, __MODULE__, :handle, 50)
    Exjabberd.Iq.register(host, "http://jabber.org/protocol/address", __MODULE__, :handle_iq)
    :ok
  end

  @impl true
  def stop(host) do
    Exjabberd.Hooks.delete(:multicast, host, __MODULE__, :handle)
    Exjabberd.Iq.unregister(host, "http://jabber.org/protocol/address", :both)
    :ok
  end

  @doc "Handle multicast with addresses (like `mod_multicast:route`)."
  @spec handle(map(), binary()) :: map()
  def handle(%{payload: payload} = stanza, _host) do
    addresses =
      Enum.flat_map(payload, fn
        %{addresses: addrs} -> addrs
        %{address: addr} -> [addr]
        _ -> []
      end)

    if addresses == [] do
      stanza
    else
      Enum.each(addresses, fn %{jid: jid, type: _type} = _addr ->
        Exjabberd.Router.route(Map.put(stanza, :to, jid))
      end)

      stanza
    end
  end

  def handle(stanza, _host), do: stanza
  @doc false
  def handle_iq(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}
end

defmodule Exjabberd.Mod.PresCounter do
  @moduledoc "`mod_pres_counter` (partial implementation). Counts presences."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_pres_counter
  @impl true
  def start(_host, _opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set])
    end

    :ok
  end

  @impl true
  def stop(_host), do: :ok
  @doc "Increment."
  def inc(host, user) do
    bare = "#{user}@#{host}"
    :ets.update_counter(@table, bare, 1, {bare, 0})
  end
end

defmodule Exjabberd.Mod.Privilege do
  @moduledoc "`mod_privilege` (XEP-0356 Privileged Entity) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.Providers do
  @moduledoc "`mod_providers` (partial implementation). S2S provider selection."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.PubSubServerInfo do
  @moduledoc "`mod_pubsub_serverinfo` (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.RegisterWeb do
  @moduledoc "`mod_register_web` (partial implementation). Web registration form."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
  @doc "Render register page."
  def render(host), do: "<form action='https://#{host}/register'>Register</form>"
end

defmodule Exjabberd.Mod.S2sBidi do
  @moduledoc "`mod_s2s_bidi` (XEP-0288) (partial implementation). Bidirectional S2S."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.ScramUpgrade do
  @moduledoc "`mod_scram_upgrade` (partial implementation). Upgrades plain to SCRAM."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
  @doc "Upgrade password."
  def upgrade(host, user) do
    _ = {host, user}
    :ok
  end
end

defmodule Exjabberd.Mod.ServiceLog do
  @moduledoc "`mod_service_log` (partial implementation). Logs stanzas to service."
  use Exjabberd.Mod.GenMod
  @table :exjabberd_service_log
  @impl true
  def start(_host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :bag])
    end

    loggers = Keyword.get(opts, :loggers, [])
    _ = loggers
    Exjabberd.Hooks.add(:user_send_packet, "global", __MODULE__, :log, 90)
    :ok
  end

  @impl true
  def stop(_host) do
    Exjabberd.Hooks.delete(:user_send_packet, "global", __MODULE__, :log)
    :ok
  end

  @doc false
  def log(stanza, _host) do
    :ets.insert(@table, {System.system_time(:millisecond), stanza})
    stanza
  end
end

defmodule Exjabberd.Mod.Sic do
  @moduledoc "`mod_sic` (XEP-0279) (partial implementation). Server IP check."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
  @doc "Get IP."
  def get_ip, do: {:ok, {127, 0, 0, 1}}
end

defmodule Exjabberd.Mod.Admin do
  @moduledoc "`mod_admin` (deprecated, use mod_admin_extra) (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.MucAdmin do
  @moduledoc "`mod_muc_admin` (partial implementation). Admin commands for MUC."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.MucLog do
  @moduledoc """
  MUC Log - `mod_muc_log` partial implementation of file rotation. Logs MUC messages to file/DB per room/day.
  Like `mod_muc_log` with `outdir` + `dirname` + `file_format` (html/plain) + `timezone` + `access_log`.
  File: `outdir/room@host/YYYY/MM/DD.html` with hourly flush like ejabberd does file:write.
  """
  use Exjabberd.Mod.GenMod
  @table :exjabberd_muc_log
  @impl true
  def start(_host, opts) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :bag, read_concurrency: true])
    end

    outdir = Keyword.get(opts, :outdir, "/tmp/muclog")
    File.mkdir_p!(outdir)
    Exjabberd.Hooks.add(:muc_log, _host = "global", __MODULE__, :log, 50)
    :ok
  end

  @impl true
  def stop(_host) do
    Exjabberd.Hooks.delete(:muc_log, "global", __MODULE__, :log)
    :ok
  end

  @doc "Log MUC message (like `mod_muc_log:add_log`) with file rotation per day."
  @spec log({binary(), binary(), map()}, binary()) :: {binary(), binary(), map()}
  def log({room_jid, nick, stanza} = data, _host) do
    :ets.insert(
      @table,
      {{room_jid, Date.utc_today()}, %{nick: nick, stanza: stanza, ts: System.system_time(:second)}}
    )

    # File rotation - best-effort like ejabberd file:write
    try do
      outdir = "/tmp/muclog"
      date = Date.utc_today()
      safe = String.replace(room_jid, ~r/[^a-zA-Z0-9@._-]/, "_")
      dir = Path.join([outdir, safe, "#{date.year}", String.pad_leading("#{date.month}", 2, "0")])
      File.mkdir_p!(dir)
      path = Path.join(dir, "#{String.pad_leading("#{date.day}", 2, "0")}.html")
      body = Map.get(stanza, :payload, []) |> inspect()
      line = "<p>[#{DateTime.utc_now() |> DateTime.to_iso8601()}][#{nick}] #{body}</p>\n"
      File.write!(path, line, [:append])
    catch
      _, _ -> :ok
    end

    data
  end

  @doc "Get logs for room/day."
  @spec get_logs(binary(), Date.t()) :: [map()]
  def get_logs(room_jid, date) do
    :ets.lookup(@table, {room_jid, date}) |> Enum.map(fn {_, v} -> v end)
  end

  @doc "Get log file path for room/date (for rotation check)."
  @spec log_file(binary(), Date.t()) :: binary()
  def log_file(room_jid, date) do
    safe = String.replace(room_jid, ~r/[^a-zA-Z0-9@._-]/, "_")

    Path.join([
      "/tmp/muclog",
      safe,
      "#{date.year}",
      String.pad_leading("#{date.month}", 2, "0"),
      "#{String.pad_leading("#{date.day}", 2, "0")}.html"
    ])
  end
end

defmodule Exjabberd.Mod.PushKeepalive do
  @moduledoc "`mod_push_keepalive` (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.SharedRosterLdap do
  @moduledoc "`mod_shared_roster_ldap` (partial implementation). Shared roster via LDAP."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.VcardLdap do
  @moduledoc "`mod_vcard_ldap` (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.AdminUpdate do
  @moduledoc "`mod_admin_update_sql` (partial implementation). Updates SQL schema on start."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(host, _opts) do
    Exjabberd.Storage.SqlSchema.create_tables(host, :postgres)
    :ok
  end

  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.InvitesHttp do
  @moduledoc "`mod_invites_http` (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end

defmodule Exjabberd.Mod.InvitesRegister do
  @moduledoc "`mod_invites_register` (partial implementation)."
  use Exjabberd.Mod.GenMod
  @impl true
  def start(_host, _opts), do: :ok
  @impl true
  def stop(_host), do: :ok
end
