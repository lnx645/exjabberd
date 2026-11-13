defmodule Exjabberd.Http.Admin do
  @moduledoc """
  Web admin — real UI on `/admin` (ejabberd's web admin, port 5280).

  Login uses a real XMPP account: the user/password are verified
  against the stored SCRAM verifier data (`Exjabberd.Auth`), and
  the bare JID must be listed in the `admin` ACL of
  `exjabberd.yml` (default `admin@localhost`). No password is ever
  stored in code or in the config file, and no default credential
  exists — create the admin account first (in-band registration
  or RPC, see README).

  After login the admin gets a signed session cookie
  (`exjabberd_admin`: `user|expiry|HMAC-SHA256`, key:
  `http.upload_secret`, HttpOnly, 8 hours). Pages:

  * dashboard — uptime, registered users, online sessions, loaded
    modules, version (all live numbers from server state);
  * users — list, create, delete, reset password (a deleted user's
    sessions are closed immediately);
  * sessions — every online session (bare JID + resource);
  * rooms — MUC rooms with occupant counts, and room destruction;
  * pubsub — service nodes with type/owner/subscriber counts, and
    node deletion.

  Every link and form works; there are no placeholder pages.
  """

  require Logger

  alias Exjabberd.Http.Config

  @cookie "exjabberd_admin"
  @session_seconds 8 * 3600

  @doc "Handle an admin HTTP request. Returns `{status, headers, body}`."
  @spec handle_http(map()) :: {pos_integer(), [{binary(), binary()}], binary()}
  def handle_http(%{method: "GET", path: path} = req) do
    case route(path) do
      :login -> {:ok, login_page(nil)}
      :logout -> {302, [{"location", "/admin/login"}, clear_cookie()], ""}
      :dashboard -> with_admin(req, &dashboard_page/2)
      :users -> with_admin(req, &users_page/2)
      :sessions -> with_admin(req, &sessions_page/2)
      :rooms -> with_admin(req, &rooms_page/2)
      :pubsub -> with_admin(req, &pubsub_page/2)
      :unknown -> {404, [], "Not found"}
    end
    |> to_response()
  end

  def handle_http(%{method: "POST", path: path} = req) do
    case route(path) do
      :login -> do_login(req)
      :users_create -> with_admin_post(req, &do_create_user/2)
      :users_delete -> with_admin_post(req, &do_delete_user/2)
      :users_reset -> with_admin_post(req, &do_reset_password/2)
      :rooms_destroy -> with_admin_post(req, &do_destroy_room/2)
      :pubsub_delete -> with_admin_post(req, &do_delete_node/2)
      _ -> {404, [], "Not found"} |> to_response()
    end
  end

  def handle_http(_req), do: {405, [], "Method not allowed"}

  # --- auth ---

  @doc "True when `bare_jid` is an admin (listed in the `admin` ACL)."
  @spec admin?(binary()) :: boolean()
  def admin?(bare_jid) when is_binary(bare_jid) do
    bare_jid = String.downcase(bare_jid)
    Enum.member?(admin_jids(), bare_jid)
  end

  @doc "Admin bare JIDs from the `admin` ACL (all configured hosts)."
  @spec admin_jids() :: [binary()]
  def admin_jids do
    Exjabberd.Config.hosts()
    |> Enum.flat_map(fn host ->
      acl = Exjabberd.Config.get(host, :acl, %{})

      case Map.get(acl, "admin") || Map.get(acl, :admin) do
        %{"user" => users} -> List.wrap(users) |> Enum.map(&to_string/1)
        %{user: users} -> List.wrap(users) |> Enum.map(&to_string/1)
        _ -> []
      end
    end)
    |> Enum.map(&String.downcase/1)
    |> Enum.uniq()
  end

  @doc "Verify an admin login: real XMPP password + admin ACL."
  @spec verify_login(binary(), binary(), binary()) :: :ok | {:error, atom()}
  def verify_login(host, user, password) do
    cond do
      user == "" or password == "" ->
        {:error, :bad_request}

      not Exjabberd.Auth.authenticate(host, user, password) ->
        {:error, :not_authorized}

      not admin?("#{user}@#{host}") ->
        {:error, :forbidden}

      true ->
        :ok
    end
  end

  defp session_user(req) do
    with cookie when is_binary(cookie) <- cookie_value(req, @cookie),
         {:ok, user, exp} <- verify_cookie(cookie),
         true <- exp > System.system_time(:second),
         true <- admin?(user) do
      {:ok, user}
    else
      _ -> :error
    end
  end

  defp verify_cookie(cookie) do
    with [user, exp_s, sig] <- String.split(cookie, "|"),
         {exp, ""} <- Integer.parse(exp_s),
         true <- secure_compare(sig, cookie_sig(user, exp)) do
      {:ok, user, exp}
    else
      _ -> :error
    end
  end

  defp make_cookie(user) do
    exp = System.system_time(:second) + @session_seconds
    "#{user}|#{exp}|#{cookie_sig(user, exp)}"
  end

  defp cookie_sig(user, exp) do
    :crypto.mac(:hmac, :sha256, Config.signing_secret(), "admin:#{user}:#{exp}")
    |> Base.url_encode64(padding: false)
  end

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) do
    :crypto.hash(:sha256, a) == :crypto.hash(:sha256, b) and byte_size(a) == byte_size(b)
  end

  defp secure_compare(_, _), do: false

  defp cookie_value(req, name) do
    req.headers
    |> Map.get("cookie", "")
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.find_value(fn
      ^name <> "=" <> value -> URI.decode(value)
      _ -> nil
    end)
  end

  defp set_cookie(value) do
    {"set-cookie",
     "#{@cookie}=#{URI.encode(value)}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=#{@session_seconds}"}
  end

  defp clear_cookie do
    {"set-cookie", "#{@cookie}=; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=0"}
  end

  # --- routing ---

  defp route("/admin"), do: :dashboard
  defp route("/admin/"), do: :dashboard
  defp route("/admin/login"), do: :login
  defp route("/admin/logout"), do: :logout
  defp route("/admin/users"), do: :users
  defp route("/admin/users/create"), do: :users_create
  defp route("/admin/users/delete"), do: :users_delete
  defp route("/admin/users/reset"), do: :users_reset
  defp route("/admin/sessions"), do: :sessions
  defp route("/admin/rooms"), do: :rooms
  defp route("/admin/rooms/destroy"), do: :rooms_destroy
  defp route("/admin/pubsub"), do: :pubsub
  defp route("/admin/pubsub/delete"), do: :pubsub_delete
  defp route(_), do: :unknown

  defp with_admin(req, page_fn) do
    case session_user(req) do
      {:ok, user} -> {:ok, page_fn.(user, req)}
      :error -> {:redirect, "/admin/login"}
    end
  end

  defp with_admin_post(req, action_fn) do
    case session_user(req) do
      {:ok, user} -> action_fn.(user, req)
      :error -> {:redirect, "/admin/login"} |> to_response()
    end
  end

  defp to_response({:ok, body}), do: {200, [{"content-type", "text/html; charset=utf-8"}], body}
  defp to_response({:redirect, loc}), do: {302, [{"location", loc}], ""}
  defp to_response({status, headers, body}), do: {status, headers, body}

  # --- actions ---

  defp do_login(req) do
    params = form_params(req)
    user = Map.get(params, "user", "") |> String.trim() |> String.downcase()
    password = Map.get(params, "password", "")
    host = List.first(Exjabberd.Config.hosts()) || "localhost"

    case verify_login(host, user, password) do
      :ok ->
        {302, [{"location", "/admin"}, set_cookie(make_cookie("#{user}@#{host}"))], ""}
        |> to_response()

      {:error, _} ->
        {:ok, login_page("Wrong username or password, or user is not an admin.")}
        |> to_response()
        |> put_status(401)
    end
  end

  defp put_status({_, headers, body}, status), do: {status, headers, body}

  defp do_create_user(_admin, req) do
    params = form_params(req)
    host = Map.get(params, "host", List.first(Exjabberd.Config.hosts()) || "localhost")
    user = Map.get(params, "user", "") |> String.trim() |> String.downcase()
    password = Map.get(params, "password", "")

    cond do
      user == "" or password == "" ->
        redirect_users("Username and password are required.")

      Exjabberd.Auth.user_exists(host, user) ->
        redirect_users("User #{user} already exists.")

      true ->
        case Exjabberd.Auth.create_user(host, user, password) do
          :ok -> redirect_users("User #{user}@#{host} created.")
          {:error, reason} -> redirect_users("Create failed: #{inspect(reason)}")
        end
    end
  end

  defp do_delete_user(_admin, req) do
    params = form_params(req)
    host = Map.get(params, "host", List.first(Exjabberd.Config.hosts()) || "localhost")
    user = Map.get(params, "user", "") |> String.trim() |> String.downcase()

    if user == "" do
      redirect_users("Username is required.")
    else
      close_user_sessions("#{user}@#{host}")

      case Exjabberd.Auth.remove_user(host, user) do
        :ok -> redirect_users("User #{user}@#{host} deleted.")
        {:error, reason} -> redirect_users("Delete failed: #{inspect(reason)}")
      end
    end
  end

  defp do_reset_password(_admin, req) do
    params = form_params(req)
    host = Map.get(params, "host", List.first(Exjabberd.Config.hosts()) || "localhost")
    user = Map.get(params, "user", "") |> String.trim() |> String.downcase()
    password = Map.get(params, "password", "")

    cond do
      user == "" or password == "" ->
        redirect_users("Username and new password are required.")

      not Exjabberd.Auth.user_exists(host, user) ->
        redirect_users("User #{user} does not exist.")

      true ->
        case Exjabberd.Auth.set_password(host, user, password) do
          :ok -> redirect_users("Password for #{user}@#{host} reset.")
          {:error, reason} -> redirect_users("Reset failed: #{inspect(reason)}")
        end
    end
  end

  defp redirect_users(message) do
    {302, [{"location", "/admin/users?msg=#{URI.encode_www_form(message)}"}], ""}
    |> to_response()
  end

  @doc "Close every live session of a bare JID (used when a user is deleted)."
  @spec close_user_sessions(binary()) :: :ok
  def close_user_sessions(bare_jid) do
    for {_res, pid, _prio} <- Exjabberd.SessionManager.get_sessions(bare_jid, "global") do
      try do
        GenServer.call(pid, :sm_terminate_now, 5_000)
      catch
        :exit, _ -> :ok
      end
    end

    :ok
  end

  # --- pages ---

  defp form_params(req) do
    body = req.body || ""
    content_type = Map.get(req.headers, "content-type", "")

    if String.contains?(content_type, "application/x-www-form-urlencoded") do
      URI.decode_query(body)
    else
      %{}
    end
  end

  defp layout(title, user, inner) do
    """
    <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>exjabberd admin — #{esc(title)}</title>
    <style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0}
    a{color:#7cb3ff}nav{background:#020617;padding:12px 20px;display:flex;gap:18px;align-items:center}
    nav b{font-size:18px}nav span{color:#94a3b8;font-size:13px;margin-left:auto}
    main{max-width:900px;margin:0 auto;padding:20px}
    .card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;margin-bottom:16px}
    table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #334155;padding:8px 6px;text-align:left;font-size:14px}
    input,button{font-size:14px;padding:8px 10px;border-radius:6px;border:1px solid #475569;background:#0f172a;color:#e2e8f0}
    button{background:#2563eb;border-color:#2563eb;cursor:pointer}
    button.danger{background:#b91c1c;border-color:#b91c1c}
    .msg{background:#14532d;border:1px solid #22c55e;padding:10px;border-radius:6px;margin-bottom:16px}
    .stat{font-size:28px;font-weight:700}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
    .err{color:#fca5a5}</style></head><body>
    <nav><b>exjabberd</b><a href="/admin">Dashboard</a><a href="/admin/users">Users</a><a href="/admin/sessions">Sessions</a><a href="/admin/rooms">Rooms</a><a href="/admin/pubsub">PubSub</a>
    <span>#{esc(user)} · <a href="/admin/logout">Logout</a></span></nav>
    <main>#{inner}</main></body></html>
    """
  end

  defp login_page(error) do
    err = if error, do: "<p class='err'>#{esc(error)}</p>", else: ""

    """
    <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>exjabberd admin — login</title>
    <style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0}
    main{max-width:420px;margin:80px auto;padding:20px}
    .card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:24px}
    input,button{font-size:15px;padding:10px;width:100%;box-sizing:border-box;margin:6px 0;border-radius:6px;border:1px solid #475569;background:#0f172a;color:#e2e8f0}
    button{background:#2563eb;border-color:#2563eb;cursor:pointer}.err{color:#fca5a5}</style></head><body>
    <main><div class="card"><h2>exjabberd admin</h2>
    <p>Log in with an XMPP admin account (listed in the <code>admin</code> ACL).</p>
    #{err}
    <form method="post" action="/admin/login">
    <input name="user" placeholder="Username (e.g. admin)" autocomplete="username" required/>
    <input name="password" type="password" placeholder="Password" autocomplete="current-password" required/>
    <button type="submit">Log in</button></form></div></main></body></html>
    """
  end

  defp dashboard_page(user, _req) do
    host = List.first(Exjabberd.Config.hosts()) || "localhost"
    uptime_s = div(elem(:erlang.statistics(:wall_clock), 0), 1000)
    users = Exjabberd.Auth.get_users(host)
    online = Exjabberd.SessionManager.count()
    modules = Exjabberd.Mod.Supervisor.loaded(host) |> Enum.map(&inspect/1) |> Enum.sort()

    stats = """
    <div class="grid">
      <div class="card"><div class="stat">#{uptime_human(uptime_s)}</div><div>Uptime</div></div>
      <div class="card"><div class="stat">#{length(users)}</div><div>Registered users</div></div>
      <div class="card"><div class="stat">#{online}</div><div>Online sessions</div></div>
      <div class="card"><div class="stat">#{length(modules)}</div><div>Modules loaded</div></div>
    </div>
    """

    mod_list =
      Enum.map_join(modules, "", fn m -> "<li>#{esc(m)}</li>" end)

    layout(
      "Dashboard",
      user,
      """
      <h1>Dashboard</h1>
      <p>Host <b>#{esc(host)}</b> · version #{esc(Exjabberd.version())} · node #{esc(to_string(node()))}</p>
      #{stats}
      <div class="card"><h3>Modules</h3><ul>#{mod_list}</ul></div>
      """
    )
  end

  defp users_page(user, req) do
    host = List.first(Exjabberd.Config.hosts()) || "localhost"
    # Flash message from the redirect after a user action (?msg=…).
    msg =
      case Map.get(req.query || %{}, "msg") do
        nil -> ""
        text -> "<div class=\"msg\">#{esc(text)}</div>"
      end

    users = Exjabberd.Auth.get_users(host) |> Enum.sort()
    online = Exjabberd.SessionManager.all_sessions() |> Enum.map(&elem(&1, 0)) |> MapSet.new()

    rows =
      Enum.map_join(users, "", fn u ->
        bare = "#{u}@#{host}"
        status = if MapSet.member?(online, bare), do: "online", else: "offline"

        """
        <tr><td>#{esc(bare)}</td><td>#{status}</td>
        <td><form method="post" action="/admin/users/delete" style="display:inline">
        <input type="hidden" name="user" value="#{esc(u)}"/>
        <button class="danger" type="submit" onclick="return confirm('Delete #{esc(u)}?')">Delete</button></form></td></tr>
        """
      end)

    layout(
      "Users",
      user,
      """
      <h1>Users on #{esc(host)}</h1>
      #{msg}
      <div class="card"><table><tr><th>User</th><th>Status</th><th></th></tr>#{rows}</table></div>
      <div class="card"><h3>Create user</h3>
      <form method="post" action="/admin/users/create">
      <input name="user" placeholder="username" required/>
      <input name="password" type="password" placeholder="password" required/>
      <button type="submit">Create</button></form></div>
      <div class="card"><h3>Reset password</h3>
      <form method="post" action="/admin/users/reset">
      <input name="user" placeholder="username" required/>
      <input name="password" type="password" placeholder="new password" required/>
      <button type="submit">Reset password</button></form></div>
      """
    )
  end

  defp sessions_page(user, _req) do
    sessions = Exjabberd.SessionManager.all_sessions()

    rows =
      Enum.map_join(sessions, "", fn {bare, resource, _pid} ->
        "<tr><td>#{esc(bare)}</td><td>#{esc(resource)}</td></tr>"
      end)

    body =
      if sessions == [] do
        "<p>No online sessions.</p>"
      else
        "<div class=\"card\"><table><tr><th>User</th><th>Resource</th></tr>#{rows}</table></div>"
      end

    layout("Sessions", user, "<h1>Online sessions (#{length(sessions)})</h1>#{body}")
  end

  defp rooms_page(user, req) do
    host = List.first(Exjabberd.Config.hosts()) || "localhost"
    msg = flash(req)
    rooms = Exjabberd.Mod.Muc.list_rooms(host)

    rows =
      Enum.map_join(rooms, "", fn room ->
        occupants =
          case Exjabberd.Mod.Muc.occupants(host, room) do
            {:ok, %{occupants: occ}} -> map_size(occ)
            _ -> 0
          end

        """
        <tr><td>#{esc(room)}</td><td>#{occupants}</td>
        <td><form method="post" action="/admin/rooms/destroy" style="display:inline">
        <input type="hidden" name="room" value="#{esc(room)}"/>
        <button class="danger" type="submit">Destroy</button></form></td></tr>
        """
      end)

    body =
      if rooms == [] do
        "<p>No MUC rooms.</p>"
      else
        "<div class=\"card\"><table><tr><th>Room</th><th>Occupants</th><th></th></tr>#{rows}</table></div>"
      end

    layout("Rooms", user, "#{msg}<h1>MUC rooms (#{length(rooms)})</h1>#{body}")
  end

  defp do_destroy_room(_admin, req) do
    params = form_params(req)
    host = List.first(Exjabberd.Config.hosts()) || "localhost"
    room = Map.get(params, "room", "")

    case Exjabberd.Mod.Muc.destroy_room(host, room) do
      :ok ->
        {302, [{"location", "/admin/rooms?msg=#{URI.encode_www_form("Room #{room} destroyed.")}"}], ""}

      {:error, :not_found} ->
        {302, [{"location", "/admin/rooms?msg=#{URI.encode_www_form("Room not found.")}"}], ""}
    end
  end

  defp pubsub_page(user, req) do
    host = List.first(Exjabberd.Config.hosts()) || "localhost"
    msg = flash(req)
    nodes = Exjabberd.Mod.PubSub.list_service_nodes(host)

    rows =
      Enum.map_join(nodes, "", fn node ->
        meta = Exjabberd.Mod.PubSub.get_node(host, node) || %{}
        subs = length(Exjabberd.Mod.PubSub.get_subscribers(host, node))

        """
        <tr><td>#{esc(node)}</td><td>#{esc(meta[:type] || "leaf")}</td><td>#{esc(meta[:owner] || "")}</td><td>#{subs}</td>
        <td><form method="post" action="/admin/pubsub/delete" style="display:inline">
        <input type="hidden" name="node" value="#{esc(node)}"/>
        <button class="danger" type="submit">Delete</button></form></td></tr>
        """
      end)

    body =
      if nodes == [] do
        "<p>No PubSub service nodes.</p>"
      else
        "<div class=\"card\"><table><tr><th>Node</th><th>Type</th><th>Owner</th><th>Subscribers</th><th></th></tr>#{rows}</table></div>"
      end

    layout("PubSub", user, "#{msg}<h1>PubSub nodes (#{length(nodes)})</h1>#{body}")
  end

  defp do_delete_node(_admin, req) do
    params = form_params(req)
    host = List.first(Exjabberd.Config.hosts()) || "localhost"
    node = Map.get(params, "node", "")

    case Exjabberd.Mod.PubSub.delete_node(host, node) do
      :ok ->
        {302, [{"location", "/admin/pubsub?msg=#{URI.encode_www_form("Node #{node} deleted.")}"}], ""}

      {:error, :not_found} ->
        {302, [{"location", "/admin/pubsub?msg=#{URI.encode_www_form("Node not found.")}"}], ""}
    end
  end

  defp flash(req) do
    case Map.get(req.query || %{}, "msg") do
      nil -> ""
      text -> "<div class=\"msg\">#{esc(text)}</div>"
    end
  end

  defp uptime_human(seconds) do
    days = div(seconds, 86_400)
    hours = div(rem(seconds, 86_400), 3600)
    minutes = div(rem(seconds, 3600), 60)
    secs = rem(seconds, 60)

    cond do
      days > 0 -> "#{days}d #{hours}h"
      hours > 0 -> "#{hours}h #{minutes}m"
      minutes > 0 -> "#{minutes}m #{secs}s"
      true -> "#{secs}s"
    end
  end

  defp esc(nil), do: ""

  defp esc(str) do
    str
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end
end
