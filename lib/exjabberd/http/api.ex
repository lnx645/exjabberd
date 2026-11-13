defmodule Exjabberd.Http.Api do
  @moduledoc """
  Minimal REST API on `/api` (ejabberd's `mod_http_api`, JSON).

  Authentication: `Authorization: Bearer <token>` where the token
  is `http.api_token` from `exjabberd.yml` (a per-boot ephemeral
  token is generated when it is not configured — see
  `Exjabberd.Http.Config`). Every endpoint without a valid token
  answers 401; there is no anonymous access.

  Endpoints (all JSON):

  * `GET /api/status` — version, uptime, hosts, registered-user
    count, online sessions.
  * `GET /api/users` — registered users for `?host=` (default:
    first configured host).
  * `POST /api/users` `{"user":…, "password":…, "host":…}` — create.
  * `GET /api/users/:user` — existence + online status.
  * `DELETE /api/users/:user` — delete (live sessions are closed).
  * `POST /api/users/:user/password` `{"password":…}` — reset.
  * `GET /api/sessions` — online sessions.
  """

  require Logger

  alias Exjabberd.Http.Config

  @doc "Handle an API HTTP request. Returns `{status, headers, body}`."
  @spec handle_http(map()) :: {pos_integer(), [{binary(), binary()}], binary()}
  def handle_http(req) do
    if authorized?(req) do
      dispatch(req)
    else
      {401, [{"content-type", "application/json"}], Jason.encode!(%{error: "unauthorized"})}
    end
  end

  defp authorized?(req) do
    case Map.get(req.headers, "authorization", "") do
      "Bearer " <> token ->
        secure_compare(String.trim(token), Config.api_token())

      _ ->
        false
    end
  end

  defp secure_compare(a, b) when is_binary(a) and is_binary(b) do
    :crypto.hash(:sha256, a) == :crypto.hash(:sha256, b) and byte_size(a) == byte_size(b)
  end

  defp secure_compare(_, _), do: false

  defp dispatch(%{method: "GET", path: "/api/status"} = req) do
    host = host_param(req)
    json(200, %{
      status: "ok",
      version: Exjabberd.version(),
      node: to_string(node()),
      uptime_seconds: div(elem(:erlang.statistics(:wall_clock), 0), 1000),
      hosts: Exjabberd.Config.hosts(),
      registered_users: length(Exjabberd.Auth.get_users(host)),
      online_sessions: Exjabberd.SessionManager.count()
    })
  end

  defp dispatch(%{method: "GET", path: "/api/users"} = req) do
    host = host_param(req)
    json(200, %{host: host, users: Exjabberd.Auth.get_users(host) |> Enum.sort()})
  end

  defp dispatch(%{method: "POST", path: "/api/users"} = req) do
    params = json_params(req)
    host = Map.get(params, "host", host_param(req))
    user = Map.get(params, "user", "") |> to_string() |> String.trim() |> String.downcase()
    password = Map.get(params, "password", "") |> to_string()

    cond do
      user == "" or password == "" ->
        json(400, %{error: "user and password are required"})

      Exjabberd.Auth.user_exists(host, user) ->
        json(409, %{error: "user already exists"})

      true ->
        case Exjabberd.Auth.create_user(host, user, password) do
          :ok -> json(201, %{user: "#{user}@#{host}", created: true})
          {:error, reason} -> json(500, %{error: inspect(reason)})
        end
    end
  end

  defp dispatch(%{method: "GET", path: "/api/sessions"}) do
    sessions =
      Exjabberd.SessionManager.all_sessions()
      |> Enum.map(fn {bare, resource, _pid} -> %{user: bare, resource: resource} end)

    json(200, %{sessions: sessions, count: length(sessions)})
  end

  defp dispatch(%{method: "GET", path: "/api/users/" <> user}) do
    user = user |> URI.decode() |> String.downcase()
    host = List.first(Exjabberd.Config.hosts()) || "localhost"

    json(200, %{
      user: "#{user}@#{host}",
      exists: Exjabberd.Auth.user_exists(host, user),
      online: Exjabberd.SessionManager.get_resources("#{user}@#{host}") != []
    })
  end

  defp dispatch(%{method: "DELETE", path: "/api/users/" <> user}) do
    user = user |> URI.decode() |> String.downcase()
    host = List.first(Exjabberd.Config.hosts()) || "localhost"
    Exjabberd.Http.Admin.close_user_sessions("#{user}@#{host}")

    case Exjabberd.Auth.remove_user(host, user) do
      :ok -> json(200, %{user: "#{user}@#{host}", deleted: true})
      {:error, reason} -> json(500, %{error: inspect(reason)})
    end
  end

  defp dispatch(%{method: "POST", path: "/api/users/" <> rest} = req) do
    case String.split(rest, "/", parts: 2) do
      [user, "password"] ->
        user = user |> URI.decode() |> String.downcase()
        host = List.first(Exjabberd.Config.hosts()) || "localhost"
        password = req |> json_params() |> Map.get("password", "") |> to_string()

        cond do
          password == "" ->
            json(400, %{error: "password is required"})

          not Exjabberd.Auth.user_exists(host, user) ->
            json(404, %{error: "user not found"})

          true ->
            case Exjabberd.Auth.set_password(host, user, password) do
              :ok -> json(200, %{user: "#{user}@#{host}", password_reset: true})
              {:error, reason} -> json(500, %{error: inspect(reason)})
            end
        end

      _ ->
        json(404, %{error: "not found"})
    end
  end

  defp dispatch(%{method: "GET", path: "/api/rooms"} = req) do
    host = host_param(req)

    rooms =
      Enum.map(Exjabberd.Mod.Muc.list_rooms(host), fn room ->
        occupants =
          case Exjabberd.Mod.Muc.occupants(host, room) do
            {:ok, %{occupants: occ}} -> map_size(occ)
            _ -> 0
          end

        %{jid: room, occupants: occupants}
      end)

    json(200, %{rooms: rooms, count: length(rooms)})
  end

  defp dispatch(%{method: "DELETE", path: "/api/rooms/" <> name} = req) do
    host = host_param(req)
    name = URI.decode(name)
    room = if String.contains?(name, "@"), do: name, else: "#{name}@conference.#{host}"

    case Exjabberd.Mod.Muc.destroy_room(host, room) do
      :ok -> json(200, %{room: room, destroyed: true})
      {:error, :not_found} -> json(404, %{error: "room not found"})
    end
  end

  defp dispatch(%{method: "GET", path: "/api/nodes"} = req) do
    host = host_param(req)

    nodes =
      Enum.map(Exjabberd.Mod.PubSub.list_service_nodes(host), fn node ->
        meta = Exjabberd.Mod.PubSub.get_node(host, node) || %{}

        %{
          node: node,
          type: meta[:type] || "leaf",
          owner: meta[:owner],
          subscribers: length(Exjabberd.Mod.PubSub.get_subscribers(host, node))
        }
      end)

    json(200, %{nodes: nodes, count: length(nodes)})
  end

  defp dispatch(%{method: "DELETE", path: "/api/nodes/" <> node} = req) do
    host = host_param(req)
    node = URI.decode(node)

    case Exjabberd.Mod.PubSub.delete_node(host, node) do
      :ok -> json(200, %{node: node, deleted: true})
      {:error, :not_found} -> json(404, %{error: "node not found"})
    end
  end

  defp dispatch(_req), do: json(404, %{error: "not found"})

  defp host_param(req) do
    Map.get(req.query || %{}, "host") || List.first(Exjabberd.Config.hosts()) || "localhost"
  end

  defp json_params(req) do
    case Jason.decode(req.body || "") do
      {:ok, map} when is_map(map) -> map
      _ -> %{}
    end
  end

  defp json(status, data) do
    {status, [{"content-type", "application/json"}], Jason.encode!(data)}
  end
end
