defmodule Exjabberd.Http.Server do
  @moduledoc """
  HTTP listener for the admin web, BOSH, WebSocket, HTTP File Upload
  and REST API — plain `:gen_tcp`, no external dependency.

  Why stdlib instead of Plug/Bandit: the hard parts here are not
  HTTP parsing but the XMPP session glue — BOSH long-polling and
  WebSocket framing both need custom per-connection processes
  anyway, and Bandit would still need that glue plus a Hex
  dependency. A small `:gen_tcp` server keeps the whole stack in
  this codebase, compiles with zero new dependencies, and is easy
  to test with `curl` and raw sockets.

  Started from a `listen:` entry with `module: exjabberd_http`:

  ```yaml
  listen:
    -
      port: 5280
      module: exjabberd_http
  ```

  Routing (paths configurable under `http.paths:`):

  * `GET /` — tiny index with links.
  * `/admin…` — `Exjabberd.Http.Admin` (login + dashboard + users + sessions).
  * `/api…` — `Exjabberd.Http.Api` (Bearer token).
  * `/bosh`, `/http-bind` (POST) — `Exjabberd.Http.Bosh`.
  * `/ws` with an Upgrade handshake — `Exjabberd.Http.WebSocket`.
  * `/upload/…` (PUT/GET) — `Exjabberd.Http.Upload`.

  Requests are handled by one spawned process per connection;
  BOSH long-polls simply block that process. Expired upload slots
  are swept every 60 seconds.
  """

  use GenServer
  require Logger

  alias Exjabberd.Http.{Admin, Api, Bosh, Config, Upload, WebSocket}

  @max_headers 65_536
  @max_body 16 * 1024 * 1024

  def start_link(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 5280)
    host = Keyword.get(opts, :host, "localhost")

    {:ok, ls} =
      :gen_tcp.listen(port, [:binary, packet: 0, active: false, reuseaddr: true, backlog: 128])

    Logger.info("exjabberd HTTP listening on 0.0.0.0:#{port} (host #{host})")
    send(self(), :accept)
    Process.send_after(self(), :sweep, 60_000)
    {:ok, %{ls: ls, port: port, host: host}}
  end

  @impl true
  def handle_info(:accept, %{ls: ls} = s) do
    case :gen_tcp.accept(ls, 1000) do
      {:ok, sock} ->
        pid = spawn(fn -> serve(sock, s.host) end)
        :ok = :gen_tcp.controlling_process(sock, pid)
        send(pid, {:take_socket, sock})

      {:error, :timeout} ->
        :ok

      {:error, reason} ->
        Logger.warning("HTTP accept error #{inspect(reason)}")
        Process.sleep(100)
    end

    send(self(), :accept)
    {:noreply, s}
  end

  def handle_info(:sweep, s) do
    removed = Upload.sweep()
    if removed > 0, do: Logger.info("HTTP upload sweep removed #{removed} expired slot(s)")
    Process.send_after(self(), :sweep, 60_000)
    {:noreply, s}
  end

  # --- per-connection ---

  defp serve(sock, host) do
    receive do
      {:take_socket, ^sock} -> :ok
    after
      5_000 -> :ok
    end

    :inet.setopts(sock, active: false)

    case read_request(sock) do
      {:ok, req} ->
        handle_connection(sock, host, req)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.debug("HTTP read failed: #{inspect(reason)}")
        :gen_tcp.close(sock)
    end
  end

  defp handle_connection(sock, host, req) do
    ws_path = Config.path("ws", "/ws")

    if req.path == ws_path and WebSocket.upgrade_request?(req.headers) do
      {status, headers, body} = WebSocket.handshake_response(req.headers)
      :ok = send_response(sock, status, headers, body)
      pid = spawn(fn -> WebSocket.serve(sock, host, peer(sock)) end)
      :ok = :gen_tcp.controlling_process(sock, pid)
      send(pid, {:take_socket, sock})
    else
      {status, headers, body} = dispatch(req)
      :ok = send_response(sock, status, headers, body)
      :gen_tcp.close(sock)
    end
  end

  defp peer(sock) do
    case :inet.peername(sock) do
      {:ok, {ip, port}} -> "#{inspect(ip)}:#{port}"
      _ -> "unknown"
    end
  end

  @doc """
  Route one parsed request to a handler. Pure apart from the
  handlers themselves — also used by `Exjabberd.Web.handle/1`
  and by the tests, so routing can be exercised without a socket.
  """
  @spec dispatch(map()) :: {pos_integer(), [{binary(), binary()}], binary()}
  def dispatch(req) do
    path = req.path || "/"
    admin_path = Config.path("admin", "/admin")
    api_path = Config.path("api", "/api")
    bosh_path = Config.path("bosh", "/bosh")
    bind_path = Config.path("http_bind", "/http-bind")
    upload_path = Config.path("upload", "/upload")

    cond do
      path == "/" ->
        {200, [{"content-type", "text/html; charset=utf-8"}], index_page()}

      path == admin_path or String.starts_with?(path, admin_path <> "/") ->
        Admin.handle_http(req)

      path == api_path or String.starts_with?(path, api_path <> "/") ->
        Api.handle_http(req)

      (path == bosh_path or path == bind_path) and req.method == "POST" ->
        {status, body} = Bosh.handle_request(req.body || "")
        {status, [{"content-type", "text/xml; charset=utf-8"}], body}

      path == bosh_path or path == bind_path ->
        {405, [{"allow", "POST"}], "BOSH requires POST"}

      path == upload_path or String.starts_with?(path, upload_path <> "/") ->
        Upload.handle_http(req)

      path == Config.path("ws", "/ws") ->
        {426, [{"upgrade", "websocket"}], "Use a WebSocket upgrade with subprotocol xmpp"}

      true ->
        {404, [{"content-type", "text/plain"}], "Not found: #{path}"}
    end
  rescue
    e ->
      Logger.warning("HTTP dispatch failed: #{inspect(e)}\n#{Exception.format_stacktrace()}")
      {500, [{"content-type", "text/plain"}], "Internal server error"}
  end

  defp index_page do
    """
    <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
    <title>exjabberd</title></head><body>
    <h1>exjabberd #{Exjabberd.version()}</h1>
    <ul>
    <li><a href="/admin">Web admin</a></li>
    <li><a href="/api/status">API status</a> (Bearer token required)</li>
    <li>BOSH: POST /bosh or /http-bind</li>
    <li>XMPP over WebSocket: ws://host:5280/ws (subprotocol xmpp)</li>
    <li>HTTP File Upload: XEP-0363 slot via XMPP, then PUT/GET /upload/…</li>
    </ul></body></html>
    """
  end

  # --- request reading ---

  defp read_request(sock) do
    case read_until(sock, "\r\n\r\n", @max_headers, "") do
      {:ok, head, rest} ->
        case parse_head(head) do
          {:ok, method, path, query, headers} ->
            case read_body(sock, headers, rest) do
              {:ok, body} ->
                {:ok,
                 %{method: method, path: path, query: query, headers: headers, body: body}}

              {:error, _} = err ->
                err
            end

          {:error, _} = err ->
            err
        end

      {:error, _} = err ->
        err
    end
  end

  defp read_until(sock, marker, max, acc) do
    if byte_size(acc) > max do
      {:error, :too_large}
    else
      case :binary.match(acc, marker) do
        {idx, len} ->
          {:ok, binary_part(acc, 0, idx), binary_part(acc, idx + len, byte_size(acc) - idx - len)}

        :nomatch ->
          case :gen_tcp.recv(sock, 0, 15_000) do
            {:ok, data} -> read_until(sock, marker, max, acc <> data)
            {:error, :closed} -> {:error, :closed}
            {:error, reason} -> {:error, reason}
          end
      end
    end
  end

  defp parse_head(head) do
    lines = String.split(head, "\r\n")

    case lines do
      [request_line | header_lines] ->
        case String.split(request_line, " ") do
          [method, target, _version] ->
            {path, query} = split_target(target)
            headers = parse_headers(header_lines)
            {:ok, method, path, query, headers}

          _ ->
            {:error, :bad_request}
        end

      _ ->
        {:error, :bad_request}
    end
  end

  defp split_target(target) do
    case String.split(target, "?", parts: 2) do
      [path] -> {URI.decode(path), %{}}
      [path, qs] -> {URI.decode(path), URI.decode_query(qs)}
    end
  end

  defp parse_headers(lines) do
    Enum.reduce(lines, %{}, fn line, acc ->
      case String.split(line, ":", parts: 2) do
        [name, value] ->
          Map.put(acc, name |> String.trim() |> String.downcase(), String.trim(value))

        _ ->
          acc
      end
    end)
  end

  defp read_body(sock, headers, rest) do
    cond do
      Map.get(headers, "transfer-encoding", "") |> String.downcase() |> String.contains?("chunked") ->
        read_chunked(sock, rest, "")

      true ->
        length =
          case Integer.parse(Map.get(headers, "content-length", "0")) do
            {n, _} when n >= 0 -> n
            _ -> 0
          end

        if length > @max_body do
          {:error, :too_large}
        else
          read_exact(sock, length, rest)
        end
    end
  end

  defp read_exact(_sock, 0, rest), do: {:ok, rest}

  defp read_exact(sock, needed, rest) do
    if byte_size(rest) >= needed do
      {:ok, binary_part(rest, 0, needed)}
    else
      case :gen_tcp.recv(sock, 0, 15_000) do
        {:ok, data} -> read_exact(sock, needed, rest <> data)
        {:error, :closed} -> {:error, :closed}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp read_chunked(sock, buf, acc) do
    case read_line(sock, buf) do
      {:ok, line, rest} ->
        size =
          line |> String.trim() |> String.split(";") |> hd() |> Integer.parse(16) |> elem(0)

        cond do
          size == 0 ->
            {:ok, acc}

          byte_size(acc) + size > @max_body ->
            {:error, :too_large}

          true ->
            case read_exact(sock, size + 2, rest) do
              {:ok, chunk} ->
                read_chunked(sock, "", acc <> binary_part(chunk, 0, size))

              {:error, _} = err ->
                err
            end
        end

      {:error, _} = err ->
        err
    end
  end

  defp read_line(sock, buf) do
    case :binary.split(buf, "\r\n") do
      [line, rest] -> {:ok, line, rest}
      _ -> read_until(sock, "\r\n", @max_headers, buf)
    end
  end

  # --- response writing ---

  defp send_response(sock, status, headers, body) do
    body = body || ""
    reason = reason_phrase(status)

    headers =
      headers ++
        [
          {"content-length", to_string(byte_size(body))},
          {"connection", "close"}
        ]

    head =
      ["HTTP/1.1 #{status} #{reason}\r\n"] ++
        Enum.map(headers, fn {k, v} -> "#{k}: #{v}\r\n" end) ++ ["\r\n"]

    :gen_tcp.send(sock, IO.iodata_to_binary(head) <> body)
  end

  defp reason_phrase(200), do: "OK"
  defp reason_phrase(201), do: "Created"
  defp reason_phrase(302), do: "Found"
  defp reason_phrase(400), do: "Bad Request"
  defp reason_phrase(401), do: "Unauthorized"
  defp reason_phrase(403), do: "Forbidden"
  defp reason_phrase(404), do: "Not Found"
  defp reason_phrase(405), do: "Method Not Allowed"
  defp reason_phrase(409), do: "Conflict"
  defp reason_phrase(410), do: "Gone"
  defp reason_phrase(413), do: "Payload Too Large"
  defp reason_phrase(415), do: "Unsupported Media Type"
  defp reason_phrase(426), do: "Upgrade Required"
  defp reason_phrase(500), do: "Internal Server Error"
  defp reason_phrase(_), do: "Unknown"
end
