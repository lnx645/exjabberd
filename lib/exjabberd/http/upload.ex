defmodule Exjabberd.Http.Upload do
  @moduledoc """
  HTTP File Upload — XEP-0363, server side.

  Flow:

  1. A client sends an IQ-set `<request xmlns='urn:xmpp:http:upload:0'
     filename='…' size='…' content-type='…'/>` (handled by
     `Exjabberd.Mod.HttpUpload`, which calls `request_slot/5` here).
  2. The reply carries a `<slot/>` with a PUT URL and a GET URL.
     Both URLs carry an HMAC-SHA256 signature over
     `slot_id | filename | expiry` (key: `http.upload_secret`) and
     the expiry timestamp, so a URL cannot be forged or reused
     past its lifetime, and a PUT cannot be made for a slot that
     was never issued.
  3. `PUT <put-url>` uploads the exact bytes (size and content-type
     are verified against the slot); `GET <get-url>` downloads them.
  4. Files live under `http.upload_dir` (default `priv/uploads/`,
     gitignored) as bare slot ids — the client-supplied filename
     never touches the filesystem, so `../` traversal is
     impossible. Expired slots/files are removed by `sweep/0`
     (run periodically by the HTTP listener) and lazily on access.

  A PUT for an unknown/expired slot, a wrong signature, a size
  mismatch or a content-type mismatch is rejected; a GET before
  upload or after expiry is a 404.
  """

  require Logger

  alias Exjabberd.Http.Config

  @table :exjabberd_upload_slots

  @doc "Request a slot. Returns `{:ok, %{put: url, get: url, slot_id: id, expires_at: ts}}`."
  @spec request_slot(binary(), binary(), binary(), non_neg_integer(), binary() | nil) ::
          {:ok, map()} | {:error, :too_large | :bad_request}
  def request_slot(host, user, filename, size, content_type) do
    ensure_table()

    cond do
      not is_binary(filename) or filename == "" or String.contains?(filename, "/") or
          String.contains?(filename, "\\") ->
        {:error, :bad_request}

      not is_integer(size) or size < 0 or size > Config.upload_max_size() ->
        {:error, :too_large}

      true ->
        slot_id = :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
        expires_at = System.system_time(:second) + Config.upload_expiry_seconds()
        base = Config.upload_url_base()
        encoded_name = URI.encode(filename)

        record = %{
          host: host,
          user: user,
          filename: filename,
          size: size,
          content_type: content_type,
          expires_at: expires_at,
          uploaded: false,
          path: Path.join(upload_dir(), slot_id)
        }

        :ets.insert(@table, {slot_id, record})

        {:ok,
         %{
           slot_id: slot_id,
           expires_at: expires_at,
           put:
             "#{base}/upload/#{slot_id}/#{encoded_name}?token=#{sign("put", slot_id, filename, expires_at)}&exp=#{expires_at}",
           get:
             "#{base}/upload/#{slot_id}/#{encoded_name}?token=#{sign("get", slot_id, filename, expires_at)}&exp=#{expires_at}"
         }}
    end
  end

  @doc "Handle `PUT /upload/:slot/:filename?token=…&exp=…` with the raw body."
  @spec put(binary(), binary(), binary() | nil, binary() | nil, binary() | nil, binary()) ::
          {:ok, :uploaded} | {:error, atom()}
  def put(slot_id, filename, token, exp, content_type, data) do
    ensure_table()

    with {:ok, record} <- fetch(slot_id),
         :ok <- check_filename(record, filename),
         :ok <- check_expiry(record),
         :ok <- check_token("put", slot_id, record.filename, exp, token),
         :ok <- check_size(record, data),
         :ok <- check_content_type(record, content_type),
         :ok <- store_file(record, data) do
      :ets.insert(@table, {slot_id, %{record | uploaded: true}})
      {:ok, :uploaded}
    end
  end

  @doc "Handle `GET /upload/:slot/:filename?token=…&exp=…`. Returns the file bytes and content-type."
  @spec get(binary(), binary(), binary() | nil, binary() | nil) ::
          {:ok, binary(), binary()} | {:error, atom()}
  def get(slot_id, filename, token, exp) do
    ensure_table()

    with {:ok, record} <- fetch(slot_id),
         :ok <- check_filename(record, filename),
         :ok <- check_expiry(record),
         :ok <- check_token("get", slot_id, record.filename, exp, token),
         true <- record.uploaded or {:error, :not_found},
         {:ok, data} <- File.read(record.path) do
      {:ok, data, record.content_type || "application/octet-stream"}
    end
  end

  @doc "Delete expired slots and their files. Returns how many were removed."
  @spec sweep() :: non_neg_integer()
  def sweep do
    ensure_table()
    now = System.system_time(:second)

    :ets.tab2list(@table)
    |> Enum.reduce(0, fn {slot_id, record}, count ->
      if record.expires_at <= now do
        File.rm(record.path)
        :ets.delete(@table, slot_id)
        count + 1
      else
        count
      end
    end)
  end

  @doc "Slot record (for tests/admin), or `:error`."
  @spec lookup(binary()) :: {:ok, map()} | :error
  def lookup(slot_id) do
    ensure_table()

    case :ets.lookup(@table, slot_id) do
      [{_, record}] -> {:ok, record}
      [] -> :error
    end
  end

  # --- HTTP entry point (called by the HTTP server router) ---

  @doc "Handle an upload HTTP request. `req` is the server's request map."
  @spec handle_http(map()) :: {pos_integer(), [{binary(), binary()}], binary()}
  def handle_http(%{method: "PUT", path: path, query: query, headers: headers, body: body}) do
    case parse_upload_path(path) do
      {:ok, slot_id, filename} ->
        content_type = Map.get(headers, "content-type")

        case put(slot_id, filename, query["token"], query["exp"], content_type, body || "") do
          {:ok, :uploaded} ->
            {201, [{"content-type", "text/plain"}], "Created"}

          {:error, :not_found} ->
            {404, [], "Unknown or expired upload slot"}

          {:error, :forbidden} ->
            {403, [], "Invalid upload token"}

          {:error, :gone} ->
            {410, [], "Upload slot expired"}

          {:error, :bad_request} ->
            {400, [], "Bad upload request"}

          {:error, :too_large} ->
            {413, [], "Upload too large"}

          {:error, :unsupported_media_type} ->
            {415, [], "Content-Type does not match the requested slot"}

          {:error, reason} ->
            Logger.warning("upload PUT failed: #{inspect(reason)}")
            {500, [], "Upload failed"}
        end

      :error ->
        {400, [], "Bad upload path"}
    end
  end

  def handle_http(%{method: "GET", path: path, query: query}) do
    case parse_upload_path(path) do
      {:ok, slot_id, filename} ->
        case get(slot_id, filename, query["token"], query["exp"]) do
          {:ok, data, content_type} ->
            {200,
             [
               {"content-type", content_type},
               {"content-disposition", "attachment; filename=\"#{filename}\""}
             ], data}

          {:error, :not_found} ->
            {404, [], "Not found"}

          {:error, :forbidden} ->
            {403, [], "Invalid download token"}

          {:error, :gone} ->
            {410, [], "Upload expired"}

          {:error, reason} ->
            Logger.warning("upload GET failed: #{inspect(reason)}")
            {500, [], "Download failed"}
        end

      :error ->
        {404, [], "Not found"}
    end
  end

  def handle_http(_req), do: {405, [{"allow", "GET, PUT"}], "Method not allowed"}

  defp parse_upload_path(path) do
    case String.split(path, "/", trim: true) do
      ["upload", slot_id, filename] when slot_id != "" and filename != "" ->
        {:ok, slot_id, URI.decode(filename)}

      _ ->
        :error
    end
  end

  # --- checks ---

  defp fetch(slot_id) do
    case :ets.lookup(@table, slot_id) do
      [{_, record}] -> {:ok, record}
      [] -> {:error, :not_found}
    end
  end

  defp check_filename(record, filename) do
    if record.filename == filename, do: :ok, else: {:error, :not_found}
  end

  defp check_expiry(record) do
    if record.expires_at > System.system_time(:second), do: :ok, else: {:error, :gone}
  end

  defp check_token(kind, slot_id, filename, exp, token) do
    with {:ok, exp_int} <- parse_exp(exp),
         true <- token != nil and token != "" do
      expected = sign(kind, slot_id, filename, exp_int)

      if secure_compare(token, expected), do: :ok, else: {:error, :forbidden}
    else
      _ -> {:error, :forbidden}
    end
  end

  defp parse_exp(nil), do: :error

  defp parse_exp(exp) do
    case Integer.parse(to_string(exp)) do
      {n, ""} when n > 0 -> {:ok, n}
      _ -> :error
    end
  end

  defp check_size(record, data) do
    cond do
      byte_size(data) > Config.upload_max_size() -> {:error, :too_large}
      byte_size(data) != record.size -> {:error, :bad_request}
      true -> :ok
    end
  end

  defp check_content_type(%{content_type: nil}, _), do: :ok
  defp check_content_type(%{content_type: ""}, _), do: :ok
  defp check_content_type(_record, nil), do: :ok

  defp check_content_type(%{content_type: expected}, given) do
    given_base = given |> String.split(";") |> hd() |> String.trim() |> String.downcase()
    expected_base = expected |> String.split(";") |> hd() |> String.trim() |> String.downcase()

    if given_base == expected_base, do: :ok, else: {:error, :unsupported_media_type}
  end

  defp store_file(record, data) do
    dir = upload_dir()
    File.mkdir_p!(dir)
    tmp = record.path <> ".tmp-#{:erlang.unique_integer([:positive])}"

    with :ok <- File.write(tmp, data),
         :ok <- File.rename(tmp, record.path) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp sign(kind, slot_id, filename, exp) do
    data = "#{kind}:#{slot_id}:#{filename}:#{exp}"
    :crypto.mac(:hmac, :sha256, Config.signing_secret(), data) |> Base.url_encode64(padding: false)
  end

  # Constant-time comparison (hash both sides first so lengths match).
  defp secure_compare(a, b) when is_binary(a) and is_binary(b) do
    :crypto.hash(:sha256, a) == :crypto.hash(:sha256, b) and byte_size(a) == byte_size(b)
  end

  defp secure_compare(_, _), do: false

  defp upload_dir do
    dir = Config.upload_dir()
    if Path.type(dir) == :absolute, do: dir, else: Path.join(File.cwd!(), dir)
  end

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end
  end
end
