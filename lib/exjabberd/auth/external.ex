defmodule Exjabberd.Auth.External do
  @moduledoc """
  External script auth backend — `ejabberd_auth_external` +
  the classic `extauth` protocol (Fase 16).

  A GenServer owns one long-lived OS process (the script named
  by `auth_external_script:` in `exjabberd.yml`, or the
  `EXJABBERD_AUTH_EXTERNAL_SCRIPT` environment variable, which
  wins) and speaks ejabberd's external authentication protocol
  to it over stdio:

      request:  <<len::16-big>> <> "op:user:host:password"
      reply:    <<len::16-big>> <> "0" | "1"

  with ops `auth`, `isuser`, `tryregister`, `setpass` and
  `removeuser` (the password is always the last field, so a
  script should split the payload into at most 4 fields).
  Requests are serialized through the GenServer — one
  outstanding request at a time, exactly like ejabberd's single
  port program. A reply of "1" means success. Timeouts, a dead
  script or a malformed reply fail closed and drop the port;
  the next request respawns the script. Nothing is spawned
  until the first request arrives and a script is configured.
  """

  @behaviour Exjabberd.Auth.Behaviour

  use GenServer

  require Logger

  alias Exjabberd.Config

  @reply_timeout_ms 5_000
  @call_timeout_ms @reply_timeout_ms + 5_000

  # ----------------------------------------------------------------
  # Auth behaviour
  # ----------------------------------------------------------------

  @impl true
  def authenticate(host, user, pass) do
    request("auth:" <> user <> ":" <> host <> ":" <> pass) == :ok
  end

  @impl true
  def user_exists(host, user) do
    request("isuser:" <> user <> ":" <> host) == :ok
  end

  @impl true
  def create_user(host, user, pass) do
    wrap(request("tryregister:" <> user <> ":" <> host <> ":" <> pass))
  end

  @impl true
  def remove_user(host, user) do
    wrap(request("removeuser:" <> user <> ":" <> host))
  end

  @impl true
  def set_password(host, user, pass) do
    wrap(request("setpass:" <> user <> ":" <> host <> ":" <> pass))
  end

  defp wrap(:ok), do: :ok
  defp wrap(_other), do: {:error, :external_auth_failed}

  defp request(payload) do
    if Process.whereis(__MODULE__) do
      try do
        GenServer.call(__MODULE__, {:request, payload}, @call_timeout_ms)
      catch
        :exit, _ -> :error
      end
    else
      :error
    end
  end

  # ----------------------------------------------------------------
  # GenServer
  # ----------------------------------------------------------------

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :worker}
  end

  @impl true
  def init(:ok), do: {:ok, %{port: nil}}

  @impl true
  def handle_call({:request, payload}, _from, state) do
    case ensure_port(state) do
      {:ok, state} ->
        case exchange(state.port, payload) do
          {:ok, reply} ->
            {:reply, if(reply == "1", do: :ok, else: :error), state}

          :error ->
            {:reply, :error, close_port(state)}
        end

      :error ->
        {:reply, :error, state}
    end
  end

  @impl true
  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    Logger.warning("auth external: script exited (status #{status}); will respawn on demand")
    {:noreply, %{state | port: nil}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ----------------------------------------------------------------

  defp ensure_port(%{port: port} = state) when is_port(port), do: {:ok, state}

  defp ensure_port(state) do
    case script_path() do
      nil ->
        :error

      path ->
        try do
          port = Port.open({:spawn_executable, path}, [:binary, :exit_status])
          {:ok, %{state | port: port}}
        rescue
          e ->
            Logger.error("auth external: cannot spawn #{path}: #{Exception.message(e)}")
            :error
        end
    end
  end

  defp close_port(%{port: port} = state) when is_port(port) do
    try do
      Port.close(port)
    rescue
      ArgumentError -> :ok
    end

    %{state | port: nil}
  end

  defp close_port(state), do: state

  defp exchange(port, payload) do
    framed = <<byte_size(payload)::16-big>> <> payload

    try do
      Port.command(port, framed)
    rescue
      ArgumentError -> :error
    else
      true -> read_reply(port, "")
    end
  end

  defp read_reply(port, acc) do
    case decode_reply(acc) do
      {:ok, reply} ->
        {:ok, reply}

      :more ->
        receive do
          {^port, {:data, data}} -> read_reply(port, acc <> data)
          {^port, {:exit_status, _}} -> :error
        after
          @reply_timeout_ms -> :error
        end
    end
  end

  defp decode_reply(<<len::16-big, rest::binary>>) when byte_size(rest) >= len do
    {:ok, binary_part(rest, 0, len)}
  end

  defp decode_reply(_acc), do: :more

  defp script_path do
    cfg =
      if Process.whereis(Config) do
        Config.auth_external_script()
      else
        System.get_env("EXJABBERD_AUTH_EXTERNAL_SCRIPT")
      end

    case cfg do
      s when is_binary(s) and s != "" -> s
      _ -> nil
    end
  end
end
