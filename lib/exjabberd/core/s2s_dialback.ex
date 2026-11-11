defmodule Exjabberd.S2S.Dialback do
  @moduledoc """
  Server Dialback (XEP-0220) — key generation/verification and the
  "call back" verification connection.

  Key formula (XEP-0220 §2.1.1, verified against both worked examples
  in version 0.15 — the printed formula only reproduces them when the
  HMAC key is the *hex encoding* of SHA256(secret), not the raw digest):

      key = HMAC-SHA256(hexlower(SHA256(secret)), "to from stream-id")

  where `from` is the Sender (initiating) domain, `to` is the Target
  (receiving) domain, and `stream-id` is the stream ID the Receiving
  Server put in the stream header it sent to the Initiating Server.

  The secret comes from configuration (`s2s_dialback_secret`); when
  it is not configured, the application generates a random ephemeral
  secret at boot (see `Exjabberd.Application`). The secret is never
  hardcoded and never logged.

  The verification connection (`verify_remote/4`) is a plain-TCP
  connection to the Authoritative Server for the Sender Domain: open
  a server stream, send `<db:verify/>`, read the valid/invalid answer
  and close again — exactly the "verify-only connection" XEP-0220
  §2.1.2 allows ("Not using TLS ... can reduce the number of round
  trips"). A server that requires STARTTLS for S2S therefore cannot
  be verified this way; that is a documented limitation.
  """

  require Logger

  @dialback_ns "jabber:server:dialback"
  @stream_ns "http://etherx.jabber.org/streams"

  @doc """
  Generate a dialback key for (`stream_id`, `from`, `to`).

  `from` is the Sender/initiating domain, `to` the Target/receiving
  domain, `stream_id` the Receiving Server's stream ID.
  """
  @spec generate_key(binary(), binary(), binary(), binary()) :: binary()
  def generate_key(secret, stream_id, from, to) do
    hmac_key = :crypto.hash(:sha256, secret) |> Base.encode16(case: :lower)
    message = "#{to} #{from} #{stream_id}"

    :crypto.mac(:hmac, :sha256, hmac_key, message)
    |> Base.encode16(case: :lower)
  end

  @doc """
  Verify a dialback key. Recomputes the expected key and compares in
  constant time, so a wrong key, wrong stream ID or wrong domain pair
  all fail the same way.
  """
  @spec verify_key(binary(), binary(), binary(), binary(), binary()) :: boolean()
  def verify_key(secret, stream_id, from, to, key) when is_binary(key) do
    expected = generate_key(secret, stream_id, from, to)
    :crypto.hash_equals(expected, String.downcase(String.trim(key)))
  rescue
    _ -> false
  end

  def verify_key(_, _, _, _, _), do: false

  @doc """
  The dialback secret for this server, from configuration
  (`s2s_dialback_secret`). The application guarantees a value is set
  at boot (generating an ephemeral one when unconfigured).
  """
  @spec secret() :: binary()
  def secret do
    case Exjabberd.Config.get("global", :s2s_dialback_secret, nil) do
      secret when is_binary(secret) and secret != "" -> secret
      _ -> raise "s2s dialback secret is not configured (see Exjabberd.Application)"
    end
  end

  @doc """
  Verify `key` with the Authoritative Server for `from_domain`.

  Opens a short-lived server stream to the authoritative server
  (resolved via `Exjabberd.S2S.resolve/1`, so configured host
  overrides apply), sends `<db:verify from=<to_domain>
  to=<from_domain> id=<stream_id>>key</db:verify>` and returns `:ok`
  when the authoritative server answers `type='valid'`, `{:error,
  :invalid}` when it answers anything else, and `{:error, reason}`
  when the authoritative server cannot be reached at all.
  """
  @spec verify_remote(binary(), binary(), binary(), binary()) ::
          :ok | {:error, term()}
  def verify_remote(from_domain, to_domain, stream_id, key) do
    verify_remote(from_domain, to_domain, stream_id, key, 10_000)
  end

  @spec verify_remote(binary(), binary(), binary(), binary(), pos_integer()) ::
          :ok | {:error, term()}
  def verify_remote(from_domain, to_domain, stream_id, key, timeout) do
    with {:ok, {host, port}} <- Exjabberd.S2S.resolve(from_domain),
         {:ok, sock} <-
           :gen_tcp.connect(connect_host(host), port, [:binary, packet: 0, active: false], 5_000),
         :ok <- :gen_tcp.send(sock, stream_header(to_domain, from_domain)),
         {:ok, _features} <- recv_until(sock, "<stream:features", timeout),
         :ok <-
           :gen_tcp.send(
             sock,
             "<db:verify xmlns:db='#{@dialback_ns}' from='#{to_domain}' " <>
               "to='#{from_domain}' id='#{stream_id}'>#{key}</db:verify>"
           ),
         {:ok, reply} <- recv_until(sock, "db:verify", timeout) do
      :gen_tcp.close(sock)

      if reply =~ ~r/type\s*=\s*['"]valid['"]/,
        do: :ok,
        else: {:error, :invalid}
    else
      {:error, reason} = err ->
        Logger.debug("dialback verify to #{from_domain} failed: #{inspect(reason)}")
        err

      other ->
        {:error, other}
    end
  catch
    :exit, reason -> {:error, reason}
  end

  @doc "Server stream header (jabber:server) for `from` → `to`."
  @spec stream_header(binary(), binary()) :: binary()
  def stream_header(from, to) do
    "<?xml version='1.0'?><stream:stream xmlns='jabber:server' " <>
      "xmlns:stream='#{@stream_ns}' xmlns:db='#{@dialback_ns}' " <>
      "from='#{from}' to='#{to}' version='1.0'>"
  end

  # `:gen_tcp.connect/4` wants a charlist hostname or an IP tuple.
  defp connect_host(host) when is_tuple(host), do: host
  defp connect_host(host) when is_binary(host), do: String.to_charlist(host)
  defp connect_host(host) when is_list(host), do: host

  # Read until `needle` appears in the accumulated bytes, or the
  # timeout / socket close hits. Returns the bytes read so far.
  defp recv_until(sock, needle, timeout) do
    recv_until(sock, needle, timeout, "")
  end

  defp recv_until(_sock, _needle, timeout, _acc) when timeout <= 0, do: {:error, :timeout}

  defp recv_until(sock, needle, timeout, acc) do
    if String.contains?(acc, needle) do
      {:ok, acc}
    else
      started = System.monotonic_time(:millisecond)

      case :gen_tcp.recv(sock, 0, timeout) do
        {:ok, data} ->
          elapsed = System.monotonic_time(:millisecond) - started
          recv_until(sock, needle, max(timeout - elapsed, 0), acc <> data)

        {:error, :closed} ->
          if String.contains?(acc, needle), do: {:ok, acc}, else: {:error, :closed}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end
end
