defmodule Exjabberd.Tls do
  @moduledoc """
  TLS certificates for STARTTLS and direct-TLS C2S (RFC 6120 §4.7).

  There is no certificate configured in this repository, so a self-signed
  certificate is generated on first use with the system `openssl`
  binary and kept under `priv/ssl/` (gitignored, never committed).
  Its subjectAltName covers `localhost` plus every configured host —
  SASL EXTERNAL for S2S authenticates a server by the domains its
  certificate names. In production, point the listeners at a real
  certificate issued for the server domain instead.
  """

  require Logger

  @doc "Ensure a certificate/key pair exists; returns `{:ok, {cert, key}}`."
  @spec ensure_cert() :: {:ok, {binary(), binary()}} | {:error, term()}
  def ensure_cert do
    dir = cert_dir()
    cert = Path.join(dir, "cert.pem")
    key = Path.join(dir, "key.pem")

    if File.exists?(cert) and File.exists?(key) do
      {:ok, {cert, key}}
    else
      generate(dir, cert, key)
    end
  end

  @doc "`:ssl` server options for a certificate/key pair."
  @spec ssl_opts({binary(), binary()}) :: keyword()
  def ssl_opts({cert, key}) do
    [
      certfile: String.to_charlist(cert),
      keyfile: String.to_charlist(key),
      verify: :verify_none,
      versions: [:"tlsv1.2", :"tlsv1.3"]
    ]
  end

  @doc """
  `:ssl` server options for the S2S listener: like `ssl_opts/1`,
  but the peer is asked for a certificate
  (`verify: :verify_peer` with `fail_if_no_peer_cert: false`) —
  without a CertificateRequest in the handshake a client never
  sends one, and SASL EXTERNAL would have nothing to check.
  Chain validation stays off (self-signed dev certificates);
  EXTERNAL applies its own identity + pinning checks to whatever
  certificate arrives, and peers without one simply use dialback.
  """
  @spec ssl_opts_s2s({binary(), binary()}) :: keyword()
  def ssl_opts_s2s(pair) do
    pair
    |> ssl_opts()
    |> Keyword.delete(:verify)
    |> Keyword.merge(
      verify: :verify_peer,
      fail_if_no_peer_cert: false,
      cacerts: [],
      verify_fun: {&accept_any_peer_cert/3, nil}
    )
  end

  # Chain validation is deliberately a no-op here: there is no CA
  # in this codebase's trust model (self-signed dev certificates),
  # and `:ssl` refuses `verify_peer` without cacerts/verify_fun.
  # The trust decision lives one layer up, in
  # `Exjabberd.S2S.External` (certificate identity + pinning) —
  # this callback only makes the handshake *carry* the peer
  # certificate so that layer can see it.
  defp accept_any_peer_cert(_cert_or_event, _event, state), do: {:valid, state}

  @doc """
  `:ssl` client options for outbound STARTTLS (S2S).

  Dev certificates here are self-signed, so verification is off —
  the same trust model as the C2S server side. Production S2S to
  real domains must verify the peer certificate against a real CA
  and check the domain (RFC 6120 §5.4.2); see the README.

  Our own certificate is presented when one is available: SASL
  EXTERNAL (see `Exjabberd.S2S.External`) authenticates the
  *initiating* server by the client certificate it shows during
  this handshake, so an outbound connection without one could
  never use EXTERNAL.
  """
  @spec ssl_client_opts() :: keyword()
  def ssl_client_opts do
    base = [verify: :verify_none, versions: [:"tlsv1.2", :"tlsv1.3"]]

    case ensure_cert() do
      {:ok, {cert, key}} ->
        base ++
          [certfile: String.to_charlist(cert), keyfile: String.to_charlist(key)]

      {:error, _} ->
        base
    end
  end

  defp cert_dir do
    case :code.priv_dir(:exjabberd) do
      {:error, _} -> Path.join(File.cwd!(), "priv/ssl")
      dir -> Path.join(to_string(dir), "ssl")
    end
  end

  # SAN list for a freshly generated certificate: `localhost` plus
  # every configured host, so the certificate actually names the
  # domains this server serves (SASL EXTERNAL identity checks rely
  # on it). Config may not be running in every caller context —
  # fall back to localhost only.
  defp san_list do
    hosts =
      try do
        Exjabberd.Config.hosts()
      rescue
        _ -> []
      catch
        _, _ -> []
      end

    (["localhost"] ++ hosts)
    |> Enum.map(&to_string/1)
    |> Enum.uniq()
    |> Enum.map(&"DNS:#{&1}")
    |> Enum.join(",")
  end

  defp generate(dir, cert, key) do
    File.mkdir_p!(dir)

    case System.find_executable("openssl") do
      nil ->
        {:error, :openssl_not_found}

      openssl ->
        args = [
          "req",
          "-x509",
          "-newkey",
          "rsa:2048",
          "-keyout",
          key,
          "-out",
          cert,
          "-days",
          "3650",
          "-nodes",
          "-subj",
          "/CN=localhost",
          "-addext",
          "subjectAltName=#{san_list()}"
        ]

        case System.cmd(openssl, args, stderr_to_stdout: true) do
          {_, 0} ->
            File.chmod!(key, 0o600)
            Logger.info("TLS self-signed certificate generated at #{cert}")
            {:ok, {cert, key}}

          {out, code} ->
            {:error, "openssl req failed (exit #{code}): #{out}"}
        end
    end
  end
end
