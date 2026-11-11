defmodule Exjabberd.Tls do
  @moduledoc """
  TLS certificates for STARTTLS and direct-TLS C2S (RFC 6120 §4.7).

  There is no certificate configured in this repository, so a self-signed
  certificate for `localhost` is generated on first use with the system
  `openssl` binary and kept under `priv/ssl/` (gitignored, never
  committed). In production, point the listeners at a real certificate
  issued for the server domain instead.
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
  `:ssl` client options for outbound STARTTLS (S2S).

  Dev certificates here are self-signed, so verification is off —
  the same trust model as the C2S server side. Production S2S to
  real domains must verify the peer certificate against a real CA
  and check the domain (RFC 6120 §5.4.2); see the README.
  """
  @spec ssl_client_opts() :: keyword()
  def ssl_client_opts do
    [verify: :verify_none, versions: [:"tlsv1.2", :"tlsv1.3"]]
  end

  defp cert_dir do
    case :code.priv_dir(:exjabberd) do
      {:error, _} -> Path.join(File.cwd!(), "priv/ssl")
      dir -> Path.join(to_string(dir), "ssl")
    end
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
          "/CN=localhost"
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
