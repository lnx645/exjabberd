defmodule Exjabberd.S2S.External do
  @moduledoc """
  SASL EXTERNAL authentication for S2S (RFC 6120 §4.8, the mechanism
  ejabberd uses in place of dialback when both sides have TLS
  certificates).

  The peer proves its domain with the X.509 certificate it presented
  during the STARTTLS handshake: authentication succeeds when

  1. the certificate *names* the asserted Sender Domain — a
     `dNSName` subjectAltName, or the subject CN when the
     certificate carries no SAN (`identities/1`); and
  2. the certificate is *trusted* (`trusted?/1`): when
     `s2s_pinned_certs` points at a PEM file, the peer certificate
     must appear in it byte-for-byte (certificate pinning — the
     trust model a small federation can actually operate: each
     peer's self-signed certificate is exchanged out of band and
     pinned). When no pin file is configured, identity alone
     decides; that matches this codebase's `verify_none` TLS stance
     for the dev certificate and is NOT sufficient for the open
     internet — production deployments should configure pinning (or
     terminate S2S at a server with a real CA setup).

  No cryptography is implemented here beyond certificate parsing —
  the TLS handshake itself (`:ssl`) is what proves the peer holds
  the certificate's private key.
  """

  require Logger

  @san_oid {2, 5, 29, 17}
  @cn_oid {2, 5, 4, 3}

  @doc """
  All domain identities a DER certificate carries: every `dNSName`
  subjectAltName, plus the subject CN as a fallback identity only
  when the certificate has no SANs (modern certificates put the
  domain in the SAN; a CN-only certificate is the dev shape). The
  result is downcased.
  """
  @spec identities(binary()) :: [binary()]
  def identities(der) when is_binary(der) do
    case decode(der) do
      {:ok, tbs} ->
        sans = san_names(tbs)

        if sans != [] do
          sans
        else
          cn_names(tbs)
        end

      :error ->
        []
    end
  end

  @doc """
  Trust decision for a DER peer certificate. With a configured
  `s2s_pinned_certs` PEM file: the certificate must be one of the
  pinned certificates (exact DER match). Without one: identity-only
  mode, everything parses as trusted (see the moduledoc for why
  that is a dev-grade stance).
  """
  @spec trusted?(binary()) :: boolean()
  def trusted?(der) when is_binary(der) do
    case pinned_certs() do
      {:ok, ders} -> der in ders
      :identity_only -> true
      {:error, reason} ->
        Logger.warning("S2S EXTERNAL: pinned certs unreadable: #{inspect(reason)}")
        false
    end
  end

  @doc """
  Verify the peer at the other end of an `:ssl` socket for
  `domain`: it must have presented a certificate that names the
  domain and is trusted. Returns `:ok` or `{:error, reason}` with
  reason `:no_peer_cert | :identity_mismatch | :untrusted |
  :bad_cert`.
  """
  @spec verify_peer(:ssl.sslsocket(), binary()) :: :ok | {:error, atom()}
  def verify_peer(socket, domain) do
    case :ssl.peercert(socket) do
      {:ok, der} -> check_cert(der, domain)
      {:error, :no_peercert} -> {:error, :no_peer_cert}
      {:error, _} -> {:error, :no_peer_cert}
    end
  end

  @doc "Certificate check without a socket (unit-testable core)."
  @spec check_cert(binary(), binary()) :: :ok | {:error, atom()}
  def check_cert(der, domain) do
    domain = String.downcase(to_string(domain))

    cond do
      identities(der) == [] -> {:error, :bad_cert}
      domain not in identities(der) -> {:error, :identity_mismatch}
      not trusted?(der) -> {:error, :untrusted}
      true -> :ok
    end
  end

  @doc """
  The configured pin file (`s2s_pinned_certs`), as
  `{:ok, [der]} | :identity_only | {:error, term()}`. Read on every
  call: the file is tiny and an operator (or the two-node test
  harness) may assemble it after boot.
  """
  @spec pinned_certs() :: {:ok, [binary()]} | :identity_only | {:error, term()}
  def pinned_certs do
    case Exjabberd.Config.get("global", :s2s_pinned_certs, nil) do
      path when is_binary(path) and path != "" ->
        case File.read(path) do
          {:ok, pem} ->
            ders =
              pem
              |> :public_key.pem_decode()
              |> Enum.filter(fn {type, _der, _} -> type == :Certificate end)
              |> Enum.map(fn {_type, der, _} -> der end)

            {:ok, ders}

          {:error, reason} ->
            {:error, reason}
        end

      _ ->
        :identity_only
    end
  end

  # --- certificate decoding (OTP :otp form) ---

  defp decode(der) do
    {:OTPCertificate, tbs, _alg, _sig} = :public_key.pkix_decode_cert(der, :otp)
    {:ok, tbs}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  # TBSCertificate record layout (:OTPTBSCertificate): subject is
  # field 6, extensions field 10 of the tuple.
  defp san_names(tbs) do
    tbs
    |> elem(10)
    |> List.wrap()
    |> Enum.filter(fn
      {:Extension, oid, _critical, _value} -> oid == @san_oid
      _ -> false
    end)
    |> Enum.flat_map(fn {:Extension, _oid, _critical, value} ->
      value
      |> List.wrap()
      |> Enum.filter(fn
        {:dNSName, _} -> true
        _ -> false
      end)
      |> Enum.map(fn {:dNSName, name} -> name |> to_string() |> String.downcase() end)
    end)
  end

  defp cn_names(tbs) do
    {:rdnSequence, rdns} = elem(tbs, 6)

    rdns
    |> List.flatten()
    |> Enum.filter(fn
      {:AttributeTypeAndValue, oid, _value} -> oid == @cn_oid
      _ -> false
    end)
    |> Enum.map(fn {:AttributeTypeAndValue, _oid, value} ->
      value |> decode_directory_string() |> String.downcase()
    end)
    |> Enum.reject(&(&1 == ""))
  end

  defp decode_directory_string({:utf8String, s}), do: to_string(s)
  defp decode_directory_string({:printableString, s}), do: to_string(s)
  defp decode_directory_string({:teletexString, s}), do: to_string(s)
  defp decode_directory_string({:bmpString, s}), do: to_string(s)
  defp decode_directory_string({:universalString, s}), do: to_string(s)
  defp decode_directory_string(s) when is_binary(s), do: s
  defp decode_directory_string(s) when is_list(s), do: to_string(s)
  defp decode_directory_string(_), do: ""
end
