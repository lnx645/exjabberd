defmodule Exjabberd.S2SExternalTest do
  @moduledoc """
  Unit tests for SASL EXTERNAL S2S certificate checks
  (`Exjabberd.S2S.External`): identity extraction from SAN / CN
  and the pinning trust decision. The live handshake (mechanism
  offer, `<auth/>`, restart, refusal cases) is covered by
  `test_s2s_external_bidi_phase19.py`.

  Fixtures are throwaway self-signed certificates (public certs
  only — no private keys are committed):
  `test/support/certs/b_localhost.pem` (CN=b.localhost, SAN
  DNS:b.localhost + DNS:localhost) and `plain_example.pem`
  (CN=plain.example, no SAN).
  """

  use ExUnit.Case, async: false

  alias Exjabberd.S2S.External

  defp der(name) do
    path = Path.join([__DIR__, "..", "support", "certs", name])
    [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(File.read!(path))
    der
  end

  test "identities come from the SAN dNSNames when present" do
    ids = External.identities(der("b_localhost.pem"))
    assert "b.localhost" in ids
    assert "localhost" in ids
    # The CN is also b.localhost here; SANs win and are not merged
    # with anything else.
    assert Enum.sort(ids) == ["b.localhost", "localhost"]
  end

  test "identities fall back to the subject CN without SANs" do
    assert External.identities(der("plain_example.pem")) == ["plain.example"]
  end

  test "identities of garbage are empty" do
    assert External.identities("not a certificate") == []
    assert External.check_cert("not a certificate", "b.localhost") == {:error, :bad_cert}
  end

  test "check_cert accepts the named domain and rejects others (identity-only mode)" do
    assert Exjabberd.Config.s2s_pinned_certs() == nil
    der = der("b_localhost.pem")
    assert External.check_cert(der, "b.localhost") == :ok
    assert External.check_cert(der, "B.LOCALHOST") == :ok
    assert External.check_cert(der, "a.localhost") == {:error, :identity_mismatch}
    assert External.check_cert(der("plain_example.pem"), "plain.example") == :ok
  end

  test "pinning: only the pinned certificate is trusted" do
    bundle =
      Path.join(System.tmp_dir!(), "pinned-#{System.unique_integer([:positive])}.pem")

    File.write!(bundle, File.read!(Path.join([__DIR__, "..", "support", "certs", "b_localhost.pem"])))
    Exjabberd.Config.set(:global, :s2s_pinned_certs, bundle)

    try do
      assert External.trusted?(der("b_localhost.pem"))
      refute External.trusted?(der("plain_example.pem"))
      assert External.check_cert(der("b_localhost.pem"), "b.localhost") == :ok

      assert External.check_cert(der("plain_example.pem"), "plain.example") ==
               {:error, :untrusted}
    after
      Exjabberd.Config.set(:global, :s2s_pinned_certs, nil)
      File.rm(bundle)
    end
  end
end
