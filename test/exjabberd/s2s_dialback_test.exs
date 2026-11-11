defmodule Exjabberd.S2SDialbackTest do
  @moduledoc """
  Unit tests for XEP-0220 dialback keys (XEP-0220 §2.1.1) and S2S
  domain resolution. The live two-node behaviour is covered by
  `test_s2s.py` (real sockets, real dialback round-trips).
  """
  use ExUnit.Case, async: false

  alias Exjabberd.S2S.Dialback

  # XEP-0220 v0.15 worked examples (§2.1.1 step 1, §2.1.2 step 2).
  # The printed formula only reproduces these values when the HMAC
  # key is the *hex encoding* of SHA256(secret) — see Dialback docs.
  test "key generation matches the XEP-0220 worked examples" do
    assert Dialback.generate_key("s3cr3tf0rd14lb4ck", "D60000229F", "capulet.example", "montague.example") ==
             "b4835385f37fe2895af6c196b59097b16862406db80559900d96bf6fa7d23df3"

    assert Dialback.generate_key("d14lb4ck43v3r", "417GAF25", "montague.example", "capulet.example") ==
             "225cc5aa6a071133249d25fef42ae516fc7a86c523aa1c6980a7f73e784c972d"
  end

  test "verify accepts the generated key and rejects anything else" do
    secret = "test-secret-#{System.unique_integer([:positive])}"
    key = Dialback.generate_key(secret, "STREAMID1", "a.localhost", "b.localhost")

    assert Dialback.verify_key(secret, "STREAMID1", "a.localhost", "b.localhost", key)
    refute Dialback.verify_key(secret, "STREAMID1", "a.localhost", "b.localhost", "0" <> key)
    refute Dialback.verify_key(secret, "OTHERSTREAM", "a.localhost", "b.localhost", key)
    refute Dialback.verify_key(secret, "STREAMID1", "a.localhost", "evil.example", key)
    refute Dialback.verify_key("wrong-secret", "STREAMID1", "a.localhost", "b.localhost", key)
    refute Dialback.verify_key(secret, "STREAMID1", "a.localhost", "b.localhost", "")
    refute Dialback.verify_key(secret, "STREAMID1", "a.localhost", "b.localhost", nil)
  end

  test "generate/verify round-trip through mod_s2s_dialback" do
    key =
      case Exjabberd.Mod.S2S.generate("STREAMID9", "a.localhost", "b.localhost") do
        {:ok, k} -> k
      end

    assert Exjabberd.Mod.S2S.verify("STREAMID9", "a.localhost", "b.localhost", key)
    refute Exjabberd.Mod.S2S.verify("STREAMID9", "a.localhost", "b.localhost", key <> "00")
  end

  test "host overrides resolve without DNS" do
    :ok = Exjabberd.Config.set(:global, :s2s_host_overrides, %{"b.localhost" => {"127.0.0.1", 5270}})

    assert {:ok, {"127.0.0.1", 5270}} = Exjabberd.S2S.resolve("b.localhost")
    assert {:ok, {"127.0.0.1", 5270}} = Exjabberd.S2S.resolve("B.LOCALHOST")

    :ok = Exjabberd.Config.set(:global, :s2s_host_overrides, %{})
  end

  test "plain DNS/hosts fallback resolves on port 5269" do
    # NOTE: the sandbox resolver answers for every name (egress
    # proxy wildcard), so a negative NXDOMAIN test is meaningless
    # here — assert the fallback path instead.
    :ok = Exjabberd.Config.set(:global, :s2s_host_overrides, %{})
    assert {:ok, {_host, 5269}} = Exjabberd.S2S.resolve("localhost")
  end
end
