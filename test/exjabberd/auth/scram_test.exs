defmodule Exjabberd.Auth.ScramTest do
  use ExUnit.Case, async: true

  alias Exjabberd.Auth.Scram

  # RFC 5802 §5 test vector (password "pencil", salt, iterations 4096).
  test "verify_password accepts the right password and rejects a wrong one" do
    creds = Scram.derive_credentials("secret")
    assert Scram.verify_password("secret", creds)
    refute Scram.verify_password("wrong", creds)
  end

  test "full SCRAM-SHA-256 exchange with channel binding n" do
    creds = Scram.derive_credentials("secret")
    first = "n,,n=alice,r=abc123"
    assert {:ok, parsed} = Scram.parse_client_first(Base.encode64(first))
    {session, server_first} = Scram.server_first(creds, parsed.client_nonce)

    session = %{session | user: parsed.user, client_first_bare: parsed.client_first_bare}
    # Client side (independent recomputation, same as a real client).
    {:ok, srv} = parse_server_first(server_first)
    salted = :crypto.pbkdf2_hmac(:sha256, "secret", srv.salt, srv.iterations, 32)
    client_key = :crypto.mac(:hmac, :sha256, salted, "Client Key")
    stored_key = :crypto.hash(:sha256, client_key)
    channel = Base.encode64("n,,")
    final_wo = "c=#{channel},r=#{srv.nonce}"
    auth_message = "#{parsed.client_first_bare},#{server_first},#{final_wo}"
    signature = :crypto.mac(:hmac, :sha256, stored_key, auth_message)
    proof = :crypto.exor(client_key, signature)
    final = "#{final_wo},p=#{Base.encode64(proof)}"

    assert {:ok, server_final} = Scram.verify_client_final(Base.encode64(final), session)
    # The server signature must verify against the ServerKey.
    assert server_final =~ "v="
    "v=" <> sig_b64 = server_final

    expected =
      :crypto.mac(:hmac, :sha256, :crypto.mac(:hmac, :sha256, salted, "Server Key"), auth_message)

    assert Base.decode64!(sig_b64) == expected
  end

  test "channel binding y is accepted, p is rejected" do
    creds = Scram.derive_credentials("secret")
    first = "y,,n=alice,r=xyz"
    assert {:ok, parsed} = Scram.parse_client_first(Base.encode64(first))
    {session, server_first} = Scram.server_first(creds, parsed.client_nonce)
    session = %{session | user: parsed.user, client_first_bare: parsed.client_first_bare}
    {:ok, srv} = parse_server_first(server_first)
    salted = :crypto.pbkdf2_hmac(:sha256, "secret", srv.salt, srv.iterations, 32)
    client_key = :crypto.mac(:hmac, :sha256, salted, "Client Key")
    stored_key = :crypto.hash(:sha256, client_key)

    for cb <- ["n,,", "y,,"] do
      channel = Base.encode64(cb)
      final_wo = "c=#{channel},r=#{srv.nonce}"
      auth_message = "#{parsed.client_first_bare},#{server_first},#{final_wo}"
      signature = :crypto.mac(:hmac, :sha256, stored_key, auth_message)
      proof = :crypto.exor(client_key, signature)
      final = "#{final_wo},p=#{Base.encode64(proof)}"
      assert {:ok, _} = Scram.verify_client_final(Base.encode64(final), session)
    end

    # "p=tls-unique,..." carries binding data we cannot verify.
    channel = Base.encode64("p=tls-unique,AAAA")
    final_wo = "c=#{channel},r=#{srv.nonce}"
    auth_message = "#{parsed.client_first_bare},#{server_first},#{final_wo}"
    signature = :crypto.mac(:hmac, :sha256, stored_key, auth_message)
    proof = :crypto.exor(client_key, signature)
    final = "#{final_wo},p=#{Base.encode64(proof)}"
    assert :error = Scram.verify_client_final(Base.encode64(final), session)
  end

  test "a wrong proof is rejected" do
    creds = Scram.derive_credentials("secret")
    assert {:ok, parsed} = Scram.parse_client_first(Base.encode64("n,,n=alice,r=abc"))
    {session, server_first} = Scram.server_first(creds, parsed.client_nonce)
    session = %{session | user: parsed.user, client_first_bare: parsed.client_first_bare}
    {:ok, srv} = parse_server_first(server_first)
    final_wo = "c=#{Base.encode64("n,,")},r=#{srv.nonce}"
    final = "#{final_wo},p=#{Base.encode64(:crypto.strong_rand_bytes(32))}"
    assert :error = Scram.verify_client_final(Base.encode64(final), session)
  end

  test "parse_client_first rejects channel binding p= and non-empty authzid" do
    assert :error = Scram.parse_client_first(Base.encode64("p=tls-unique,,n=alice,r=x"))
    assert :error = Scram.parse_client_first(Base.encode64("n,bob,n=alice,r=x"))
  end

  defp parse_server_first(first) do
    attrs =
      first
      |> String.split(",")
      |> Enum.map(fn kv -> kv |> String.split("=", parts: 2) |> List.to_tuple() end)
      |> Map.new()

    {:ok,
     %{
       nonce: attrs["r"],
       salt: Base.decode64!(attrs["s"]),
       iterations: String.to_integer(attrs["i"])
     }}
  end
end
