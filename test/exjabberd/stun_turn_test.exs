defmodule Exjabberd.StunTurnTest do
  @moduledoc """
  Unit tests for the STUN (RFC 5389) + TURN (RFC 5766) codec:
  framing, XOR addresses, MESSAGE-INTEGRITY, FINGERPRINT, stateless
  nonces and the long-term credential derivation. No sockets here —
  the live server behaviour is covered by `JingleOmemoTest` and
  `test_stun_turn_phase5.py`.
  """
  use ExUnit.Case, async: true

  alias Exjabberd.StunTurn

  @cookie 0x2112A442

  test "binding request encodes and decodes" do
    tid = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>
    raw = StunTurn.encode(%{type: StunTurn.binding_request(), transaction_id: tid, attrs: []})
    assert <<0x00, 0x01, 0x00, 0x00, @cookie::32, ^tid::binary>> = raw
    assert {:ok, %{type: 0x0001, transaction_id: ^tid, attrs: []}} = StunTurn.decode(raw)
  end

  test "decode rejects a bad magic cookie and a short message" do
    assert {:error, :bad_cookie} =
             StunTurn.decode(<<0x00, 0x01, 0x00, 0x00, 0xDEADBEEF::32, 0::96>>)

    assert {:error, :short} = StunTurn.decode(<<0x00, 0x01>>)
  end

  test "xor-mapped-address round-trips for ipv4 and ipv6" do
    tid = StunTurn.new_transaction_id()

    for addr <- [
          {:ipv4, {192, 0, 2, 33}, 54321},
          {:ipv6, {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 1234}
        ] do
      raw =
        StunTurn.encode(%{
          type: StunTurn.binding_success(),
          transaction_id: tid,
          attrs: [{StunTurn.attr_xor_mapped_address(), {:xor, addr, tid}}]
        })

      assert {:ok, msg} = StunTurn.decode(raw)
      assert StunTurn.address_attr(msg, StunTurn.attr_xor_mapped_address()) == addr
    end
  end

  test "message-integrity verifies and detects tampering" do
    key = "test-key-0123456789"
    tid = StunTurn.new_transaction_id()

    raw =
      StunTurn.encode(
        %{
          type: StunTurn.binding_request(),
          transaction_id: tid,
          attrs: [{StunTurn.attr_username(), "alice"}]
        },
        integrity_key: key
      )

    assert StunTurn.verify_integrity(raw, key) == :ok
    assert StunTurn.verify_integrity(raw, "wrong-key") == {:error, :bad_integrity}

    # Flip one byte in the username value.
    tampered = binary_part(raw, 0, byte_size(raw) - 1) <> <<0x00>>
    assert StunTurn.verify_integrity(tampered, key) == {:error, :bad_integrity}

    assert StunTurn.verify_integrity(
             StunTurn.encode(%{type: 1, transaction_id: tid, attrs: []}),
             key
           ) == :no_integrity
  end

  test "fingerprint verifies and detects tampering" do
    tid = StunTurn.new_transaction_id()

    raw =
      StunTurn.encode(%{type: StunTurn.binding_request(), transaction_id: tid, attrs: []},
        fingerprint: true
      )

    assert StunTurn.verify_fingerprint(raw) == :ok

    tampered = binary_part(raw, 0, byte_size(raw) - 1) <> <<0x00>>
    assert StunTurn.verify_fingerprint(tampered) == {:error, :bad_fingerprint}
  end

  test "integrity and fingerprint compose (MI covers up to MI, fingerprint covers all)" do
    key = "another-key"
    tid = StunTurn.new_transaction_id()

    raw =
      StunTurn.encode(
        %{
          type: StunTurn.binding_request(),
          transaction_id: tid,
          attrs: [{StunTurn.attr_username(), "bob"}]
        },
        integrity_key: key,
        fingerprint: true
      )

    assert StunTurn.verify_integrity(raw, key) == :ok
    assert StunTurn.verify_fingerprint(raw) == :ok
  end

  test "stateless nonce round-trips and rejects foreign secrets" do
    secret = "turn-secret"
    nonce = StunTurn.make_nonce(secret)
    assert StunTurn.verify_nonce(secret, nonce) == :ok
    assert StunTurn.verify_nonce("other-secret", nonce) == {:error, :bad_nonce}
    assert StunTurn.verify_nonce(secret, "not-base64!!") == {:error, :bad_nonce}
  end

  test "long-term key is MD5(username:realm:password)" do
    assert StunTurn.long_term_key("alice", "example.org", "secret") ==
             :crypto.hash(:md5, "alice:example.org:secret")
  end

  test "turn password derivation is stable and username-bound" do
    assert StunTurn.turn_password("1234:alice@localhost", "s3cr3t") ==
             StunTurn.turn_password("1234:alice@localhost", "s3cr3t")

    assert StunTurn.turn_password("1234:alice@localhost", "s3cr3t") !=
             StunTurn.turn_password("1234:bob@localhost", "s3cr3t")
  end

  test "channel data encodes and decodes, with padding" do
    assert StunTurn.channel_data?(<<0x40, 0x00, 0x00, 0x05, "hello", 0, 0, 0>>)
    refute StunTurn.channel_data?(<<0x00, 0x01, 0x00, 0x00>>)

    frame = StunTurn.encode_channel_data(0x4000, "hello")
    assert {:ok, 0x4000, "hello", ""} = StunTurn.decode_channel_data(frame)

    frame2 = StunTurn.encode_channel_data(0x4001, "hi") <> "tail"
    assert {:ok, 0x4001, "hi", "tail"} = StunTurn.decode_channel_data(frame2)
  end

  test "error response carries code and reason" do
    tid = StunTurn.new_transaction_id()
    req = %{type: StunTurn.binding_request(), transaction_id: tid, attrs: []}
    raw = StunTurn.error_response(req, 401, "Unauthorized")
    assert {:ok, %{type: 0x0111} = msg} = StunTurn.decode(raw)
    assert StunTurn.attr(msg, StunTurn.attr_error_code()) == {401, "Unauthorized"}
  end
end
