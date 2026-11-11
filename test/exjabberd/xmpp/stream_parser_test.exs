defmodule Exjabberd.Xmpp.StreamParserTest do
  use ExUnit.Case, async: true

  alias Exjabberd.Xmpp.StreamParser

  test "several stanzas in one packet are all returned" do
    buf =
      "<message id='1'><body>hi</body></message><presence/><iq id='2' type='get'><ping xmlns='urn:xmpp:ping'/></iq>"

    assert {:ok, units, ""} = StreamParser.parse_buffer(buf)
    assert length(units) == 3
    assert Enum.at(units, 0) =~ "<message"
    assert Enum.at(units, 1) == "<presence/>"
    assert Enum.at(units, 2) =~ "ping"
  end

  test "a stanza split across packets stays in the remainder" do
    assert {:ok, [], rest} = StreamParser.parse_buffer("<message id='1'><body>hel")

    assert {:ok, ["<message id='1'><body>hello</body></message>"], ""} =
             StreamParser.parse_buffer(rest <> "lo</body></message>")
  end

  test "stream open tag is complete at its own >" do
    open = "<stream:stream to='localhost' version='1.0'>"
    assert {:ok, [^open], ""} = StreamParser.parse_buffer(open)
    assert {:ok, [^open, "<presence/>"], ""} = StreamParser.parse_buffer(open <> "<presence/>")
  end

  test "a < inside a tag is malformed" do
    assert {:error, :malformed} = StreamParser.parse_buffer("<message><broken<presence/>")
  end

  test "bare text at top level is malformed" do
    assert {:error, :malformed} = StreamParser.parse_buffer("hello")
  end

  test "oversized remainder is rejected with :too_large" do
    assert {:error, :too_large} =
             StreamParser.parse_buffer("<message>" <> String.duplicate("x", 300_000), 262_144)
  end

  test "processing instructions and comments are units" do
    assert {:ok, ["<?xml version='1.0'?>", "<presence/>"], ""} =
             StreamParser.parse_buffer("<?xml version='1.0'?><presence/>")
  end

  test "quoted > inside an attribute does not end the tag" do
    assert {:ok, ["<message to='a>b' type='chat'/>"], ""} =
             StreamParser.parse_buffer("<message to='a>b' type='chat'/>")
  end
end
