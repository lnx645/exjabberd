defmodule Exjabberd.Xmpp.StreamParser do
  @moduledoc """
  Incremental XMPP stream parser (RFC 6120 §4.7).

  Splits a raw TCP byte stream into complete top-level XML units
  (stream open, stanzas, stream close, processing instructions) without
  losing data: a unit split across TCP packets stays in the remainder
  buffer, and several units arriving in one packet are all returned.

  This replaces the old string-matching splitter, which dropped every
  stanza after the first one in a packet and silently swallowed the rest.

  Returns `{:ok, units, rest}` on success, `{:error, :malformed}` when
  the bytes can never become valid XML (for example a `<` inside a tag
  or bare text at top level), and `{:error, :too_large}` when the
  unparsed remainder exceeds `max_size` (ejabberd default 262144 bytes).
  """

  @default_max_size 262_144

  @doc "Parse as many complete top-level XML units as possible from `buf`."
  @spec parse_buffer(binary(), non_neg_integer()) ::
          {:ok, [binary()], binary()} | {:error, :malformed | :too_large}
  def parse_buffer(buf, max_size \\ @default_max_size) do
    if byte_size(buf) > max_size do
      {:error, :too_large}
    else
      scan(buf, [])
    end
  end

  defp scan(<<>>, acc), do: {:ok, Enum.reverse(acc), ""}

  defp scan(buf, acc) do
    buf = skip_ws(buf)

    case buf do
      <<>> ->
        {:ok, Enum.reverse(acc), ""}

      _ ->
        case take_unit(buf) do
          {:ok, unit, rest} -> scan(rest, [unit | acc])
          {:incomplete, _} -> {:ok, Enum.reverse(acc), buf}
          {:error, _} = err -> err
        end
    end
  end

  defp skip_ws(<<c, rest::binary>>) when c in [?\s, ?\t, ?\r, ?\n], do: skip_ws(rest)
  defp skip_ws(buf), do: buf

  # One complete unit from the front of the buffer.
  defp take_unit(<<"<?", _::binary>> = buf), do: take_until(buf, "?>")
  defp take_unit(<<"<!--", _::binary>> = buf), do: take_until(buf, "-->")
  defp take_unit(<<"</", _::binary>> = buf), do: parse_tag(buf)

  defp take_unit(<<"<", _::binary>> = buf) do
    case tag_name(buf) do
      {:ok, "stream:stream"} ->
        # The stream open tag is never closed by a matching end tag;
        # it is complete as soon as its own ">" is found.
        parse_tag(buf)

      {:ok, _} ->
        take_element(buf)

      {:incomplete} ->
        {:incomplete, buf}

      {:error, _} = err ->
        err
    end
  end

  defp take_unit(_), do: {:error, :malformed}

  # Read the tag name after "<". Returns {:ok, name} when the name is
  # terminated by whitespace, ">" or "/>", {:incomplete} when the buffer
  # ends mid-name, {:error, :malformed} when the name is empty/invalid.
  defp tag_name(<<"<", rest::binary>>), do: tag_name(rest, "")

  defp tag_name(<<>>, _acc), do: {:incomplete}

  defp tag_name(<<c, _::binary>>, acc)
       when c in [?\s, ?\t, ?\r, ?\n, ?>, ?/] and acc != "" do
    {:ok, acc}
  end

  defp tag_name(<<c, rest::binary>>, acc)
       when (c >= ?a and c <= ?z) or (c >= ?A and c <= ?Z) or (c >= ?0 and c <= ?9) or
              c in [?:, ?-, ?_, ?.] do
    tag_name(rest, acc <> <<c>>)
  end

  defp tag_name(_, _), do: {:error, :malformed}

  # A complete element, tracking nesting depth. The first tag opens the
  # element (depth 1); the unit is complete when depth returns to 0.
  defp take_element(buf), do: take_element_loop(buf, buf, 0, 0)

  defp take_element_loop(full, <<>>, _depth, _taken), do: {:incomplete, full}

  defp take_element_loop(full, <<?<, _::binary>> = rest, depth, taken) do
    case parse_tag(rest) do
      {:ok, tag, rest2} ->
        taken2 = taken + byte_size(tag)

        cond do
          String.starts_with?(tag, "<?") or String.starts_with?(tag, "<!--") or
              String.starts_with?(tag, "<![CDATA[") ->
            take_element_loop(full, rest2, depth, taken2)

          String.starts_with?(tag, "</") ->
            cond do
              depth == 1 -> {:ok, binary_part(full, 0, taken2), rest2}
              depth > 1 -> take_element_loop(full, rest2, depth - 1, taken2)
              true -> {:error, :malformed}
            end

          String.ends_with?(tag, "/>") ->
            if depth == 0 do
              {:ok, tag, rest2}
            else
              take_element_loop(full, rest2, depth, taken2)
            end

          true ->
            take_element_loop(full, rest2, depth + 1, taken2)
        end

      {:incomplete, _} ->
        {:incomplete, full}

      {:error, _} = err ->
        err
    end
  end

  defp take_element_loop(full, rest, depth, taken) do
    # Text content: skip to the next "<".
    case :binary.split(rest, "<") do
      [_only] ->
        {:incomplete, full}

      [text, after_lt] ->
        take_element_loop(full, "<" <> after_lt, depth, taken + byte_size(text))
    end
  end

  # Parse one tag starting at "<". Handles PI, comments and CDATA by
  # their terminators; normal tags end at ">" outside quotes. A "<"
  # inside a tag (outside quotes) is malformed XML.
  defp parse_tag(<<"<!--", _::binary>> = bin), do: take_until(bin, "-->")
  defp parse_tag(<<"<?", _::binary>> = bin), do: take_until(bin, "?>")
  defp parse_tag(<<"<![CDATA[", _::binary>> = bin), do: take_until(bin, "]]>")
  defp parse_tag(<<"<", _::binary>> = bin), do: scan_tag(bin, 1, nil)

  defp take_until(bin, marker) do
    case :binary.match(bin, marker) do
      {idx, len} ->
        {:ok, binary_part(bin, 0, idx + len),
         binary_part(bin, idx + len, byte_size(bin) - idx - len)}

      :nomatch ->
        {:incomplete, bin}
    end
  end

  defp scan_tag(bin, pos, _quote) when pos >= byte_size(bin), do: {:incomplete, bin}

  defp scan_tag(bin, pos, quote) do
    <<_::binary-size(pos), c, _::binary>> = bin

    cond do
      quote != nil and c == quote ->
        scan_tag(bin, pos + 1, nil)

      quote != nil ->
        scan_tag(bin, pos + 1, quote)

      c in [?", ?'] ->
        scan_tag(bin, pos + 1, c)

      c == ?< ->
        {:error, :malformed}

      c == ?> ->
        {:ok, binary_part(bin, 0, pos + 1), binary_part(bin, pos + 1, byte_size(bin) - pos - 1)}

      true ->
        scan_tag(bin, pos + 1, nil)
    end
  end
end
