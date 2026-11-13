defmodule Exjabberd.Http.Captcha do
  @moduledoc """
  HTTP captcha endpoint (`/captcha`) — the web half of
  `mod_captcha` (XEP-0158), shaped like ejabberd's captcha flow:

  * `POST /captcha` — create a challenge; the JSON answer carries
    the challenge `id` and its image URL (never the answer itself).
  * `GET /captcha/<id>` — the challenge as a PNG image, rendered
    in-process from a 5×7 bitmap font with noise dots (no image
    library or external tool involved).
  * `POST /captcha/<id>` with `answer=<digits>` (form) or
    `{"answer": "<digits>"}` (JSON) — `200 {"ok":true}` when the
    answer is right, `403 {"ok":false}` otherwise. Challenges are
    single-use and expire after 5 minutes.
  """

  alias Exjabberd.Http.Config

  @doc "Handle a captcha HTTP request. Returns `{status, headers, body}`."
  @spec handle_http(map()) :: {pos_integer(), [{binary(), binary()}], binary()}
  def handle_http(%{method: "POST", path: path} = req) do
    base = Config.path("captcha", "/captcha")

    cond do
      path == base ->
        {:ok, id} = Exjabberd.Mod.Captcha.generate(host())
        body = JSON.encode!(%{"id" => id, "image" => "#{base}/#{id}", "expires_in" => 300})
        {201, [{"content-type", "application/json"}], body}

      String.starts_with?(path, base <> "/") ->
        id = String.replace_prefix(path, base <> "/", "")
        answer = extract_answer(req)

        if not is_nil(answer) and Exjabberd.Mod.Captcha.verify(host(), id, answer) do
          {200, [{"content-type", "application/json"}], ~s({"ok":true})}
        else
          {403, [{"content-type", "application/json"}], ~s({"ok":false})}
        end

      true ->
        {404, [], "Not found"}
    end
  end

  def handle_http(%{method: "GET", path: path}) do
    base = Config.path("captcha", "/captcha")

    if String.starts_with?(path, base <> "/") do
      id = String.replace_prefix(path, base <> "/", "")

      case Exjabberd.Mod.Captcha.answer_for(host(), id) do
        {:ok, answer} -> {200, [{"content-type", "image/png"}], png(answer)}
        :error -> {404, [], "Unknown or expired captcha"}
      end
    else
      {404, [], "Not found"}
    end
  end

  def handle_http(_req), do: {405, [], "Method not allowed"}

  defp host, do: List.first(Exjabberd.Config.hosts()) || "localhost"

  defp extract_answer(req) do
    body = req.body || ""

    cond do
      String.starts_with?(body, "{") ->
        case JSON.decode(body) do
          {:ok, %{"answer" => answer}} -> to_string(answer)
          _ -> nil
        end

      true ->
        case URI.decode_query(body) do
          %{"answer" => answer} -> answer
          _ -> nil
        end
    end
  end

  # --- PNG rendering: 5x7 bitmap digits, scaled, with noise ---

  @font %{
    ?0 => ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
    ?1 => ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
    ?2 => ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
    ?3 => ["11111", "00010", "00100", "00010", "00001", "10001", "01110"],
    ?4 => ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
    ?5 => ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
    ?6 => ["00110", "01000", "10000", "11110", "10001", "10001", "01110"],
    ?7 => ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
    ?8 => ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
    ?9 => ["01110", "10001", "10001", "01111", "00001", "00010", "01100"]
  }
  @scale 6
  @pad 10
  @spacing 8

  @doc "Render a digit string as PNG bytes (grayscale, in-process)."
  @spec png(binary()) :: binary()
  def png(text) do
    digits = String.to_charlist(text)
    glyph_w = 5 * @scale
    glyph_h = 7 * @scale
    width = @pad * 2 + length(digits) * glyph_w + max(length(digits) - 1, 0) * @spacing
    height = @pad * 2 + glyph_h

    dark =
      digits
      |> Enum.with_index()
      |> Enum.flat_map(fn {ch, idx} ->
        x0 = @pad + idx * (glyph_w + @spacing)

        @font
        |> Map.fetch!(ch)
        |> Enum.with_index()
        |> Enum.flat_map(fn {row, gy} ->
          row
          |> String.to_charlist()
          |> Enum.with_index()
          |> Enum.filter(fn {bit, _gx} -> bit == ?1 end)
          |> Enum.flat_map(fn {_bit, gx} ->
            for dx <- 0..(@scale - 1),
                dy <- 0..(@scale - 1),
                do: {x0 + gx * @scale + dx, @pad + gy * @scale + dy}
          end)
        end)
      end)
      |> MapSet.new()

    # Noise: a few hundred gray pixels sprinkled deterministically
    # from the text, so re-rendering the same challenge looks alike.
    :rand.seed(:exsss, :erlang.phash2(text))
    noise = MapSet.new(for _ <- 1..350, do: {:rand.uniform(width) - 1, :rand.uniform(height) - 1})

    rows =
      for y <- 0..(height - 1) do
        line =
          for x <- 0..(width - 1) do
            cond do
              MapSet.member?(dark, {x, y}) -> 30
              MapSet.member?(noise, {x, y}) -> 120
              true -> 245
            end
          end

        IO.iodata_to_binary([0 | line])
      end

    raw = IO.iodata_to_binary(rows)

    IO.iodata_to_binary([
      <<137, 80, 78, 71, 13, 10, 26, 10>>,
      chunk("IHDR", <<width::32, height::32, 8, 0, 0, 0, 0>>),
      chunk("IDAT", :zlib.compress(raw)),
      chunk("IEND", "")
    ])
  end

  defp chunk(type, data) do
    [<<byte_size(data)::32>>, type, data, <<:erlang.crc32(type <> data)::32>>]
  end
end
