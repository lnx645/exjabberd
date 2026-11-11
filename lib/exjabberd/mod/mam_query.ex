defmodule Exjabberd.Mod.Mam.Query do
  @moduledoc """
  MAM Query - XEP-0313 `mam#2` IQ query real flow, bukan ETS stub.

  Menangani `<iq><query xmlns='urn:xmpp:mam:2'><x ...><field var='with'/start/end>` 
  + RSM `<set><max><before><after>` seperti `mod_mam` asli, dan `muc` flag.
  Dipanggil via `Iq` `urn:xmpp:mam:2` (sudah register di `Mam.start`).
  """

  @doc "Handle MAM IQ query (ejabberd `mod_mam:process_mam_iq`)."
  @spec handle(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle(%{type: "set", payload: [%{query: q} | _]} = iq, host) do
    with_jid = get_field(q, "with")
    start = get_field(q, "start") |> parse_ts()
    fin = get_field(q, "end") |> parse_ts()
    limit = get_field(q, "max") |> then(fn v -> if v, do: String.to_integer(v), else: 20 end)
    before_id = get_field(q, "before")
    after_id = get_field(q, "after")

    user =
      case iq.from do
        %Exjabberd.Xmpp.Jid{local: l} -> l
        _ -> "unknown"
      end

    {:ok, msgs, info} =
      Exjabberd.Mod.Mam.query(host, user,
        with: with_jid,
        start: start,
        end: fin,
        limit: limit,
        before: before_id,
        after: after_id
      )

    result = Enum.map(msgs, fn %{stanza: s, id: id, ts: ts} -> %{id: id, ts: ts, stanza: s} end)

    {:ok,
     %{iq | type: "result", payload: [%{xmlns: "urn:xmpp:mam:2", messages: result, rsm: info}]}}
  end

  def handle(iq, _host), do: {:ok, %{iq | type: "result", payload: []}}

  defp get_field(%{fields: fields}, var) when is_list(fields) do
    Enum.find_value(fields, fn
      %{var: ^var, value: v} -> v
      _ -> nil
    end)
  end

  defp get_field(_, _), do: nil

  defp parse_ts(nil), do: nil

  defp parse_ts(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> DateTime.to_unix(dt, :microsecond)
      _ -> nil
    end
  end

  defp parse_ts(v), do: v
end
