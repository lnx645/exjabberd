defmodule Exjabberd.Mod.Mam.Query do
  @moduledoc """
  MAM IQ handler — XEP-0313 (`urn:xmpp:mam:2`).

  Handles, on the requesting user's (or room's) JID:

  * IQ-set `<query/>` — archive query with an optional `jabber:x:data`
    form (`with` / `start` / `end`, XEP-0082 timestamps) and an RSM
    `<set/>` (`max` / `before` / `after`, XEP-0059). Each match is
    sent back as its own `<message/>` carrying
    `<result queryid id><forwarded><delay/><message/></forwarded></result>`,
    and the IQ result itself carries only
    `<fin complete><set><first/><last/><count/></set></fin>`.
  * IQ-get / IQ-set `<prefs/>` — get/set archiving preferences
    (`default='always|never|roster'`, `<always/>` / `<never/>` JID
    lists).

  A query addressed to `room@conference.host` reads the room archive
  (written by `Exjabberd.Mod.Mam.archive_muc/5`); anything else reads
  the requesting user's own archive. Room archives are only served
  to occupants and affiliated users of the room (ejabberd behaves
  the same way); everyone else gets `forbidden`.
  """

  require Logger

  alias Exjabberd.Mod.Mam
  alias Exjabberd.Xmpp.{Codec, Jid, Stanza}

  @mam_ns "urn:xmpp:mam:2"
  @rsm_ns "http://jabber.org/protocol/rsm"
  @forward_ns "urn:xmpp:forward:0"
  @delay_ns "urn:xmpp:delay"

  @doc "Handle a MAM IQ (query or prefs)."
  @spec handle(map(), binary()) :: {:ok, map()} | {:error, term()}
  def handle(%{type: type} = iq, host) when type in ["get", "set"] do
    payload = iq.payload || []

    cond do
      Stanza.child(payload, "prefs") != nil ->
        handle_prefs(iq, host, Stanza.child(payload, "prefs"))

      Stanza.child(payload, "query") != nil ->
        handle_query(iq, host, Stanza.child(payload, "query"))

      true ->
        {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}
    end
  end

  def handle(iq, _host),
    do: {:error, :bad_request, Exjabberd.Iq.error_iq(iq, "bad-request")}

  # --- prefs ---

  defp handle_prefs(%{type: "get"} = iq, host, _prefs_el) do
    {:ok, prefs} = Mam.get_prefs(host, requester_user(iq))
    {:ok, %{iq | type: "result", payload: [prefs_element(prefs)]}}
  end

  defp handle_prefs(%{type: "set"} = iq, host, prefs_el) do
    default = prefs_el.attrs["default"] || Mam.default_pref(host)
    always = jid_list(prefs_el, "always")
    never = jid_list(prefs_el, "never")

    {:ok, prefs} =
      Mam.set_prefs(host, requester_user(iq), %{default: default, always: always, never: never})

    {:ok, %{iq | type: "result", payload: [prefs_element(prefs)]}}
  end

  defp prefs_element(prefs) do
    %{
      name: "prefs",
      attrs: %{"xmlns" => @mam_ns, "default" => prefs.default},
      children: [
        %{name: "always", attrs: %{}, children: Enum.map(prefs.always, &jid_element/1)},
        %{name: "never", attrs: %{}, children: Enum.map(prefs.never, &jid_element/1)}
      ]
    }
  end

  defp jid_element(jid), do: %{name: "jid", attrs: %{}, children: [jid]}

  defp jid_list(prefs_el, name) do
    case Stanza.child(prefs_el.children, name) do
      nil -> []
      el -> Enum.map(el.children, &Stanza.text_of/1)
    end
  end

  # --- query ---

  defp handle_query(iq, host, query_el) do
    owner = query_owner(iq, host)

    # Room archives are private to the room: the requester must be
    # an occupant or hold an affiliation in that room.
    if room_archive?(iq) and not room_member?(host, owner, requester_bare(iq)) do
      {:error, :forbidden, Exjabberd.Iq.error_iq(iq, "forbidden")}
    else
      do_handle_query(iq, host, query_el, owner)
    end
  end

  defp room_archive?(iq) do
    case iq.to do
      %Jid{local: local, domain: "conference." <> _} when is_binary(local) and local != "" ->
        true

      _ ->
        false
    end
  end

  defp room_member?(host, room_jid, bare) do
    case Exjabberd.Mod.Muc.occupants(host, room_jid) do
      {:ok, state} ->
        affiliated = Map.get(state.affiliations, bare) in [:owner, :admin, :member]
        occupant = Enum.any?(state.occupants, fn {_nick, occ} -> occ.jid == bare end)
        affiliated or occupant

      _ ->
        false
    end
  end

  defp do_handle_query(iq, host, query_el, owner) do
    queryid = query_el.attrs["queryid"]
    form = Stanza.child(query_el.children, "x")
    rsm = Stanza.child(query_el.children, "set")

    with_jid = form_field(form, "with")
    start_ts = form_field(form, "start") |> parse_ts()
    end_ts = form_field(form, "end") |> parse_ts()
    limit = rsm_value(rsm, "max") |> parse_limit()
    before_id = rsm_value(rsm, "before")
    after_id = rsm_value(rsm, "after")

    {:ok, records, info} =
      Mam.query(host, owner,
        with: with_jid,
        start: start_ts,
        end: end_ts,
        limit: limit,
        before: before_id,
        after: after_id
      )

    requester = iq.from
    Enum.each(records, fn rec -> send_result(requester, queryid, rec) end)

    {:ok, %{iq | type: "result", payload: [fin_element(queryid, info)]}}
  end

  # One archived message back to the requester, as XEP-0313 §5.2
  # requires: a <message/> from the server wrapping the original
  # stanza in <forwarded/> with its <delay/> stamp.
  defp send_result(requester, queryid, rec) do
    original =
      case Codec.parse_xml(rec.xml) do
        {:ok, el} -> el
        {:error, _} -> %{name: "message", attrs: %{}, children: []}
      end

    attrs = %{"xmlns" => @mam_ns, "id" => rec.id}
    attrs = if queryid, do: Map.put(attrs, "queryid", queryid), else: attrs

    result = %{
      name: "result",
      attrs: attrs,
      children: [
        %{
          name: "forwarded",
          attrs: %{"xmlns" => @forward_ns},
          children: [
            %{
              name: "delay",
              attrs: %{
                "xmlns" => @delay_ns,
                "stamp" => Mam.delay_stamp(rec.ts),
                "from" => rec.from
              },
              children: []
            },
            original
          ]
        }
      ]
    }

    stanza =
      Stanza.new(:message,
        from: "localhost",
        to: requester,
        payload: [result]
      )

    Exjabberd.Router.route(stanza)
  end

  defp fin_element(queryid, info) do
    attrs = %{"xmlns" => @mam_ns, "complete" => to_string(info.complete)}
    attrs = if queryid, do: Map.put(attrs, "queryid", queryid), else: attrs

    set_children =
      [
        info.first && %{name: "first", attrs: %{"index" => "0"}, children: [info.first]},
        info.last && %{name: "last", attrs: %{}, children: [info.last]},
        %{name: "count", attrs: %{}, children: [to_string(info.count)]}
      ]
      |> Enum.reject(&is_nil/1)

    %{
      name: "fin",
      attrs: attrs,
      children: [%{name: "set", attrs: %{"xmlns" => @rsm_ns}, children: set_children}]
    }
  end

  # --- helpers ---

  # MUC query: the IQ is addressed to the room; otherwise the
  # requester's own bare JID owns the archive.
  defp query_owner(iq, _host) do
    case iq.to do
      %Jid{domain: "conference." <> _} = room -> Jid.bare(room)
      %Jid{local: local, domain: domain} when is_binary(local) -> "#{local}@#{domain}"
      bin when is_binary(bin) -> Jid.bare(bin)
      _ -> requester_bare(iq)
    end
  end

  defp requester_bare(iq) do
    case iq.from do
      %Jid{} = jid -> Jid.bare(jid)
      bin when is_binary(bin) -> Jid.bare(bin)
      _ -> ""
    end
  end

  defp requester_user(iq) do
    case iq.from do
      %Jid{local: local} when is_binary(local) -> local
      bin when is_binary(bin) -> bin |> String.split("@") |> hd()
      _ -> ""
    end
  end

  defp form_field(nil, _var), do: nil

  defp form_field(form, var) do
    Enum.find_value(form.children, fn
      %{name: "field", attrs: %{"var" => ^var}, children: children} ->
        Stanza.child_text(children, "value")

      _ ->
        nil
    end)
  end

  defp rsm_value(nil, _name), do: nil

  defp rsm_value(set, name) do
    case Stanza.child(set.children, name) do
      nil -> nil
      el -> Stanza.text_of(el)
    end
  end

  defp parse_ts(nil), do: nil

  defp parse_ts(str) when is_binary(str) do
    case DateTime.from_iso8601(String.trim(str)) do
      {:ok, dt, _} -> DateTime.to_unix(dt, :microsecond)
      _ -> nil
    end
  end

  defp parse_ts(_), do: nil

  defp parse_limit(nil), do: Mam.default_page_size()

  defp parse_limit(str) when is_binary(str) do
    case Integer.parse(String.trim(str)) do
      {n, ""} when n > 0 -> n
      _ -> Mam.default_page_size()
    end
  end

  defp parse_limit(n) when is_integer(n) and n > 0, do: n
  defp parse_limit(_), do: Mam.default_page_size()
end
