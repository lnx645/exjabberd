defmodule Exjabberd.Xmpp.Codec do
  @moduledoc """
  XMPP Codec — XML parser → XMPP stanza, RFC 6120 + ejabberd `xmpp` codec (partial implementation).

  Seperti `fast_xml`/`xmpp` di ejabberd, tidak hardcode string `"<message>"`
  di mana-mana. Parsing via `:xmerl_scan` (OTP) + `Exjabberd.Xmpp.Jid` + `Stanza`.

  Dipakai oleh `C2S`/`S2S`/`BOSH`/`WebSocket` — satu-satunya pintu masuk XML.
  Mudah dirawat: tambah XEP baru cukup tambah `decode` clause, tidak ubah
  string hardcode di banyak file.

  Contoh ejabberd: `xmpp:decode(El)` → `exjabberd: Codec.decode(xml_string)` → `%Stanza{}`.
  """

  alias Exjabberd.Xmpp.{Jid, Stanza}

  @type xml :: binary()
  @type element :: %{name: binary(), attrs: map(), children: [element() | binary()]}

  @doc "Decode XML string → stanza map (RFC 6120 §8). Returns `{:ok, stanza}` | `{:error, :malformed}`."
  @spec decode(xml()) :: {:ok, Stanza.stanza()} | {:error, atom()}
  def decode(xml) when is_binary(xml) do
    case parse_xml(xml) do
      {:ok, %{name: name} = el} when name in ["message", "presence", "iq"] ->
        try do
          {:ok, element_to_stanza(el, xml)}
        rescue
          ArgumentError -> {:error, :invalid_type}
        end

      {:ok, _el} ->
        {:error, :unknown_stanza}

      {:error, _} = err ->
        err
    end
  end

  @doc "Encode stanza → XML string (kebalikan decode)."
  @spec encode(Stanza.stanza()) :: xml()
  def encode(%{name: name, id: id, from: from, to: to, type: type, payload: payload}) do
    attrs =
      [
        id && ~s(id='#{escape(id)}'),
        from && ~s(from='#{escape(jid_to_string(from))}'),
        to && ~s(to='#{escape(jid_to_string(to))}'),
        type && ~s(type='#{escape(type)}')
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" ")

    inner = encode_payload(payload)

    cond do
      inner == "" and attrs == "" -> "<#{name}/>"
      inner == "" -> "<#{name} #{attrs}/>"
      attrs == "" -> "<#{name}>#{inner}</#{name}>"
      true -> "<#{name} #{attrs}>#{inner}</#{name}>"
    end
  end

  @doc "Parse XML string → element tree (tidak hardcode, pakai parser OTP :xmerl)."
  @spec parse_xml(xml()) :: {:ok, element()} | {:error, atom()}
  def parse_xml(xml) do
    try do
      {doc, _} =
        apply(:xmerl_scan, :string, [
          String.to_charlist(xml),
          [{:quiet, true}, {:validation, :off}]
        ])

      {:ok, xmerl_to_element(doc)}
    rescue
      _ -> {:error, :malformed}
    catch
      _, _ -> {:error, :malformed}
    end
  end

  # --- Feature handler (ejabberd `stream_features` tidak hardcode) ---

  @doc "Build stream features via handler registry (ejabberd `ejabberd_c2s:stream_features` tidak hardcode string)."
  @spec stream_features(binary(), keyword()) :: [element()]
  def stream_features(host, opts \\ []) do
    # Kumpulkan dari Hooks `c2s_stream_features` — tiap feature (STARTTLS, SASL, bind) daftar sendiri
    base = Exjabberd.Hooks.run_fold(:c2s_stream_features, host, [], opts)
    # Fallback kalau belum ada yang daftar. Hanya fitur yang benar-benar
    # diimplementasi yang diiklankan: STARTTLS (bila belum TLS), SASL
    # PLAIN + SCRAM-SHA-256, dan resource binding setelah auth. SM, CSI,
    # carbons dan SCRAM-SHA-1/512 TIDAK diiklankan karena belum ada.
    if base == [] do
      authenticated = Keyword.get(opts, :authenticated, false)
      tls = Keyword.get(opts, :tls, false)

      sasl =
        if authenticated do
          []
        else
          [
            %{
              name: "mechanisms",
              attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-sasl"},
              children: [
                %{name: "mechanism", attrs: %{}, children: ["PLAIN"]},
                %{name: "mechanism", attrs: %{}, children: ["SCRAM-SHA-256"]}
              ]
            }
          ]
        end

      bind =
        if authenticated do
          [%{name: "bind", attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-bind"}, children: []}]
        else
          []
        end

      tls_el =
        if authenticated or tls do
          []
        else
          [
            %{
              name: "starttls",
              attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-tls"},
              children: []
            }
          ]
        end

      tls_el ++ sasl ++ bind
    else
      base
    end
  end

  @doc "Encode stream features list to XML (ejabberd `xmpp:encode_stream_features`)."
  @spec encode_stream_features([element()]) :: binary()
  def encode_stream_features(features) when is_list(features) do
    inner = Enum.map_join(features, "", &encode_payload/1)
    "<stream:features>#{inner}</stream:features>"
  end

  # --- private ---

  defp element_to_stanza(%{name: name, attrs: attrs, children: children} = _el, raw) do
    # name bisa "message" / "presence" / "iq" + attrs id/from/to/type
    type = Map.get(attrs, "type")
    id = Map.get(attrs, "id")
    from = parse_jid(Map.get(attrs, "from"))
    to = parse_jid(Map.get(attrs, "to"))
    # payload = children yang sudah di-decode jadi element atau text
    Stanza.new(String.to_atom(name),
      id: id,
      from: from,
      to: to,
      type: type,
      payload: children,
      raw: raw
    )
  end

  defp parse_jid(nil), do: nil

  defp parse_jid(str) when is_binary(str) do
    case Jid.parse(str) do
      {:ok, jid} -> jid
      _ -> str
    end
  end

  defp jid_to_string(nil), do: ""
  defp jid_to_string(%Jid{} = jid), do: Jid.to_string(jid)
  defp jid_to_string(bin) when is_binary(bin), do: bin

  defp encode_payload(nil), do: ""
  defp encode_payload([]), do: ""
  defp encode_payload(list) when is_list(list), do: Enum.map_join(list, "", &encode_payload/1)

  defp encode_payload(%{name: n, attrs: a, children: c}) do
    encode_element(n, a, c)
  end

  # --- IQ result payloads built by the mod handlers (ad-hoc maps) ---

  defp encode_payload(%{xmlns: "jabber:iq:roster", items: items} = m) do
    attrs = %{"xmlns" => "jabber:iq:roster"}

    attrs =
      case Map.get(m, :ver) do
        nil -> attrs
        ver -> Map.put(attrs, "ver", to_string(ver))
      end

    encode_element("query", attrs, Enum.map(items, &roster_item/1))
  end

  defp encode_payload(%{xmlns: "http://jabber.org/protocol/disco#info"} = m) do
    identities =
      case Map.get(m, :identities) do
        [_ | _] = ids -> Enum.map(ids, &disco_identity/1)
        _ -> [disco_identity(%{category: "server", type: "im", name: "exjabberd"})]
      end

    features =
      Enum.map(Map.get(m, :features, []), fn f ->
        %{name: "feature", attrs: %{"var" => f}, children: []}
      end)

    encode_element(
      "query",
      %{"xmlns" => "http://jabber.org/protocol/disco#info"},
      identities ++ features
    )
  end

  defp encode_payload(%{xmlns: "http://jabber.org/protocol/disco#items"} = m) do
    children =
      Enum.map(Map.get(m, :items, []), fn item ->
        attrs = %{"jid" => Map.get(item, :jid, "")}

        attrs =
          case Map.get(item, :name) do
            nil -> attrs
            name -> Map.put(attrs, "name", name)
          end

        %{name: "item", attrs: attrs, children: []}
      end)

    encode_element("query", %{"xmlns" => "http://jabber.org/protocol/disco#items"}, children)
  end

  defp encode_payload(%{xmlns: "urn:xmpp:time", tzo: tzo, utc: utc}) do
    encode_element("time", %{"xmlns" => "urn:xmpp:time"}, [
      %{name: "tzo", attrs: %{}, children: [to_string(tzo)]},
      %{name: "utc", attrs: %{}, children: [to_string(utc)]}
    ])
  end

  defp encode_payload(%{xmlns: "jabber:iq:version"} = m) do
    children = [
      %{name: "name", attrs: %{}, children: [to_string(Map.get(m, :name, "exjabberd"))]},
      %{name: "version", attrs: %{}, children: [to_string(Map.get(m, :version, ""))]}
    ]

    children =
      case Map.get(m, :os) do
        nil -> children
        os -> children ++ [%{name: "os", attrs: %{}, children: [to_string(os)]}]
      end

    encode_element("query", %{"xmlns" => "jabber:iq:version"}, children)
  end

  defp encode_payload(%{xmlns: "jabber:iq:register"} = m) do
    children = []

    children =
      case Map.get(m, :instructions) do
        nil -> children
        text -> children ++ [%{name: "instructions", attrs: %{}, children: [to_string(text)]}]
      end

    children =
      if Map.has_key?(m, :username) do
        children ++
          [%{name: "username", attrs: %{}, children: [to_string(Map.get(m, :username) || "")]}]
      else
        children
      end

    children =
      if Map.has_key?(m, :password) do
        children ++
          [%{name: "password", attrs: %{}, children: [to_string(Map.get(m, :password) || "")]}]
      else
        children
      end

    encode_element("query", %{"xmlns" => "jabber:iq:register"}, children)
  end

  defp encode_payload(%{xmlns: "jabber:iq:privacy"} = m) do
    children =
      Enum.map(Map.get(m, :lists, []), fn list ->
        items =
          Enum.map(Map.get(list, :items, []), fn item ->
            %{name: "item", attrs: item_attrs(item), children: []}
          end)

        %{name: "list", attrs: %{"name" => to_string(Map.get(list, :name, ""))}, children: items}
      end)

    encode_element("query", %{"xmlns" => "jabber:iq:privacy"}, children)
  end

  defp encode_payload(%{xmlns: "urn:xmpp:blocking"} = m) do
    children =
      Enum.map(Map.get(m, :blocklist, []), fn jid ->
        %{name: "item", attrs: %{"jid" => to_string(jid)}, children: []}
      end)

    encode_element("blocklist", %{"xmlns" => "urn:xmpp:blocking"}, children)
  end

  defp encode_payload(%{xmlns: "vcard-temp"} = m) do
    children =
      case Map.get(m, :vcard) do
        vc when is_map(vc) ->
          Enum.map(vc, fn {k, v} ->
            %{name: to_string(k), attrs: %{}, children: [to_string(v)]}
          end)

        _ ->
          []
      end

    encode_element("vCard", %{"xmlns" => "vcard-temp"}, children)
  end

  # Error stanza payload built by Stanza.error_reply / Iq.error_iq.
  defp encode_payload({:error, %{condition: condition} = info}) do
    text = Map.get(info, :text, "")

    children = [
      %{name: condition, attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-stanzas"}, children: []}
    ]

    children =
      if text != "" do
        children ++
          [
            %{
              name: "text",
              attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-stanzas"},
              children: [to_string(text)]
            }
          ]
      else
        children
      end

    encode_element("error", %{"type" => "cancel"}, children)
  end

  # Long tail: any other handler payload carrying an xmlns. The element
  # name is derived from the namespace; remaining keys become child
  # elements with text content.
  defp encode_payload(%{xmlns: ns} = m) do
    children =
      m
      |> Map.delete(:xmlns)
      |> Enum.map(fn {k, v} -> %{name: to_string(k), attrs: %{}, children: [to_string(v)]} end)

    encode_element(xmlns_tag(ns), %{"xmlns" => ns}, children)
  end

  defp encode_payload(bin) when is_binary(bin), do: escape(bin)
  defp encode_payload(other), do: escape(inspect(other))

  defp encode_element(name, attrs, children) do
    attrs_s =
      attrs |> Enum.map(fn {k, v} -> ~s(#{k}='#{escape(v)}') end) |> Enum.join(" ")

    inner = encode_payload(children)

    cond do
      inner == "" and attrs_s == "" -> "<#{name}/>"
      inner == "" -> "<#{name} #{attrs_s}/>"
      attrs_s == "" -> "<#{name}>#{inner}</#{name}>"
      true -> "<#{name} #{attrs_s}>#{inner}</#{name}>"
    end
  end

  defp roster_item(%{jid: jid} = item) do
    attrs = %{
      "jid" => to_string(jid),
      "subscription" => to_string(Map.get(item, :subscription, :none))
    }

    attrs =
      case Map.get(item, :name) do
        nil -> attrs
        "" -> attrs
        name -> Map.put(attrs, "name", to_string(name))
      end

    children =
      Enum.map(Map.get(item, :groups, []), fn g ->
        %{name: "group", attrs: %{}, children: [to_string(g)]}
      end)

    %{name: "item", attrs: attrs, children: children}
  end

  defp disco_identity(%{category: cat, type: type} = id) do
    attrs = %{"category" => to_string(cat), "type" => to_string(type)}

    attrs =
      case Map.get(id, :name) do
        nil -> attrs
        name -> Map.put(attrs, "name", to_string(name))
      end

    %{name: "identity", attrs: attrs, children: []}
  end

  defp item_attrs(item) when is_map(item) do
    Enum.reduce(item, %{}, fn {k, v}, acc ->
      if is_binary(v) or is_atom(v) or is_integer(v),
        do: Map.put(acc, to_string(k), to_string(v)),
        else: acc
    end)
  end

  defp xmlns_tag("jabber:iq:roster"), do: "query"
  defp xmlns_tag("http://jabber.org/protocol/disco#info"), do: "query"
  defp xmlns_tag("http://jabber.org/protocol/disco#items"), do: "query"
  defp xmlns_tag("jabber:iq:version"), do: "query"
  defp xmlns_tag("jabber:iq:privacy"), do: "query"
  defp xmlns_tag("jabber:iq:register"), do: "query"
  defp xmlns_tag("urn:xmpp:time"), do: "time"
  defp xmlns_tag("urn:xmpp:blocking"), do: "blocklist"
  defp xmlns_tag("vcard-temp"), do: "vCard"
  defp xmlns_tag(_), do: "query"

  defp escape(str) when is_binary(str) do
    str
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    # Attributes are single-quoted on the wire, so escape those too.
    |> String.replace("'", "&apos;")
  end

  defp escape(other), do: escape(to_string(other))

  # :xmerl -> element
  defp xmerl_to_element({:xmlElement, name, _, _, _, _, _, attrs, content, _, _, _}) do
    attr_map =
      attrs
      |> Enum.map(fn {:xmlAttribute, k, _, _, _, _, _, _, v, _} ->
        {to_string(k), to_string(v)}
      end)
      |> Map.new()

    children =
      content
      |> Enum.map(fn
        {:xmlElement, _, _, _, _, _, _, _, _, _, _, _} = el ->
          xmerl_to_element(el)

        {:xmlText, _, _, _, v, _} ->
          to_string(v) |> String.trim() |> then(fn s -> if s == "", do: nil, else: s end)

        _ ->
          nil
      end)
      |> Enum.reject(&is_nil/1)

    %{name: to_string(name), attrs: attr_map, children: children}
  end

  defp xmerl_to_element(other), do: %{name: "unknown", attrs: %{}, children: [inspect(other)]}
end

defmodule Exjabberd.Xmpp.Feature do
  @moduledoc """
  Feature Handler — tidak hardcode XML. Tiap fitur (STARTTLS, SASL, bind, session)
  daftar via `Hooks` `c2s_stream_features` seperti ejabberd `xmpp_stream_features`.

  Mudah dirawat: tambah XEP baru (misal ` carbons`) cukup:
  `Hooks.add(:c2s_stream_features, host, MyFeature, :announce, 50)`
  tanpa ubah `Codec` atau `C2S` string hardcode.
  """

  @doc "Daftar semua fitur untuk host (dipanggil Codec.stream_features)."
  @spec announce(binary(), keyword()) :: [map()]
  def announce(host, opts) do
    Exjabberd.Hooks.run_fold(:c2s_stream_features, host, [], opts)
  end

  @doc "Register STARTTLS feature (ejabberd `starttls`)."
  def register_starttls(host) do
    Exjabberd.Hooks.add(:c2s_stream_features, host, __MODULE__, :starttls_feature, 10)
  end

  @doc false
  def starttls_feature(acc, _host, _opts \\ nil) do
    acc ++
      [%{name: "starttls", attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-tls"}, children: []}]
  end

  @doc "Register SASL feature."
  def register_sasl(host, mechs \\ ["PLAIN", "SCRAM-SHA-256"]) do
    Exjabberd.Hooks.add(:c2s_stream_features, host, __MODULE__, :sasl_feature, 20)
    _ = mechs
    :ok
  end

  @doc false
  def sasl_feature(acc, _host, _opts \\ nil) do
    acc ++
      [
        %{
          name: "mechanisms",
          attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-sasl"},
          children:
            Enum.map(["PLAIN", "SCRAM-SHA-256"], fn m ->
              %{name: "mechanism", attrs: %{}, children: [m]}
            end)
        }
      ]
  end

  @doc "Register bind feature (RFC 6120 §7)."
  def register_bind(host) do
    Exjabberd.Hooks.add(:c2s_stream_features, host, __MODULE__, :bind_feature, 30)
  end

  @doc false
  def bind_feature(acc, _host, opts \\ nil) do
    if Keyword.get(opts || [], :authenticated, false) do
      acc ++
        [%{name: "bind", attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-bind"}, children: []}]
    else
      acc
    end
  end

  @doc "Register Stream Management (XEP-0198)."
  def register_sm(host) do
    Exjabberd.Hooks.add(:c2s_stream_features, host, __MODULE__, :sm_feature, 40)
  end

  @doc false
  def sm_feature(acc, _host, opts \\ nil) do
    if Keyword.get(opts || [], :authenticated, false) do
      acc ++ [%{name: "sm", attrs: %{"xmlns" => "urn:xmpp:sm:3"}, children: []}]
    else
      acc
    end
  end

  @doc "Register CSI (XEP-0352)."
  def register_csi(host) do
    Exjabberd.Hooks.add(:c2s_stream_features, host, __MODULE__, :csi_feature, 50)
  end

  @doc false
  def csi_feature(acc, _host, _opts \\ nil) do
    acc ++ [%{name: "csi", attrs: %{"xmlns" => "urn:xmpp:csi:0"}, children: []}]
  end

  @doc "Register Carbons (XEP-0280)."
  def register_carbons(host) do
    Exjabberd.Hooks.add(:c2s_stream_features, host, __MODULE__, :carbons_feature, 60)
  end

  @doc false
  def carbons_feature(acc, _host, opts \\ nil) do
    if Keyword.get(opts || [], :authenticated, false) do
      acc ++
        [%{name: "carbons", attrs: %{"xmlns" => "urn:xmpp:carbons:2"}, children: []}]
    else
      acc
    end
  end
end
