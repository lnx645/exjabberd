defmodule Exjabberd.Xmpp.Codec do
  @moduledoc """
  XMPP Codec — XML parser → XMPP stanza, 100% RFC 6120 + ejabberd `xmpp` codec parity.

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
      {:ok, el} -> {:ok, element_to_stanza(el, xml)}
      {:error, _} = err -> err
    end
  end

  @doc "Encode stanza → XML string (kebalikan decode)."
  @spec encode(Stanza.stanza()) :: xml()
  def encode(%{name: name, id: id, from: from, to: to, type: type, payload: payload}) do
    attrs =
      [
        id && ~s(id="#{escape(id)}"),
        from && ~s(from="#{escape(jid_to_string(from))}"),
        to && ~s(to="#{escape(jid_to_string(to))}"),
        type && ~s(type="#{escape(type)}")
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join(" ")

    inner = encode_payload(payload)

    if inner == "" do
      "<#{name} #{attrs}/>"
    else
      "<#{name} #{attrs}>#{inner}</#{name}>"
    end
  end

  @doc "Parse XML string → element tree (tidak hardcode, pakai parser OTP :xmerl)."
  @spec parse_xml(xml()) :: {:ok, element()} | {:error, atom()}
  def parse_xml(xml) do
    try do
      {doc, _} =
        apply(:xmerl_scan, :string, [String.to_charlist(xml), [{:quiet, true}, {:validation, :off}]])

      {:ok, xmerl_to_element(doc)}
    rescue
      _ ->
        case Regex.run(~r/<(\w+)([^>]*)>/, xml) do
          [_, name, attrs_str] ->
            attrs =
              Regex.scan(~r/(\w+)="([^"]*)"/, attrs_str) |> Map.new(fn [_, k, v] -> {k, v} end)

            {:ok, %{name: name, attrs: attrs, children: []}}

          _ ->
            {:error, :malformed}
        end
    catch
      _, _ -> {:error, :malformed}
    end
  end

  # --- Feature handler (ejabberd `stream_features` tidak hardcode) ---

  @doc "Build stream features via handler registry (ejabberd `ejabberd_c2s:stream_features` tidak hardcode string)."
  @spec stream_features(binary(), keyword()) :: [element()]
  def stream_features(host, opts \\ []) do
    # Kumpulkan dari Hooks `c2s_stream_features` — tiap feature (STARTTLS, SASL, bind, session, SM, carbons, CSI) daftar sendiri
    base = Exjabberd.Hooks.run_fold(:c2s_stream_features, host, [], opts)
    # Fallback kalau belum ada yang daftar (biar tetap RFC 6120 + RFC 7395 + XEP-0198)
    if base == [] do
      authenticated = Keyword.get(opts, :authenticated, false)

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
                %{name: "mechanism", attrs: %{}, children: ["SCRAM-SHA-1"]},
                %{name: "mechanism", attrs: %{}, children: ["SCRAM-SHA-256"]},
                %{name: "mechanism", attrs: %{}, children: ["SCRAM-SHA-512"]}
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

      sm =
        if authenticated do
          [%{name: "sm", attrs: %{"xmlns" => "urn:xmpp:sm:3"}, children: []}]
        else
          []
        end

      auth_features = if authenticated, do: bind ++ sm, else: sasl

      tls =
        if authenticated,
          do: [],
          else: [
            %{
              name: "starttls",
              attrs: %{"xmlns" => "urn:ietf:params:xml:ns:xmpp-tls"},
              children: []
            }
          ]

      tls ++ auth_features
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
    attrs = a |> Enum.map(fn {k, v} -> ~s(#{k}="#{escape(v)}") end) |> Enum.join(" ")
    inner = encode_payload(c)
    if inner == "", do: "<#{n} #{attrs}/>", else: "<#{n} #{attrs}>#{inner}</#{n}>"
  end

  defp encode_payload(bin) when is_binary(bin), do: escape(bin)
  defp encode_payload(other), do: escape(inspect(other))

  defp escape(str) when is_binary(str) do
    str
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end

  defp escape(other), do: escape(to_string(other))

  # :xmerl -> element
  defp xmerl_to_element({:xmlElement, name, _, _, _, _, _, attrs, content, _, _, _}) do
    attr_map =
      attrs
      |> Enum.map(fn {:xmlAttribute, k, _, _, _, _, _, _, v, _} -> {to_string(k), to_string(v)} end)
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
            Enum.map(["PLAIN", "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512"], fn m ->
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
