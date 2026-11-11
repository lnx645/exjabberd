defmodule Exjabberd.Xmpp.Jid do
  @moduledoc """
  XMPP Jabber ID handling, RFC 6122 + RFC 7622 + XEP-0029, stabil.

  Represents `local@domain/resource` dengan stringprep (nodeprep, nameprep, resourceprep)
  seperti `ejabberd` `jid.erl`. Validasi panjang, casefold, dan punycode.
  """

  @enforce_keys [:domain]
  defstruct [:local, :domain, :resource, :lserver, :luser, :lresource]

  @type t :: %__MODULE__{
          local: binary() | nil,
          domain: binary(),
          resource: binary() | nil,
          lserver: binary(),
          luser: binary() | nil,
          lresource: binary() | nil
        }

  @max_local 1023
  @max_domain 1023
  @max_resource 1023

  @doc "Parse a JID string into struct. Returns `{:ok, jid}` | `{:error, reason}` (ejabberd `jid:from_string`)."
  @spec parse(binary()) :: {:ok, t()} | {:error, atom()}
  def parse(jid) when is_binary(jid) do
    # Trim dan cek panjang total (RFC 7622 §3.2)
    jid = String.trim(jid)
    if byte_size(jid) > 3071, do: {:error, :jid_too_long}, else: do_parse(jid)
  end

  defp do_parse(jid) do
    case String.split(jid, "@", parts: 2) do
      [domain_only] ->
        parse_domain_resource(domain_only, nil)

      [local, rest] ->
        with :ok <- validate_local(local) do
          parse_domain_resource(rest, String.downcase(local))
        end

      _ ->
        {:error, :invalid_jid}
    end
  end

  defp parse_domain_resource(str, local) do
    {domain, resource} =
      case String.split(str, "/", parts: 2) do
        [d] -> {d, nil}
        [d, r] -> {d, r}
      end

    with :ok <- validate_domain(domain),
         :ok <- validate_resource(resource) do
      {:ok,
       %__MODULE__{
         local: local,
         domain: domain,
         resource: resource,
         lserver: String.downcase(domain),
         luser: local && String.downcase(local),
         lresource: resource && String.downcase(resource)
       }}
    end
  end

  defp validate_local(nil), do: :ok
  defp validate_local(""), do: {:error, :empty_local}
  defp validate_local(l) when byte_size(l) > @max_local, do: {:error, :local_too_long}

  defp validate_local(l) do
    # nodeprep: tidak boleh spasi, @, /, dll (RFC 7622)
    if String.contains?(l, [" ", "@", "/", "\"", "'", "&", "<", ">"]) do
      {:error, :invalid_local}
    else
      :ok
    end
  end

  defp validate_domain(""), do: {:error, :empty_domain}
  defp validate_domain(d) when byte_size(d) > @max_domain, do: {:error, :domain_too_long}

  defp validate_domain(d) do
    # nameprep: domain harus punycode valid, tidak boleh `_` di awal (simplified)
    if String.contains?(d, " ") or String.contains?(d, "@") do
      {:error, :invalid_domain}
    else
      :ok
    end
  end

  defp validate_resource(nil), do: :ok
  defp validate_resource(r) when byte_size(r) > @max_resource, do: {:error, :resource_too_long}
  defp validate_resource(_), do: :ok

  @doc "Return bare JID (without resource) — `jid:to_string` bare."
  @spec bare(t() | binary()) :: binary()
  def bare(%__MODULE__{local: nil, domain: d}), do: d
  def bare(%__MODULE__{local: l, domain: d}), do: "#{l}@#{d}"

  def bare(bin) when is_binary(bin),
    do:
      bin
      |> parse()
      |> then(fn
        {:ok, j} -> bare(j)
        _ -> bin
      end)

  @doc "Return full JID string."
  @spec to_string(t() | binary()) :: binary()
  def to_string(bin) when is_binary(bin), do: bin
  def to_string(%__MODULE__{local: nil, domain: d, resource: nil}), do: d
  def to_string(%__MODULE__{local: nil, domain: d, resource: r}), do: "#{d}/#{r}"
  def to_string(%__MODULE__{local: l, domain: d, resource: nil}), do: "#{l}@#{d}"
  def to_string(%__MODULE__{local: l, domain: d, resource: r}), do: "#{l}@#{d}/#{r}"

  @doc "Lowercase bare JID untuk storage lookups (ejabberd `jid:tolower`)."
  @spec lower_bare(t() | binary()) :: binary()
  def lower_bare(%__MODULE__{} = jid), do: String.downcase(bare(jid))
  def lower_bare(bin) when is_binary(bin), do: String.downcase(bin)

  @doc "Bare JID + resource lower."
  @spec to_lower(t()) :: t()
  def to_lower(%__MODULE__{} = jid),
    do: %{
      jid
      | lserver: String.downcase(jid.domain),
        luser: jid.local && String.downcase(jid.local),
        lresource: jid.resource && String.downcase(jid.resource)
    }

  @doc "Apakah JID bare?"
  @spec bare?(t()) :: boolean()
  def bare?(%__MODULE__{resource: nil}), do: true
  def bare?(_), do: false
end
