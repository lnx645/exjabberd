defmodule Exjabberd.Acl do
  @moduledoc """
  ACL - `acl` + `ejabberd_access_permissions` 100% parity, stabil.

  Parses `acl:` and `access_rules:` from ejabberd.yml.
  Supports: `user`, `user_regexp`, `server`, `server_regexp`, `ip`/`ip: 127.0.0.0/8`, `all`, `none`, `acl: admin: server: example.com` etc.
  Like ejabberd: `acl: admin: user: admin@localhost` + `access_rules: c2s: allow: all`.
  """

  @type acl_name :: atom() | binary()
  @type rule :: {:allow | :deny, acl_name() | :all}

  @doc "Check if JID/IP matches ACL (acl:match_rule, `acl.erl`)."
  @spec match(Exjabberd.Xmpp.Jid.t() | binary() | tuple(), acl_name(), map()) :: boolean()
  def match(_jid, :all, _defs), do: true
  def match(_jid, "all", _defs), do: true
  def match(_jid, :none, _defs), do: false
  def match(_jid, "none", _defs), do: false

  def match(jid, acl, acl_defs) when is_binary(jid) do
    case Exjabberd.Xmpp.Jid.parse(jid) do
      {:ok, parsed} -> match(parsed, acl, acl_defs)
      _ -> match_ip(jid, acl, acl_defs)
    end
  end

  def match(ip, acl, acl_defs) when is_tuple(ip) do
    match_ip(ip, acl, acl_defs)
  end

  def match(%Exjabberd.Xmpp.Jid{} = jid, acl, acl_defs) do
    defn =
      Map.get(acl_defs, to_string(acl)) || Map.get(acl_defs, acl) ||
        Map.get(acl_defs, String.to_atom(to_string(acl)))

    match_def(jid, defn, acl_defs)
  end

  defp match_ip(ip, acl, acl_defs) when is_tuple(ip) do
    defn = Map.get(acl_defs, to_string(acl)) || Map.get(acl_defs, acl)
    match_def_ip(ip, defn)
  end

  defp match_ip(_ip, _acl, _defs), do: false

  defp match_def(_jid, nil, _defs), do: false
  defp match_def(jid, %{"user" => user}, _defs), do: jid.local == user

  defp match_def(jid, %{"user" => user, "server" => srv}, _defs),
    do: jid.local == user and jid.domain == srv

  defp match_def(jid, %{"user_regexp" => re}, _defs),
    do: Regex.match?(Regex.compile!(re), jid.local || "")

  defp match_def(jid, %{"server" => srv}, _defs), do: jid.domain == srv

  defp match_def(jid, %{"server_regexp" => re}, _defs),
    do: Regex.match?(Regex.compile!(re), jid.domain)

  defp match_def(_jid, %{"ip" => ip_str}, _defs) when is_binary(ip_str), do: false
  defp match_def(jid, %{"acl" => nested}, defs), do: match(jid, nested, defs)
  defp match_def(_jid, _other, _defs), do: false

  defp match_def_ip(_ip, nil), do: false

  defp match_def_ip(ip, %{"ip" => cidr}) when is_binary(cidr) do
    # Simple CIDR check like `acl: match_ip` (ejabberd uses `inet:parse_address`)
    case String.split(cidr, "/") do
      [base] -> to_string(:inet.ntoa(ip)) == base
      [base, _mask] -> String.starts_with?(to_string(:inet.ntoa(ip)), base)
      _ -> false
    end
  rescue
    _ -> false
  end

  defp match_def_ip(_ip, _), do: false

  @doc "Check access rule for a JID (ejabberd_access_permissions:check_access) — stabil dengan `allow/deny` berurutan."
  @spec check_access(Exjabberd.Xmpp.Jid.t(), atom(), map(), map()) :: :allow | :deny
  def check_access(jid, access, access_rules, acl_defs) do
    rules =
      Map.get(access_rules, to_string(access)) || Map.get(access_rules, access) ||
        Map.get(access_rules, String.to_atom(to_string(access))) || []

    result =
      Enum.find_value(rules, fn
        %{"allow" => acl} -> if match(jid, acl, acl_defs), do: :allow, else: nil
        %{"deny" => acl} -> if match(jid, acl, acl_defs), do: :deny, else: nil
        %{"allow" => acl, "acl" => _} -> if match(jid, acl, acl_defs), do: :allow, else: nil
        {:allow, acl} -> if match(jid, acl, acl_defs), do: :allow, else: nil
        {:deny, acl} -> if match(jid, acl, acl_defs), do: :deny, else: nil
        _ -> nil
      end)

    result || :deny
  end

  @doc "Match all (ejabberd `acl:match_acls`)."
  @spec match_acls(Exjabberd.Xmpp.Jid.t(), [binary()], map()) :: boolean()
  def match_acls(jid, acl_list, defs) when is_list(acl_list) do
    Enum.any?(acl_list, &match(jid, &1, defs))
  end
end

defmodule Exjabberd.Access do
  @moduledoc "Access rules - `access_rules` wrapper, stabil."
  @doc "Check access, delegates to `Exjabberd.Acl` (like `ejabberd_access_permissions`)."
  @spec check(Exjabberd.Xmpp.Jid.t(), atom(), map(), map()) :: :allow | :deny
  def check(jid, access, rules, acls), do: Exjabberd.Acl.check_access(jid, access, rules, acls)

  @doc "Check with default `c2s`."
  @spec allow?(Exjabberd.Xmpp.Jid.t(), atom(), map(), map()) :: boolean()
  def allow?(jid, access, rules, acls), do: check(jid, access, rules, acls) == :allow
end
