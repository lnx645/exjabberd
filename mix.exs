defmodule Exjabberd.MixProject do
  use Mix.Project

  def project do
    [
      app: :exjabberd,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_options: [warnings_as_errors: true],
      dialyzer: [plt_add_opts: [apps_direct: [:mnesia, :ssl, :inets]]],
      deps: deps(),
      aliases: aliases(),
      docs: docs(),
      test_coverage: [tool: ExCoveralls]
    ]
  end

  def cli do
    [preferred_envs: [coveralls: :test, "coveralls.html": :test]]
  end

  def application do
    [
      mod: {Exjabberd.Application, []},
      extra_applications: [:logger, :crypto, :ssl, :inets, :mnesia, :os_mon, :runtime_tools, :xmerl]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:yaml_elixir, "~> 2.9"},
      {:telemetry, "~> 1.2"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test}
    ]
  end

  defp aliases do
    [
      check: ["format --check-formatted", "credo --strict", "dialyzer", "test"]
    ]
  end

  defp docs do
    [
      main: "Exjabberd",
      extras: ["README.md"]
    ]
  end
end
