🇿🇦 South Africa Intel MCP

A South Africa-first intelligence and situational-awareness MCP server built from the "World Intel MCP" (https://github.com/marc-shade/world-intel-mcp) project.

South Africa is the primary area of interest. The system collects, normalizes, caches, analyzes, and exposes intelligence from relevant public data sources through the Model Context Protocol (MCP).

🎯 Mission

Provide a free, open-source intelligence platform focused on South Africa.

The system is designed to answer questions such as:

- What is happening in South Africa right now?
- What are the latest major South African news developments?
- What is happening with South Africa's economy and the rand?
- What is happening with electricity and Eskom?
- What are the latest developments in South African politics?
- What infrastructure incidents are occurring?
- What is happening at South African ports and airports?
- What weather and environmental events are developing?
- What significant security developments are occurring?
- What are the important developments across South Africa's provinces?

Global information may be used when it has a direct and meaningful impact on South Africa.

🇿🇦 Core Intelligence Domains

- News & current events
- Government & politics
- Economy & macroeconomics
- Markets, JSE & ZAR
- Energy & electricity
- Security & instability
- Infrastructure
- Transport, aviation & maritime
- Weather & disasters
- Environment
- Geospatial intelligence
- Business & companies
- Mining & commodities
- Intelligence analysis

💰 Zero-Cost Principle

This project is designed to operate using free and publicly available data sources wherever possible.

The project will not require:

- Paid hosting
- Paid databases
- Paid APIs
- Paid scraping services
- Paid proxy services
- Paid domains

Optional services that require API credentials must never be mandatory for the core South Africa intelligence system.

🏗 Architecture

The project preserves the original World Intel MCP architecture:

Public Data Sources
        ↓
Source Modules
        ↓
Fetcher
        ↓
Circuit Breaker
        ↓
SQLite Cache
        ↓
Analysis
        ↓
MCP Server
        ↓
AI Client / Dashboard

📱 Intended Use

The system is designed to be accessible remotely so that it can be used from a phone or other device through an MCP-compatible client and/or web dashboard.

⚠️ Disclaimer

This project aggregates information from public sources. It does not guarantee the accuracy, completeness, or timeliness of third-party data.

Information should be independently verified before being used for important decisions.

License

This project retains the license of the original World Intel MCP project.
