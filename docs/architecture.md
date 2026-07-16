# Architecture

OVCA Core is a Rust workspace with shared types, storage, observability, MCP,
LLM client, brain cache, runtime routing, LangGraph-style orchestration, Policy
Tools, and four MCP server binaries. Coordinator is the front door, Engineer handles
engineering, Reviewer handles review, and Auditor handles cross-audit.

Python contains the reference Policy Tools logic, direct-call adapter, and a
dependency-free ASGI compatibility surface for embedding and tests. It has no
standalone server entrypoint. The Rust `ovca-policy-tools` binary is the
authoritative portable HTTP service for the twelve shared tools. Data roots are
external inputs; the repository contains no operational memory or history.
