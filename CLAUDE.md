# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build the entire workspace
cargo build

# Build in release mode
cargo build --release

# Run the main orchestrator
cargo run -p main_orchestrator

# Run all tests across the workspace
cargo test

# Run tests for a specific crate
cargo test -p network_scanner
cargo test -p http_fuzzer
cargo test -p cve_scanner

# Run a single test by name
cargo test -p network_scanner it_works

# Lint with Clippy
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --all

# Check formatting without applying
cargo fmt --all -- --check
```

## Architecture

This is a Cargo workspace containing a security tooling suite with four crates:

```
crates/
  network_scanner/     # Library: network scanning capabilities
  http_fuzzer/         # Library: HTTP fuzzing capabilities
  cve_scanner/         # Library: CVE lookup/scanning capabilities
  main_orchestrator/   # Binary: ties everything together via an AI agent
```

**`main_orchestrator`** is the only binary crate. It depends on all three library crates and is responsible for orchestrating them. It has two planned internal modules (currently scaffolded as stubs):

- `agent/` — AI agent layer intended to use **Ollama** (local LLM) for decision-making. Contains `ollama.rs` (HTTP client to Ollama API), `prompts.rs` (prompt templates), and `mod.rs`.
- `execution/` — Tool dispatch layer. Contains `registry.rs` (maps tool names to crate functions) and `mod.rs`.

The intended data flow is: `main.rs` → `agent` (Ollama decides which tools to invoke) → `execution::registry` (dispatches to `network_scanner`, `http_fuzzer`, or `cve_scanner`) → results returned to agent for synthesis.

**Key shared dependencies** (defined at workspace root, referenced with `workspace = true`):
- `tokio` with `full` features — async runtime for the orchestrator and HTTP calls
- `reqwest` — used for HTTP fuzzing and Ollama API communication
- `serde` / `serde_json` — serialization of tool inputs/outputs passed between agent and execution layer
- `anyhow` — unified error handling across crates

The three library crates (`network_scanner`, `http_fuzzer`, `cve_scanner`) currently have no dependencies of their own — add shared workspace deps to them only when needed rather than duplicating version declarations.

The project uses **Rust edition 2024** in the individual crates and **2021** at the workspace level — be aware of this discrepancy when using edition-specific features.
