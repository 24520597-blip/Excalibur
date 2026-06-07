# Excalibur

AI-powered autonomous penetration testing agent with evidence-guided attack tree search (EGATS) planning. Solves CTF challenges, Hack The Box machines, and authorized security assessments.

## Prerequisites

- **Docker** -- [Install Docker](https://docs.docker.com/get-docker/)
- **LLM Provider** (one of):
  - Claude subscription (OAuth login)
  - Anthropic API key
  - Gemini API key
  - OpenRouter API key
  - Local LLM (LM Studio, Ollama, etc.)

## Installation

```bash
make install          # Build Docker image
make config           # Configure authentication (first time)
make connect          # Connect to container
```

## Usage

Inside the container:

```bash
# Interactive TUI mode (default)
excalibur --target 10.10.11.234

# Non-interactive mode
excalibur --target 10.10.11.100 --non-interactive

# With context hint
excalibur --target 10.10.11.50 --instruction "WordPress site, check plugin vulns"

# Use Gemini API directly
GEMINI_API_KEY="your-key" excalibur --target 10.10.11.50 --provider gemini
```

The Gemini backend uses Google's official `google-genai` SDK and exposes a
workspace-scoped shell function tool so the model can execute pentesting commands.

**Keyboard shortcuts:** `F1` Help | `Ctrl+P` Pause/Resume | `Ctrl+Q` Quit

## Docker Commands

| Command | Description |
|---------|-------------|
| `make install` | Build the Docker image |
| `make config` | Configure API authentication |
| `make connect` | Connect to container (main entry point) |
| `make stop` | Stop container (config persists) |
| `make clean-docker` | Remove everything including config |

## Running Tests

```bash
make test             # All tests (excludes Docker tests)
make test-cov         # Tests with coverage report
make lint             # Ruff linter
make typecheck        # Mypy type checking
make check            # All checks (lint + typecheck)
```

## License

MIT License. See `LICENSE.md`.

**Disclaimer:** For educational purposes and authorized security testing only.
