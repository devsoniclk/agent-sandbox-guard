# Contributing to agent-epistemic-verifier

Thank you for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/devsoniclk/agent-epistemic-verifier.git
cd agent-epistemic-verifier
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests -v --cov=agent_epistemic_verifier
```

All contributions require 100% test pass rates and strict type safety.

## Commit Guidelines
Follow conventional commits with clear scope indicators:
- `feat:` New features
- `fix:` Bug fixes
- `test:` Test additions or improvements
- `docs:` Documentation updates
