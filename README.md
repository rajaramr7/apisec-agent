# APIsec Agent

AI-powered CLI tool for configuring API security testing. The agent helps developers set up APIsec by analyzing their API artifacts and generating configuration through conversation.

## The Problem

- Security teams purchase APIsec but lack the API knowledge to configure it
- Developers have the knowledge but won't engage with security UIs
- Manual mediation between teams doesn't scale

## The Solution

A terminal-based conversational agent that:
1. Runs in the developer's repository
2. Infers configuration from artifacts (OpenAPI specs, Postman collections, logs)
3. Asks smart questions to fill gaps
4. Generates APIsec configuration files

## Installation

```bash
# Install from source
git clone https://github.com/rajaramr7/apisec-agent.git
cd apisec-agent
pip install -e .

# Or install directly
pip install apisec
```

## Quick Start

```bash
# Navigate to your API repository
cd /path/to/your/api

# Start the agent
apisec agent

# Or specify options
apisec agent --repo-path ./my-api --config-output apisec-config.yaml
```

## Commands

### `apisec agent`

Start the interactive configuration agent.

```bash
apisec agent [OPTIONS]

Options:
  -r, --repo-path PATH      Path to repository (default: current directory)
  -o, --config-output PATH  Output path for config (default: apisec-config.yaml)
  -m, --model TEXT          LLM model to use (default: gpt-4)
  -v, --verbose             Enable verbose output
  --help                    Show this message and exit
```

### `apisec pr-init`

Create a GitHub PR with the generated configuration.

```bash
apisec pr-init [OPTIONS]

Options:
  -r, --repo TEXT           GitHub repository (owner/repo) [required]
  -b, --branch TEXT         Branch name (default: apisec-config)
  -c, --config-file PATH    Config file to commit (default: apisec-config.yaml)
  --draft                   Create as draft PR
  --help                    Show this message and exit
```

## What the Agent Analyzes

| Artifact | Information Extracted |
|----------|----------------------|
| OpenAPI/Swagger specs | Endpoints, auth schemes, schemas, base URL |
| Postman collections | Requests, auth config, environment variables |
| Access logs | Endpoints, auth patterns, request examples |
| Environment files | Base URLs, auth endpoints, configuration |

## Example Session

```
$ apisec agent

🔍 Scanning repository for API artifacts...

Found:
  ✓ docs/openapi.yaml (OpenAPI 3.0)
  ✓ postman/api.postman_collection.json
  ✓ logs/staging-access.log (500 entries)
  ✓ config/staging.env

📋 Inferred Configuration:

  API Name: Orders API
  Base URL: https://staging-api.orders.example.com
  Auth Type: Bearer (JWT)
  Token Endpoint: /auth/token
  Endpoints: 8 discovered

❓ I have a few questions:

  1. I found credentials for 'user_a' and 'admin' in the logs.
     Should I use both for security testing? [Y/n]

  2. The /orders/{id} endpoint shows user-based access control.
     Should I test for BOLA vulnerabilities? [Y/n]

✅ Configuration generated: apisec-config.yaml

Would you like to create a PR with this configuration? [y/N]
```

## Configuration Output

The agent generates configuration in YAML format:

```yaml
version: "1.0"
api_name: Orders API
base_url: https://staging-api.orders.example.com

auth:
  type: bearer
  token_endpoint: /auth/token
  grant_type: password
  credentials:
    - type: password
      username: user_a
      password_env: USER_A_PASSWORD
    - type: password
      username: admin
      password_env: ADMIN_PASSWORD

endpoints:
  - path: /orders
    method: GET
    auth_required: true
  - path: /orders/{id}
    method: GET
    auth_required: true
    roles: [user, admin]
  # ... more endpoints

security_tests:
  enabled: true
  test_types:
    - bola
    - auth_bypass
    - injection
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for the LLM |
| `GITHUB_TOKEN` | GitHub token for PR creation |

## Project Structure

```
apisec-agent/
├── apisec/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── agent/              # Conversational agent
│   │   ├── chat.py         # Chat loop
│   │   ├── llm.py          # LLM client
│   │   └── tools.py        # Agent tools
│   ├── inference/          # Artifact analysis
│   │   ├── openapi.py      # OpenAPI parser
│   │   ├── postman.py      # Postman parser
│   │   ├── logs.py         # Log analyzer
│   │   ├── env.py          # Env file parser
│   │   └── scanner.py      # Artifact scanner
│   ├── config/             # Configuration
│   │   ├── schema.py       # Config schema
│   │   └── generator.py    # Config generator
│   └── pr/                 # GitHub integration
│       └── github.py       # PR manager
├── prompts/
│   └── system_prompt.md    # Agent system prompt
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black apisec/
ruff check apisec/

# Type checking
mypy apisec/
```

## License

MIT
