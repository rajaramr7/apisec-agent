# ============================================================================
# APIsec Agent — Intelligent Requirement Gathering Enhancement
# ============================================================================
#
# Run this AFTER you've tested v0 and validated the basic conversation flow.
# This adds intelligence around what to gather, from where, and how to drive
# the conversation dynamically based on what's found vs. what's missing.
#
# ============================================================================


# ============================================================================
# OVERVIEW: What the Agent Must Gather
# ============================================================================

The agent needs to gather 6 things to enable effective API security testing.
4 are must-haves. 2 are for deeper testing.

## Must-Haves (without these, testing is impossible or useless)

| # | Requirement | What It Is | Without It |
|---|-------------|------------|------------|
| 1 | Host URL | Running instance URL (staging/dev) | Can't make requests |
| 2 | Endpoints + Signatures | What endpoints exist, params, types | Don't know what to test |
| 3 | Working Payloads | Valid request bodies | Tests fail with noise |
| 4 | Auth Config + Credentials | How to auth + actual creds | Can't get past 401 |

## Deeper Requirements (for real security value)

| # | Requirement | What It Is | Without It |
|---|-------------|------------|------------|
| 5 | BOLA Identities | 2+ users + resource ownership | Can't test horizontal privilege |
| 6 | RBAC Roles | Role accounts (user/admin/etc.) | Can't test vertical privilege |


# ============================================================================
# PROMPT PART 1: Add Gateway Log Parsers
# ============================================================================

Add support for parsing API gateway logs to apisec/inference/

## File: apisec/inference/gateway_logs.py

```python
"""
Parse API gateway logs from various providers.
These logs are goldmines — they show real traffic patterns, auth headers, 
endpoints actually in use, and response codes.
"""

def detect_gateway_log_format(path: str) -> str:
    """
    Detect which gateway format a log file uses.
    Returns: 'kong' | 'aws_api_gateway' | 'apigee' | 'nginx' | 'envoy' | 'unknown'
    """
    pass

def parse_kong_logs(path: str) -> dict:
    """
    Parse Kong API Gateway access logs.
    
    Kong log format (JSON):
    {
        "request": {
            "uri": "/orders/1001",
            "method": "GET",
            "headers": {"authorization": "Bearer xxx", ...}
        },
        "response": {"status": 200},
        "authenticated_entity": {"consumer_id": "user_a"},
        "latencies": {"request": 45},
        "started_at": 1234567890
    }
    
    Returns:
        {
            "endpoints": [{"method": "GET", "path": "/orders/{id}", ...}],
            "users": ["user_a", "user_b"],
            "auth_patterns": {"type": "bearer", "header": "authorization"},
            "resource_access": {"user_a": ["/orders/1001", "/orders/1002"]}
        }
    """
    pass

def parse_aws_api_gateway_logs(path: str) -> dict:
    """
    Parse AWS API Gateway access logs.
    
    AWS API Gateway log format (JSON):
    {
        "requestId": "xxx",
        "ip": "1.2.3.4",
        "caller": "user_a",
        "user": "user_a",
        "requestTime": "2024-01-15T10:23:45Z",
        "httpMethod": "GET",
        "resourcePath": "/orders/{id}",
        "path": "/orders/1001",
        "status": 200,
        "responseLength": 256
    }
    
    Returns: same structure as kong parser
    """
    pass

def parse_apigee_logs(path: str) -> dict:
    """
    Parse Apigee API Gateway logs.
    
    Returns: same structure as kong parser
    """
    pass

def parse_nginx_access_logs(path: str) -> dict:
    """
    Parse nginx access logs (common in front of APIs).
    
    Common nginx log format:
    1.2.3.4 - user_a [15/Jan/2024:10:23:45 +0000] "GET /orders/1001 HTTP/1.1" 200 256 "-" "curl/7.64.1"
    
    JSON format (if configured):
    {"remote_addr": "1.2.3.4", "remote_user": "user_a", "request": "GET /orders/1001", ...}
    
    Returns: same structure as kong parser
    """
    pass

def parse_envoy_logs(path: str) -> dict:
    """
    Parse Envoy proxy access logs (common in Kubernetes/service mesh).
    
    Returns: same structure as kong parser
    """
    pass

def parse_gateway_logs(path: str) -> dict:
    """
    Main entry point. Detects format and parses accordingly.
    
    Returns:
        {
            "format": "kong",
            "endpoints": [...],
            "users": [...],
            "auth_patterns": {...},
            "resource_access": {...},
            "request_samples": {...}  # sample payloads per endpoint
        }
    """
    format = detect_gateway_log_format(path)
    
    parsers = {
        "kong": parse_kong_logs,
        "aws_api_gateway": parse_aws_api_gateway_logs,
        "apigee": parse_apigee_logs,
        "nginx": parse_nginx_access_logs,
        "envoy": parse_envoy_logs
    }
    
    if format in parsers:
        return {"format": format, **parsers[format](path)}
    else:
        return {"format": "unknown", "error": "Unrecognized log format"}
```


# ============================================================================
# PROMPT PART 2: Add QA/Test Log Parsers
# ============================================================================

Add support for parsing QA and test execution logs.

## File: apisec/inference/test_logs.py

```python
"""
Parse QA and test execution logs.
These often contain valid request/response pairs, test user credentials,
and working payloads that passed validation.
"""

def detect_test_log_format(path: str) -> str:
    """
    Detect test framework format.
    Returns: 'pytest' | 'jest' | 'mocha' | 'postman_newman' | 'karate' | 'rest_assured' | 'unknown'
    """
    pass

def parse_pytest_logs(path: str) -> dict:
    """
    Parse pytest output logs.
    
    Look for:
    - API calls made during tests
    - Request/response captures
    - Test fixtures used
    - Auth setup in conftest
    
    Returns:
        {
            "endpoints_tested": [...],
            "payloads": {...},
            "auth_setup": {...},
            "test_users": [...]
        }
    """
    pass

def parse_newman_logs(path: str) -> dict:
    """
    Parse Postman/Newman CLI output.
    
    Newman JSON output contains full request/response for each test.
    
    Returns: same structure
    """
    pass

def parse_karate_logs(path: str) -> dict:
    """
    Parse Karate test framework logs.
    
    Karate logs are verbose and contain full HTTP exchanges.
    
    Returns: same structure
    """
    pass

def parse_rest_assured_logs(path: str) -> dict:
    """
    Parse REST Assured (Java) test logs.
    
    Returns: same structure
    """
    pass

def parse_test_logs(path: str) -> dict:
    """
    Main entry point. Detects format and parses accordingly.
    """
    pass
```


# ============================================================================
# PROMPT PART 3: Add Test Fixtures Parser
# ============================================================================

Add support for parsing test fixtures and seed data.

## File: apisec/inference/fixtures.py

```python
"""
Parse test fixtures and database seed files.
These contain valid test data that developers created specifically for testing.
"""

def scan_for_fixtures(repo_path: str) -> list:
    """
    Find fixture files in common locations.
    
    Looks in:
    - tests/fixtures/
    - test/fixtures/
    - __tests__/fixtures/
    - fixtures/
    - tests/data/
    - test_data/
    - seeds/
    - db/seeds/
    - prisma/seed.ts
    - spec/fixtures/ (Ruby/RSpec)
    
    File types:
    - JSON files
    - YAML files
    - Python files (pytest fixtures)
    - JavaScript/TypeScript files (Jest)
    - SQL files (database seeds)
    
    Returns: list of fixture file paths
    """
    pass

def parse_json_fixtures(path: str) -> dict:
    """
    Parse JSON fixture files.
    
    Common patterns:
    - {"users": [...], "orders": [...]}
    - Array of objects
    - Nested test scenarios
    
    Extract:
    - Entity types (users, orders, etc.)
    - Sample records
    - Relationships (user_id in orders)
    - IDs that can be used for testing
    
    Returns:
        {
            "entities": {
                "users": [{"id": "user_a", "role": "user"}, ...],
                "orders": [{"id": "1001", "user_id": "user_a"}, ...]
            },
            "relationships": {
                "orders.user_id": "users.id"
            },
            "ownership": {
                "user_a": {"orders": ["1001", "1002"]},
                "user_b": {"orders": ["2001"]}
            }
        }
    """
    pass

def parse_pytest_fixtures(path: str) -> dict:
    """
    Parse Python pytest fixture files (conftest.py, fixtures.py).
    
    Look for:
    - @pytest.fixture definitions
    - Test user creation
    - Auth token generation
    - Sample payload factories
    
    Returns: structured fixture data
    """
    pass

def parse_database_seeds(path: str) -> dict:
    """
    Parse database seed files (SQL, Prisma, etc.).
    
    Extract:
    - INSERT statements
    - User records
    - Resource ownership
    
    Returns: structured seed data
    """
    pass

def parse_fixtures(repo_path: str) -> dict:
    """
    Main entry point. Finds and parses all fixtures.
    
    Returns:
        {
            "fixtures_found": ["tests/fixtures/users.json", ...],
            "users": [...],
            "test_data": {...},
            "resource_ownership": {...},
            "sample_payloads": {...}
        }
    """
    pass
```


# ============================================================================
# PROMPT PART 4: Add Docker/CI Config Parsers
# ============================================================================

Add support for parsing Docker and CI/CD configs.

## File: apisec/inference/devops.py

```python
"""
Parse Docker Compose and CI/CD configuration files.
These reveal environment structure, URLs, and secrets references.
"""

def parse_docker_compose(path: str) -> dict:
    """
    Parse docker-compose.yaml
    
    Extract:
    - Service names and ports
    - Environment variables
    - Network configuration
    - URLs for services
    
    Returns:
        {
            "services": {
                "api": {
                    "ports": ["8000:8000"],
                    "environment": {
                        "DATABASE_URL": "...",
                        "AUTH_URL": "..."
                    }
                }
            },
            "inferred_urls": {
                "api": "http://localhost:8000"
            },
            "env_vars": ["DATABASE_URL", "AUTH_URL", ...]
        }
    """
    pass

def parse_github_actions(path: str) -> dict:
    """
    Parse .github/workflows/*.yml
    
    Extract:
    - Environment names (staging, production)
    - Secrets referenced (${{ secrets.API_KEY }})
    - Environment URLs
    - Deployment targets
    
    Returns:
        {
            "environments": ["staging", "production"],
            "secrets_referenced": ["API_KEY", "CLIENT_SECRET", ...],
            "env_urls": {"staging": "https://staging.api.com"},
            "deployment_config": {...}
        }
    """
    pass

def parse_gitlab_ci(path: str) -> dict:
    """
    Parse .gitlab-ci.yml
    
    Returns: same structure as github actions parser
    """
    pass

def parse_env_example(path: str) -> dict:
    """
    Parse .env.example or .env.sample
    
    These show what env vars are expected without actual values.
    
    Returns:
        {
            "expected_vars": ["API_URL", "CLIENT_ID", "CLIENT_SECRET"],
            "categorized": {
                "urls": ["API_URL", "AUTH_URL"],
                "credentials": ["CLIENT_ID", "CLIENT_SECRET"],
                "other": ["DEBUG", "LOG_LEVEL"]
            }
        }
    """
    pass

def parse_devops_configs(repo_path: str) -> dict:
    """
    Main entry point. Finds and parses all devops configs.
    
    Returns combined insights from docker-compose, CI/CD, env examples.
    """
    pass
```


# ============================================================================
# PROMPT PART 5: Update Scanner
# ============================================================================

Update apisec/inference/scanner.py to find all these new sources.

```python
def scan_repo(path: str) -> dict:
    """
    Comprehensive repo scan for all artifact types.
    
    Returns:
        {
            # Existing
            "openapi_specs": [...],
            "postman_collections": [...],
            "postman_environments": [...],
            "env_files": [...],
            "log_files": [...],
            
            # New
            "gateway_logs": [...],           # Kong, AWS API Gateway, etc.
            "test_logs": [...],              # pytest, newman, karate output
            "fixture_files": [...],          # Test fixtures and seed data
            "docker_compose": [...],         # docker-compose.yml
            "ci_configs": [...],             # .github/workflows/, .gitlab-ci.yml
            "env_examples": [...],           # .env.example, .env.sample
            "code_files": {                  # For route/auth analysis
                "python": [...],
                "javascript": [...],
                "typescript": [...],
                "java": [...]
            }
        }
    """
    pass
```


# ============================================================================
# PROMPT PART 6: Requirement → Source Mapping
# ============================================================================

Create a new module that maps requirements to sources with priority.

## File: apisec/inference/strategy.py

```python
"""
Intelligent gathering strategy.
Maps each requirement to sources, with priority order.
"""

REQUIREMENT_SOURCES = {
    "host_url": {
        "description": "Running instance URL (staging/dev)",
        "sources": [
            {"name": "postman_environment", "field": "base_url", "priority": 1},
            {"name": "env_files", "field": "BASE_URL|API_URL", "priority": 2},
            {"name": "docker_compose", "field": "inferred_urls", "priority": 3},
            {"name": "openapi_spec", "field": "servers", "priority": 4},
            {"name": "ci_configs", "field": "env_urls", "priority": 5},
            {"name": "ask_dev", "priority": 99}
        ]
    },
    
    "endpoints": {
        "description": "API endpoints and their signatures",
        "sources": [
            {"name": "openapi_spec", "field": "paths", "priority": 1},
            {"name": "postman_collection", "field": "requests", "priority": 2},
            {"name": "gateway_logs", "field": "endpoints", "priority": 3},
            {"name": "code_analysis", "field": "routes", "priority": 4},
            {"name": "ask_dev", "priority": 99}
        ]
    },
    
    "payloads": {
        "description": "Working request payloads",
        "sources": [
            {"name": "postman_collection", "field": "request_bodies", "priority": 1},
            {"name": "gateway_logs", "field": "request_samples", "priority": 2},
            {"name": "test_logs", "field": "payloads", "priority": 3},
            {"name": "fixture_files", "field": "sample_payloads", "priority": 4},
            {"name": "openapi_spec", "field": "examples", "priority": 5},
            {"name": "ask_dev", "priority": 99}
        ]
    },
    
    "auth_config": {
        "description": "Authentication type and configuration",
        "sources": [
            {"name": "postman_collection", "field": "auth", "priority": 1},
            {"name": "openapi_spec", "field": "securitySchemes", "priority": 2},
            {"name": "gateway_logs", "field": "auth_patterns", "priority": 3},
            {"name": "code_analysis", "field": "auth_middleware", "priority": 4},
            {"name": "ask_dev", "priority": 99}
        ]
    },
    
    "auth_credentials": {
        "description": "Actual credentials (tokens, client_id/secret)",
        "sources": [
            {"name": "postman_environment", "field": "credentials", "priority": 1},
            {"name": "env_files", "field": "secrets", "priority": 2},
            {"name": "fixture_files", "field": "test_credentials", "priority": 3},
            {"name": "ask_dev", "priority": 99}  # Often required
        ]
    },
    
    "bola_identities": {
        "description": "Multiple user identities for BOLA testing",
        "sources": [
            {"name": "postman_environment", "field": "user_tokens", "priority": 1},
            {"name": "fixture_files", "field": "users", "priority": 2},
            {"name": "gateway_logs", "field": "users", "priority": 3},
            {"name": "test_logs", "field": "test_users", "priority": 4},
            {"name": "ask_dev", "priority": 99}  # Often required
        ]
    },
    
    "resource_ownership": {
        "description": "Which user owns which resources",
        "sources": [
            {"name": "gateway_logs", "field": "resource_access", "priority": 1},
            {"name": "fixture_files", "field": "ownership", "priority": 2},
            {"name": "log_files", "field": "inferred_ownership", "priority": 3},
            {"name": "ask_dev", "priority": 99}
        ]
    },
    
    "rbac_roles": {
        "description": "Role model and role-based accounts",
        "sources": [
            {"name": "code_analysis", "field": "role_annotations", "priority": 1},
            {"name": "fixture_files", "field": "roles", "priority": 2},
            {"name": "openapi_spec", "field": "security_scopes", "priority": 3},
            {"name": "ask_dev", "priority": 99}  # Usually required
        ]
    }
}


def build_gathering_plan(artifacts: dict) -> dict:
    """
    Given found artifacts, build a plan for what can be inferred vs. what to ask.
    
    Args:
        artifacts: Output from scanner.scan_repo()
    
    Returns:
        {
            "can_infer": {
                "host_url": {"source": "postman_environment", "confidence": "high"},
                "endpoints": {"source": "openapi_spec", "confidence": "high"},
                ...
            },
            "must_ask": ["auth_credentials", "bola_identities"],
            "gathering_order": [
                "host_url",      # Start with basics
                "endpoints",
                "payloads",
                "auth_config",
                "auth_credentials",  # May need to ask
                "bola_identities",   # May need to ask
                "resource_ownership",
                "rbac_roles"
            ]
        }
    """
    pass


def gather_requirement(requirement: str, artifacts: dict, parsed_data: dict) -> dict:
    """
    Attempt to gather a specific requirement from available sources.
    
    Args:
        requirement: One of the REQUIREMENT_SOURCES keys
        artifacts: Found artifact paths
        parsed_data: Already parsed data from artifacts
    
    Returns:
        {
            "found": True/False,
            "value": <the data>,
            "source": "postman_environment",
            "confidence": "high" | "medium" | "low",
            "needs_confirmation": True/False
        }
    """
    pass
```


# ============================================================================
# PROMPT PART 7: Update Agent Tools
# ============================================================================

Add new tools to apisec/agent/tools.py:

```python
# Add these tool definitions

{
    "type": "function",
    "function": {
        "name": "parse_gateway_logs",
        "description": "Parse API gateway logs (Kong, AWS API Gateway, Apigee, nginx). Extracts endpoints, users, auth patterns, and request samples.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the gateway log file"
                }
            },
            "required": ["path"]
        }
    }
},

{
    "type": "function",
    "function": {
        "name": "parse_test_logs",
        "description": "Parse QA/test execution logs (pytest, Jest, Newman, Karate). Extracts tested endpoints, payloads, and auth setup.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the test log file"
                }
            },
            "required": ["path"]
        }
    }
},

{
    "type": "function",
    "function": {
        "name": "parse_fixtures",
        "description": "Parse test fixtures and seed data. Extracts test users, sample data, and resource ownership.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to fixtures directory or file"
                }
            },
            "required": ["path"]
        }
    }
},

{
    "type": "function",
    "function": {
        "name": "parse_devops_configs",
        "description": "Parse Docker Compose and CI/CD configs. Extracts service URLs, environment variables, and secrets references.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to repo root to scan for devops configs"
                }
            },
            "required": ["path"]
        }
    }
},

{
    "type": "function",
    "function": {
        "name": "get_gathering_status",
        "description": "Check what requirements have been gathered vs. what's still needed. Use this to know what to ask about.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
}
```


# ============================================================================
# PROMPT PART 8: Updated System Prompt
# ============================================================================

Replace/enhance the system prompt with this intelligence:

```markdown
# APIsec Agent — System Prompt (Enhanced)

You are an APIsec configuration assistant. Your job is to gather everything needed
for API security testing with minimal developer friction.

## What You Must Gather

You need 6 things. 4 are must-haves, 2 are for deeper testing:

### Must-Haves (testing is impossible without these)

1. **Host URL** — A running instance to test against (staging/dev)
2. **Endpoints + Signatures** — What endpoints exist, parameters, types
3. **Working Payloads** — Valid request bodies that won't 400
4. **Auth Config + Credentials** — How to authenticate + actual tokens/creds

### Deeper Requirements (for real security value)

5. **BOLA Identities** — 2+ user accounts with different resource ownership
6. **RBAC Roles** — Accounts for different roles (user, admin, etc.)

## What Good Questions Sound Like

The dev should feel like they're talking to a smart colleague who's trying to deeply understand their API.

**Questions that show you're thinking:**
- "Your Postman shows client_credentials, but I also see user_a_token and user_b_token. Do you use both service-level and user-level auth?"
- "The OpenAPI spec lists /orders/{id} but your logs show /v2/orders/{id}. Which is current?"
- "I see rate limiting headers in your gateway logs. Should I be aware of limits during testing?"

**Questions that uncover nuance:**
- "Users can only see their own orders — are there exceptions? Like shared orders, or org-level access?"
- "Your fixtures show an 'admin' role. What can admins do that regular users can't?"
- "I see soft deletes in your schema (deleted_at field). Should deleted orders be invisible to users?"

**Questions that validate understanding:**
- "So the auth flow is: get token from /auth/token with client creds, then use Bearer header. Correct?"
- "Just to confirm — user_a should see orders 1001-1003, and user_b should NOT be able to see those. Right?"

**Questions that tap into tribal knowledge:**
- "Any endpoints that are particularly sensitive? Things that have broken before?"
- "Are there test accounts I should avoid? Or rate limits that might block testing?"
- "Anything quirky about the auth that I wouldn't know from the spec?"

## Your Gathering Strategy

### Priority Order for Each Requirement

**Host URL:**
1. Postman environment → `base_url` (most reliable)
2. .env files → `BASE_URL`, `API_URL`
3. Docker Compose → service ports
4. OpenAPI spec → `servers` section
5. CI/CD configs → deployment URLs
6. ASK DEV (last resort)

**Endpoints + Signatures:**
1. OpenAPI spec → full definitions (best)
2. Postman collection → requests
3. Gateway logs → observed endpoints
4. Code analysis → route definitions
5. ASK DEV (last resort)

**Working Payloads:**
1. Postman collection → request bodies (devs test with these)
2. Gateway logs → actual request bodies from traffic
3. Test logs → payloads that passed
4. Test fixtures → sample data
5. OpenAPI examples → often minimal
6. ASK DEV (last resort)

**Auth Config:**
1. Postman collection → auth configuration + pre-request scripts
2. OpenAPI spec → securitySchemes
3. Gateway logs → auth header patterns
4. Code analysis → auth middleware
5. ASK DEV (last resort)

**Auth Credentials:**
1. Postman environment → client_id, client_secret, tokens
2. .env files → credential variables (if present)
3. Test fixtures → test credentials
4. ASK DEV (often required — this is sensitive)

**BOLA Identities:**
1. Postman environment → user_a_token, user_b_token, etc.
2. Test fixtures → test user definitions
3. Gateway logs → user IDs observed
4. Test logs → users in test runs
5. ASK DEV (often required)

**Resource Ownership:**
1. Gateway logs → who accessed what (gold!)
2. Test fixtures → ownership in seed data
3. Application logs → inferred from access patterns
4. ASK DEV (often required)

**RBAC Roles:**
1. Code analysis → @roles(['admin']), permission decorators
2. Test fixtures → role definitions
3. OpenAPI security scopes
4. ASK DEV (usually required — tribal knowledge)

## Conversation Flow

### Phase 1: Scan Everything

When you start, scan for ALL artifact types:
- OpenAPI specs
- Postman collections + environments
- Gateway logs (Kong, AWS API Gateway, nginx, etc.)
- Test logs (pytest, Newman, etc.)
- Test fixtures and seed data
- Docker Compose
- CI/CD configs
- .env files and .env.example

Report what you found clearly.

### Phase 2: Gather from Artifacts (No Questions Yet)

For each requirement, work through sources in priority order.
Parse everything available. Build a picture of what you know.

Track internally:
- ✅ Gathered (high confidence)
- ⚠️ Gathered (needs confirmation)
- ❌ Not found (must ask)

### Phase 3: Present Findings + Confirm

Show the developer what you gathered:

```
Here's what I found:

Host URL: https://staging-api.company.com
  (from Postman staging environment)

Endpoints: 14 endpoints
  (from OpenAPI spec at ./docs/openapi.yaml)

Auth: OAuth2 client_credentials
  Token endpoint: https://auth.company.com/token
  (from Postman collection pre-request script)

Credentials: 
  ✓ client_id: staging_service
  ✓ client_secret: [found in Postman env]
  (from Postman staging environment)

BOLA Users:
  ✓ user_a with token [found]
  ✓ user_b with token [found]
  Resource ownership: inferred from gateway logs
    - user_a accessed orders 1001, 1002, 1003
    - user_b accessed orders 2001, 2002

Does this look right?
```

### Phase 4: Fill Gaps (Ask Smart Questions)

Ask about things you couldn't find OR need to validate. Be specific and show your reasoning:

**Good (shows thinking, asks with context):**
```
I have the basic auth flow working, but I want to make sure I understand BOLA correctly.

From your gateway logs, I see:
- user_a accessed orders 1001, 1002, 1003
- user_b accessed orders 2001, 2002

Is that the pattern — users can only see their own orders? 
Or are there exceptions (like org-level access, or shared orders)?
```

**Good (validates understanding):**
```
Your Postman environment has admin_token, but I don't see any admin-specific 
endpoints in your OpenAPI spec. 

Are there admin routes I should test? Or is admin just "can see all resources"?
```

**Bad (just collecting data):**
```
Please provide:
- Admin username
- Admin password
- Admin role name
- Admin permissions
```

### Phase 5: Handle Edge Cases

**Multiple environments found:**
```
I found 3 Postman environments: dev, staging, prod.
Which should I use for security testing? (I'd recommend staging)
```

**Conflicting information:**
```
I found different base URLs:
- Postman env: https://staging-api.company.com
- OpenAPI spec: https://api.company.com

Which is correct for testing?
```

**Missing credentials despite rich artifacts:**
```
I found everything except actual credentials.
Your Postman environment has placeholders for client_id and client_secret.

Can you provide test credentials? 
(I'll store them as environment variable references, not in the config file)
```

**No OpenAPI spec:**
```
I didn't find an OpenAPI spec, but I found:
- 23 endpoints in your Postman collection
- 45 unique endpoints in gateway logs

I can build the endpoint inventory from these. Should I proceed?
```

## Intelligence Guidelines

1. **Ask the right questions, not fewer questions.** The goal isn't to minimize interaction — it's to make every question feel purposeful. The dev should think "that's a smart question" not "why is it asking me this?"

2. **Be a smart colleague onboarding onto their project.** You're not a form. You're not a robot. You're someone who's trying to understand their API deeply and asking the questions that matter.

3. **Cross-reference sources to ask better questions.** If gateway logs show user_a accessing orders 1001-1003, don't ask "what resources does user_a own?" — ask "I see user_a accesses orders 1001-1003 in your logs. Is that the ownership pattern, or is there more nuance?"

4. **Validate understanding, don't just collect data.** "Your Postman shows OAuth2 with client_credentials. But I also see user tokens — do you use both flows?" shows you're thinking, not just parsing.

5. **Uncover nuance that artifacts can't capture.** Artifacts show what exists. Questions uncover: edge cases, exceptions, business logic, tribal knowledge. "Users can only see their own orders — unless they're in the same organization?"

6. **Explain your sources.** "I found X in your Postman environment" builds trust. The dev knows you're not guessing.

7. **Make the dev feel like a useful collaborator.** They have context you can't get from files. Honor that. Their answers should feel valuable, not like filling out forms.

## Response Style

- Show your thinking: "From your gateway logs, I can see user_a accessed orders 1001-1003 — that suggests ownership-based access control"
- Ask with context: "I see OAuth2 in your spec, but your Postman uses a custom header. Which is current?"
- Validate, don't assume: "So users can only see their own orders — any exceptions I should know about?"
- Offer insight: "Your logs show 403s when user_a hits /admin endpoints — looks like you have role-based restrictions there"
- Respect their expertise: They built this API. They know things the artifacts don't capture. Ask questions that tap into that knowledge.

## Tools Available

- scan_repo: Find all artifacts
- parse_openapi: Parse OpenAPI/Swagger specs
- parse_postman: Parse Postman collections
- parse_postman_environment: Parse Postman environments
- parse_logs: Parse application logs
- parse_gateway_logs: Parse API gateway logs (Kong, AWS, nginx, etc.)
- parse_test_logs: Parse test execution logs
- parse_fixtures: Parse test fixtures and seed data
- parse_devops_configs: Parse Docker Compose and CI/CD configs
- get_gathering_status: Check what's gathered vs. what's missing
- generate_config: Create the final config file
```


# ============================================================================
# PROMPT PART 9: Add Sample Gateway Logs to Sample API
# ============================================================================

Add sample gateway logs to the sample-orders-api repo.

## File: logs/gateway-access.log

Create Kong-style JSON logs (~300 entries):

```json
{"timestamp":"2024-01-15T10:23:45.123Z","request":{"uri":"/orders/1001","method":"GET","headers":{"authorization":"Bearer eyJhbG...","content-type":"application/json"}},"response":{"status":200},"authenticated_entity":{"consumer_id":"user_a"},"latencies":{"request":45,"kong":2,"proxy":43},"client_ip":"10.0.1.50"}
{"timestamp":"2024-01-15T10:23:46.456Z","request":{"uri":"/orders","method":"POST","headers":{"authorization":"Bearer eyJhbG...","content-type":"application/json"},"body":{"product":"Widget X","amount":149.99}},"response":{"status":201},"authenticated_entity":{"consumer_id":"user_a"},"latencies":{"request":120,"kong":3,"proxy":117},"client_ip":"10.0.1.50"}
```

Include:
- Different users (user_a, user_b, admin)
- Different endpoints
- Clear ownership patterns (user_a always accesses 1001-1003, user_b accesses 2001-2002)
- Mix of GET, POST, PUT, DELETE
- Some 401/403 errors (for realism)


# ============================================================================
# PROMPT PART 10: Add Test Fixtures to Sample API
# ============================================================================

Add test fixtures to the sample-orders-api repo.

## File: tests/fixtures/users.json

```json
{
  "users": [
    {
      "id": "user_a",
      "email": "user_a@test.com",
      "role": "user",
      "password_hash": "..."
    },
    {
      "id": "user_b", 
      "email": "user_b@test.com",
      "role": "user",
      "password_hash": "..."
    },
    {
      "id": "admin",
      "email": "admin@test.com",
      "role": "admin",
      "password_hash": "..."
    }
  ]
}
```

## File: tests/fixtures/orders.json

```json
{
  "orders": [
    {"id": "1001", "user_id": "user_a", "product": "Widget A", "amount": 99.99, "status": "shipped"},
    {"id": "1002", "user_id": "user_a", "product": "Widget B", "amount": 149.99, "status": "pending"},
    {"id": "1003", "user_id": "user_a", "product": "Widget C", "amount": 199.99, "status": "delivered"},
    {"id": "2001", "user_id": "user_b", "product": "Gadget X", "amount": 299.99, "status": "pending"},
    {"id": "2002", "user_id": "user_b", "product": "Gadget Y", "amount": 399.99, "status": "shipped"}
  ]
}
```

## File: tests/fixtures/test_credentials.json

```json
{
  "service_account": {
    "client_id": "service_account",
    "client_secret": "service_secret"
  },
  "test_users": {
    "user_a": {"username": "user_a", "password": "password_a"},
    "user_b": {"username": "user_b", "password": "password_b"},
    "admin": {"username": "admin", "password": "admin_password"}
  }
}
```


# ============================================================================
# PROMPT PART 11: Add Docker Compose to Sample API
# ============================================================================

Add Docker Compose configuration.

## File: docker-compose.yaml

```yaml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/orders
      - AUTH_SECRET=dev_secret_key_12345
      - LOG_LEVEL=DEBUG
    depends_on:
      - db

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=orders
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```


# ============================================================================
# PROMPT PART 12: Add CI Config to Sample API
# ============================================================================

Add GitHub Actions workflow.

## File: .github/workflows/test.yml

```yaml
name: Test

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  STAGING_URL: https://staging-api.orders.example.com
  AUTH_URL: https://staging-api.orders.example.com/auth/token

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run tests
        env:
          API_URL: http://localhost:8000
          CLIENT_ID: ${{ secrets.TEST_CLIENT_ID }}
          CLIENT_SECRET: ${{ secrets.TEST_CLIENT_SECRET }}
          USER_A_TOKEN: ${{ secrets.USER_A_TOKEN }}
          USER_B_TOKEN: ${{ secrets.USER_B_TOKEN }}
        run: pytest tests/
      
  deploy-staging:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - name: Deploy to staging
        env:
          STAGING_API_KEY: ${{ secrets.STAGING_API_KEY }}
        run: echo "Deploying to staging..."
```


# ============================================================================
# VERIFICATION
# ============================================================================

After implementing, verify:

[ ] Scanner finds gateway logs, test fixtures, docker-compose, CI configs
[ ] Gateway log parser extracts users, endpoints, ownership patterns
[ ] Fixtures parser extracts test users, resource ownership
[ ] Strategy module correctly prioritizes sources
[ ] Agent uses get_gathering_status to know what's missing
[ ] Agent cross-references sources to ask smarter questions
[ ] Agent explains where it found each piece of information
[ ] Agent asks questions that show it's thinking (not just collecting)
[ ] Agent validates understanding before proceeding
[ ] Agent uncovers nuance (exceptions, edge cases, tribal knowledge)
[ ] Dev feels like they're collaborating with a smart colleague
[ ] Conversation feels intelligent and purposeful

Key test: After the conversation, ask yourself:
- "Did the agent ask questions I wouldn't have thought to document?"
- "Did I feel like my answers mattered?"
- "Would I trust this agent to understand my API?"

# ============================================================================
# END OF ENHANCEMENT PROMPT
# ============================================================================
