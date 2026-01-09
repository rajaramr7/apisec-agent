"""
Requirement → Source Mapping Strategy.

This is the brain of intelligent requirement gathering. It knows what information
is needed for each level of security testing and where to find it.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pathlib import Path


class SecurityLevel(Enum):
    """Security testing levels in priority order."""
    BASIC = 1       # No auth, basic scanning
    AUTHENTICATED = 2  # With auth, full endpoint coverage
    BOLA = 3        # Multi-user, horizontal privilege testing
    RBAC = 4        # Role-based, vertical privilege testing


class RequirementStatus(Enum):
    """Status of a requirement."""
    MISSING = "missing"           # Not found anywhere
    INFERRED = "inferred"         # Found in artifacts, needs confirmation
    CONFIRMED = "confirmed"       # User confirmed
    PROVIDED = "provided"         # User directly provided


@dataclass
class Requirement:
    """A single configuration requirement."""
    name: str
    description: str
    level: SecurityLevel
    required: bool = True
    value: Any = None
    status: RequirementStatus = RequirementStatus.MISSING
    source: Optional[str] = None  # Where the value was found
    confidence: float = 0.0       # 0.0 to 1.0


@dataclass
class ArtifactSource:
    """Represents an artifact that can provide information."""
    path: str
    artifact_type: str
    parsed_data: Optional[Dict[str, Any]] = None
    provides: Set[str] = field(default_factory=set)  # What requirements it can fulfill


class RequirementStrategy:
    """
    Maps requirements to artifact sources and tracks fulfillment.

    This class understands:
    1. What information is needed for each security level
    2. Where to find each piece of information
    3. How to prioritize sources (some are more reliable than others)
    """

    # Mapping of requirement names to potential artifact sources
    # Priority order: earlier sources are preferred
    REQUIREMENT_SOURCES = {
        # Level 1: Basic
        "api_name": [
            ("openapi", "info.title"),
            ("postman", "info.name"),
            ("docker_compose", "services.*.image"),
            ("ci_configs", "workflow_name"),
        ],
        "base_url": [
            ("postman_environments", "url_related.base_url"),
            ("docker_compose", "inferred_base_url"),
            ("env", "BASE_URL"),
            ("openapi", "servers[0].url"),
            ("gateway_logs", "inferred from hosts"),
        ],
        "spec_path": [
            ("openapi", "file_path"),
        ],
        "endpoints": [
            ("openapi", "endpoints"),
            ("postman", "requests"),
            ("gateway_logs", "endpoints"),
            ("test_outputs", "endpoints_tested"),
        ],

        # Level 2: Auth
        "auth_type": [
            ("openapi", "security_schemes"),
            ("postman", "auth.type"),
            ("postman_environments", "auth_related"),
            ("gateway_logs", "auth_patterns.type"),
            ("test_outputs", "auth_observed.type"),
        ],
        "token_endpoint": [
            ("postman", "auth.token_url"),
            ("postman_environments", "url_related.auth_url"),
            ("openapi", "security_schemes.*.tokenUrl"),
            ("env", "TOKEN_URL|AUTH_URL"),
        ],
        "client_id": [
            ("postman_environments", "auth_related.client_id"),
            ("env", "CLIENT_ID"),
            ("docker_compose", "credentials_config.client_id_var"),
            ("ci_configs", "secrets_used"),
        ],
        "client_secret": [
            ("postman_environments", "auth_related.client_secret"),
            ("env", "CLIENT_SECRET"),
            ("docker_compose", "credentials_config.client_secret_var"),
            ("ci_configs", "secrets_used"),
        ],

        # Level 3: BOLA
        "test_users": [
            ("fixtures", "test_users"),
            ("postman_environments", "user_identities"),
            ("gateway_logs", "users"),
            ("test_outputs", "users extracted from tests"),
            ("logs", "user patterns"),
        ],
        "resource_ownership": [
            ("fixtures", "ownership_map"),
            ("gateway_logs", "resource_access"),
            ("logs", "user to resource mapping"),
            ("test_outputs", "sample_responses"),
        ],
        "user_credentials": [
            ("postman_environments", "user_identities.*.token"),
            ("fixtures", "user records with passwords"),
            ("env", "USER_*_TOKEN"),
        ],

        # Level 4: RBAC
        "roles": [
            ("fixtures", "entities.users[].role"),
            ("openapi", "security_schemes.scopes"),
            ("postman_environments", "role patterns"),
        ],
        "role_permissions": [
            ("openapi", "security requirements per endpoint"),
            ("fixtures", "role definitions"),
        ],
    }

    def __init__(self):
        """Initialize the strategy with empty requirements."""
        self.requirements: Dict[str, Requirement] = {}
        self.sources: Dict[str, ArtifactSource] = {}
        self._initialize_requirements()

    def _initialize_requirements(self):
        """Set up all known requirements."""
        requirement_defs = [
            # Level 1: Basic
            ("api_name", "Human-readable name of the API", SecurityLevel.BASIC, True),
            ("base_url", "Base URL for the API (e.g., https://api.example.com)", SecurityLevel.BASIC, True),
            ("spec_path", "Path to OpenAPI specification file", SecurityLevel.BASIC, False),
            ("endpoints", "List of API endpoints", SecurityLevel.BASIC, True),

            # Level 2: Authenticated
            ("auth_type", "Authentication type (oauth2, api_key, basic, bearer)", SecurityLevel.AUTHENTICATED, True),
            ("token_endpoint", "OAuth2 token endpoint URL", SecurityLevel.AUTHENTICATED, False),
            ("client_id", "OAuth2 client ID or API key identifier", SecurityLevel.AUTHENTICATED, False),
            ("client_secret", "OAuth2 client secret", SecurityLevel.AUTHENTICATED, False),

            # Level 3: BOLA
            ("test_users", "List of test user identities", SecurityLevel.BOLA, True),
            ("resource_ownership", "Mapping of users to owned resources", SecurityLevel.BOLA, True),
            ("user_credentials", "Credentials for each test user", SecurityLevel.BOLA, True),

            # Level 4: RBAC
            ("roles", "List of roles in the system", SecurityLevel.RBAC, True),
            ("role_permissions", "What each role can do", SecurityLevel.RBAC, True),
        ]

        for name, desc, level, required in requirement_defs:
            self.requirements[name] = Requirement(
                name=name,
                description=desc,
                level=level,
                required=required
            )

    def register_source(self, path: str, artifact_type: str, parsed_data: Dict[str, Any]):
        """Register an artifact source with its parsed data."""
        source = ArtifactSource(
            path=path,
            artifact_type=artifact_type,
            parsed_data=parsed_data,
            provides=self._determine_provides(artifact_type, parsed_data)
        )
        self.sources[path] = source

    def _determine_provides(self, artifact_type: str, data: Dict[str, Any]) -> Set[str]:
        """Determine what requirements an artifact can provide."""
        provides = set()

        for req_name, sources in self.REQUIREMENT_SOURCES.items():
            for source_type, _ in sources:
                if source_type == artifact_type:
                    # Check if the data actually contains relevant info
                    if self._has_data_for(req_name, artifact_type, data):
                        provides.add(req_name)

        return provides

    def _has_data_for(self, req_name: str, artifact_type: str, data: Dict[str, Any]) -> bool:
        """Check if data contains information for a requirement."""
        if not data:
            return False

        # Type-specific checks
        if artifact_type == "openapi":
            if req_name == "api_name":
                return bool(data.get("info", {}).get("title"))
            elif req_name == "base_url":
                return bool(data.get("servers"))
            elif req_name == "endpoints":
                return bool(data.get("endpoints"))
            elif req_name == "auth_type":
                return bool(data.get("security_schemes"))

        elif artifact_type == "postman_environments":
            if req_name == "base_url":
                return bool(data.get("url_related", {}).get("base_url"))
            elif req_name == "client_id":
                return "client_id" in str(data.get("auth_related", {})).lower()
            elif req_name == "test_users":
                return bool(data.get("user_identities"))

        elif artifact_type == "fixtures":
            if req_name == "test_users":
                return bool(data.get("test_users"))
            elif req_name == "resource_ownership":
                return bool(data.get("ownership_map"))

        elif artifact_type == "gateway_logs":
            if req_name == "endpoints":
                return bool(data.get("endpoints"))
            elif req_name == "test_users":
                return bool(data.get("users"))
            elif req_name == "auth_type":
                return bool(data.get("auth_patterns"))

        elif artifact_type == "docker_compose":
            if req_name == "base_url":
                return bool(data.get("inferred_base_url"))
            elif req_name in ("client_id", "client_secret"):
                return bool(data.get("credentials_config"))

        elif artifact_type == "test_outputs":
            if req_name == "endpoints":
                return bool(data.get("endpoints_tested"))
            elif req_name == "auth_type":
                return bool(data.get("auth_observed"))

        return False

    def extract_requirement(self, req_name: str, artifact_type: str, data: Dict[str, Any]) -> Optional[Any]:
        """Extract a requirement value from artifact data."""
        if not data:
            return None

        if artifact_type == "openapi":
            if req_name == "api_name":
                return data.get("info", {}).get("title")
            elif req_name == "base_url":
                servers = data.get("servers", [])
                return servers[0].get("url") if servers else None
            elif req_name == "endpoints":
                return data.get("endpoints", [])
            elif req_name == "auth_type":
                schemes = data.get("security_schemes", {})
                if schemes:
                    # Return first scheme type
                    first = list(schemes.values())[0]
                    return first.get("type")

        elif artifact_type == "postman_environments":
            if req_name == "base_url":
                return data.get("url_related", {}).get("base_url")
            elif req_name == "token_endpoint":
                return data.get("url_related", {}).get("auth_url")
            elif req_name == "client_id":
                auth = data.get("auth_related", {})
                return auth.get("client_id") or auth.get("CLIENT_ID")
            elif req_name == "test_users":
                return list(data.get("user_identities", {}).keys())
            elif req_name == "user_credentials":
                return data.get("user_identities", {})

        elif artifact_type == "fixtures":
            if req_name == "test_users":
                return data.get("test_users", [])
            elif req_name == "resource_ownership":
                return data.get("ownership_map", {})
            elif req_name == "roles":
                # Try to extract roles from user records
                roles = set()
                for entity_type, records in data.get("entities", {}).items():
                    if entity_type in ("users", "user", "accounts"):
                        for record in records:
                            if "role" in record:
                                roles.add(record["role"])
                return list(roles) if roles else None

        elif artifact_type == "gateway_logs":
            if req_name == "endpoints":
                return data.get("endpoints", [])
            elif req_name == "test_users":
                return data.get("users", [])
            elif req_name == "auth_type":
                return data.get("auth_patterns", {}).get("type")
            elif req_name == "resource_ownership":
                return data.get("resource_access", {})

        elif artifact_type == "docker_compose":
            if req_name == "api_name":
                services = data.get("api_services", [])
                return services[0] if services else None
            elif req_name == "base_url":
                return data.get("inferred_base_url")

        elif artifact_type == "test_outputs":
            if req_name == "endpoints":
                return data.get("endpoints_tested", [])
            elif req_name == "auth_type":
                return data.get("auth_observed", {}).get("type")

        elif artifact_type == "postman":
            if req_name == "api_name":
                return data.get("info", {}).get("name")
            elif req_name == "auth_type":
                auth = data.get("auth", {})
                return auth.get("type") if auth else None
            elif req_name == "endpoints":
                requests = data.get("requests", [])
                return [{"method": r["method"], "path": r["path"]} for r in requests]

        return None

    def fulfill_from_sources(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Try to fulfill requirements from registered sources.

        Returns a report of what was found and where.
        """
        fulfillment_report = {}

        for req_name, req in self.requirements.items():
            found_values = []

            # Check each source in priority order
            for source_type, path_hint in self.REQUIREMENT_SOURCES.get(req_name, []):
                for source_path, source in self.sources.items():
                    if source.artifact_type == source_type and source.parsed_data:
                        value = self.extract_requirement(req_name, source_type, source.parsed_data)
                        if value is not None:
                            found_values.append({
                                "value": value,
                                "source": source_path,
                                "source_type": source_type,
                                "confidence": self._calculate_confidence(source_type, req_name)
                            })

            if found_values:
                # Use the highest confidence value
                found_values.sort(key=lambda x: x["confidence"], reverse=True)
                best = found_values[0]

                req.value = best["value"]
                req.status = RequirementStatus.INFERRED
                req.source = best["source"]
                req.confidence = best["confidence"]

            fulfillment_report[req_name] = found_values

        return fulfillment_report

    def _calculate_confidence(self, source_type: str, req_name: str) -> float:
        """Calculate confidence score for a value from a source."""
        # Base confidence by source type (some sources are more reliable)
        source_confidence = {
            "openapi": 0.9,           # Specs are authoritative
            "postman_environments": 0.85,  # Often has real values
            "postman": 0.8,
            "fixtures": 0.8,
            "docker_compose": 0.7,
            "gateway_logs": 0.75,
            "test_outputs": 0.7,
            "env": 0.6,               # May have placeholders
            "ci_configs": 0.5,
            "logs": 0.5,
        }

        return source_confidence.get(source_type, 0.5)

    def get_status_report(self) -> Dict[str, Any]:
        """Get a report of all requirements and their status."""
        report = {
            "by_level": {},
            "by_status": {s.value: [] for s in RequirementStatus},
            "completion": {}
        }

        for level in SecurityLevel:
            level_reqs = [r for r in self.requirements.values() if r.level == level]
            fulfilled = [r for r in level_reqs if r.status != RequirementStatus.MISSING]
            required_fulfilled = [r for r in level_reqs if r.required and r.status != RequirementStatus.MISSING]
            required_total = [r for r in level_reqs if r.required]

            report["by_level"][level.name] = {
                "total": len(level_reqs),
                "fulfilled": len(fulfilled),
                "required_fulfilled": len(required_fulfilled),
                "required_total": len(required_total),
                "ready": len(required_fulfilled) == len(required_total),
                "requirements": [
                    {
                        "name": r.name,
                        "description": r.description,
                        "status": r.status.value,
                        "value": r.value if r.status != RequirementStatus.MISSING else None,
                        "source": r.source,
                        "confidence": r.confidence,
                        "required": r.required
                    }
                    for r in level_reqs
                ]
            }

        for req in self.requirements.values():
            report["by_status"][req.status.value].append(req.name)

        return report

    def get_missing_requirements(self, level: Optional[SecurityLevel] = None) -> List[Requirement]:
        """Get requirements that are still missing."""
        missing = []
        for req in self.requirements.values():
            if req.status == RequirementStatus.MISSING:
                if level is None or req.level == level:
                    missing.append(req)
        return missing

    def get_next_question(self) -> Optional[Dict[str, Any]]:
        """Get the next question to ask the user based on what's missing."""
        # Prioritize by level (lower levels first)
        for level in SecurityLevel:
            missing = self.get_missing_requirements(level)
            required_missing = [r for r in missing if r.required]

            if required_missing:
                req = required_missing[0]

                # Generate contextual question
                return {
                    "requirement": req.name,
                    "question": self._generate_question(req),
                    "context": self._generate_context(req),
                    "level": level.name
                }

        return None

    def _generate_question(self, req: Requirement) -> str:
        """Generate a natural question for a requirement."""
        questions = {
            "api_name": "What's the name of this API?",
            "base_url": "What's the base URL for testing? (e.g., https://staging-api.example.com)",
            "auth_type": "How does your API handle authentication? (OAuth2, API key, Basic auth, JWT bearer?)",
            "token_endpoint": "What's the OAuth2 token endpoint URL?",
            "client_id": "What client ID should I use for authentication?",
            "client_secret": "Do you have a client secret for the test environment?",
            "test_users": "What test users do you have? (I need at least 2 for BOLA testing)",
            "resource_ownership": "Which resources does each test user own?",
            "user_credentials": "What are the credentials (tokens or passwords) for each test user?",
            "roles": "What roles exist in your system? (admin, user, etc.)",
            "role_permissions": "What can each role do?",
        }

        return questions.get(req.name, f"Please provide: {req.description}")

    def _generate_context(self, req: Requirement) -> Optional[str]:
        """Generate context/explanation for why we need this."""
        context = {
            "base_url": "I'll use this to send test requests. Staging or dev is preferred.",
            "auth_type": "This determines how I'll authenticate test requests.",
            "test_users": "For BOLA testing, I need users with different access rights to test if user A can access user B's data.",
            "resource_ownership": "I need to know which resources each user owns so I can test cross-user access.",
            "roles": "For RBAC testing, I need to test if lower-privilege roles can perform higher-privilege actions.",
        }

        return context.get(req.name)

    def confirm_requirement(self, req_name: str, value: Any, source: str = "user"):
        """User confirms or provides a requirement value."""
        if req_name in self.requirements:
            self.requirements[req_name].value = value
            self.requirements[req_name].status = RequirementStatus.CONFIRMED
            self.requirements[req_name].source = source
            self.requirements[req_name].confidence = 1.0

    def highest_ready_level(self) -> SecurityLevel:
        """Get the highest security level we're ready for."""
        for level in reversed(list(SecurityLevel)):
            level_report = self.get_status_report()["by_level"][level.name]
            if level_report["ready"]:
                return level

        return SecurityLevel.BASIC

    def export_config_data(self) -> Dict[str, Any]:
        """Export fulfilled requirements as config data."""
        config = {
            "api": {},
            "auth": {},
            "identities": [],
            "scan": {}
        }

        # API info
        if self.requirements["api_name"].value:
            config["api"]["name"] = self.requirements["api_name"].value
        if self.requirements["base_url"].value:
            config["api"]["base_url"] = self.requirements["base_url"].value
        if self.requirements["spec_path"].value:
            config["api"]["spec_path"] = self.requirements["spec_path"].value

        # Auth config
        if self.requirements["auth_type"].value:
            config["auth"]["type"] = self.requirements["auth_type"].value
        if self.requirements["token_endpoint"].value:
            config["auth"]["token_endpoint"] = self.requirements["token_endpoint"].value

        # Identities for BOLA
        test_users = self.requirements["test_users"].value
        ownership = self.requirements["resource_ownership"].value
        credentials = self.requirements["user_credentials"].value

        if test_users and isinstance(test_users, list):
            for user in test_users:
                identity = {"name": user}

                if ownership and user in ownership:
                    identity["owns_resources"] = ownership[user]

                if credentials and user in credentials:
                    identity["credentials"] = credentials[user]

                config["identities"].append(identity)

        return config
