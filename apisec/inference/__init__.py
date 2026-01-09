"""Inference module - Extract API information from artifacts."""

from .openapi import OpenAPIParser, parse_openapi
from .postman import PostmanParser, parse_postman, parse_postman_environment
from .logs import LogAnalyzer, parse_logs
from .env import EnvParser, parse_env, find_env_files
from .scanner import ArtifactScanner, scan_repo, get_artifact_summary
from .infer import infer_api_config, generate_apisec_config

# New parsers for intelligent requirement gathering
from .gateway_logs import (
    parse_gateway_logs,
    detect_gateway_log_format,
    parse_kong_logs,
    parse_aws_api_gateway_logs,
    parse_apigee_logs,
    parse_nginx_access_logs,
    parse_envoy_logs,
)
from .test_logs import (
    parse_test_logs,
    detect_test_log_format,
    parse_pytest_output,
    parse_jest_output,
    parse_newman_output,
    parse_karate_output,
    parse_rest_assured_output,
)
from .fixtures import (
    parse_fixtures,
    detect_fixtures_format,
    parse_json_fixtures,
    parse_yaml_fixtures,
    parse_sql_fixtures,
    scan_for_fixtures,
)
from .devops import (
    parse_devops_config,
    detect_ci_format,
    parse_docker_compose,
    parse_github_actions,
    parse_gitlab_ci,
    parse_jenkinsfile,
    parse_circleci,
    scan_for_devops_configs,
)
from .strategy import (
    RequirementStrategy,
    SecurityLevel,
    RequirementStatus,
    Requirement,
    ArtifactSource,
)

__all__ = [
    # OpenAPI
    "OpenAPIParser",
    "parse_openapi",
    # Postman
    "PostmanParser",
    "parse_postman",
    "parse_postman_environment",
    # Logs
    "LogAnalyzer",
    "parse_logs",
    # Environment
    "EnvParser",
    "parse_env",
    "find_env_files",
    # Scanner
    "ArtifactScanner",
    "scan_repo",
    "get_artifact_summary",
    # Inference
    "infer_api_config",
    "generate_apisec_config",
    # Gateway Logs
    "parse_gateway_logs",
    "detect_gateway_log_format",
    "parse_kong_logs",
    "parse_aws_api_gateway_logs",
    "parse_apigee_logs",
    "parse_nginx_access_logs",
    "parse_envoy_logs",
    # Test Logs
    "parse_test_logs",
    "detect_test_log_format",
    "parse_pytest_output",
    "parse_jest_output",
    "parse_newman_output",
    "parse_karate_output",
    "parse_rest_assured_output",
    # Fixtures
    "parse_fixtures",
    "detect_fixtures_format",
    "parse_json_fixtures",
    "parse_yaml_fixtures",
    "parse_sql_fixtures",
    "scan_for_fixtures",
    # DevOps
    "parse_devops_config",
    "detect_ci_format",
    "parse_docker_compose",
    "parse_github_actions",
    "parse_gitlab_ci",
    "parse_jenkinsfile",
    "parse_circleci",
    "scan_for_devops_configs",
    # Strategy
    "RequirementStrategy",
    "SecurityLevel",
    "RequirementStatus",
    "Requirement",
    "ArtifactSource",
]
