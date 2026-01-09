"""
Parse DevOps configuration files.
Docker Compose and CI configs reveal: environment URLs, service dependencies,
environment variables, and secrets configuration.
"""

import json
import re
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional


def parse_docker_compose(path: str) -> Dict[str, Any]:
    """
    Parse docker-compose.yml to extract API configuration.

    Extracts:
    - Service names and ports
    - Environment variables (especially URLs and credentials)
    - Health check endpoints
    - Dependency relationships

    Returns:
        {
            "services": {
                "api": {
                    "image": "orders-api:latest",
                    "ports": ["8080:8080"],
                    "environment": {"DATABASE_URL": "...", "AUTH_URL": "..."},
                    "depends_on": ["db", "redis"],
                    "healthcheck": "/health"
                }
            },
            "api_services": ["api", "orders-service"],
            "environment_vars": {
                "BASE_URL": "http://api:8080",
                "AUTH_URL": "http://auth:8081"
            },
            "credentials_config": {
                "client_id_var": "CLIENT_ID",
                "client_secret_var": "CLIENT_SECRET"
            },
            "networks": ["api-network"],
            "inferred_base_url": "http://localhost:8080"
        }
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"docker-compose.yml not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    compose = yaml.safe_load(content)

    services_info = {}
    api_services = []
    all_env_vars = {}
    credentials_config = {}
    networks = []
    inferred_base_url = None

    # Common API service name patterns
    api_patterns = ['api', 'server', 'backend', 'service', 'app', 'web']

    services = compose.get('services', {})

    for service_name, service_config in services.items():
        if not isinstance(service_config, dict):
            continue

        service_info = {
            'image': service_config.get('image', ''),
            'ports': service_config.get('ports', []),
            'depends_on': service_config.get('depends_on', []),
            'environment': {},
            'healthcheck': None
        }

        # Extract environment variables
        env = service_config.get('environment', {})
        if isinstance(env, list):
            # Convert list format to dict
            env = {item.split('=')[0]: item.split('=')[1] if '=' in item else ''
                   for item in env}
        elif isinstance(env, dict):
            pass
        else:
            env = {}

        service_info['environment'] = env
        all_env_vars.update(env)

        # Extract health check
        healthcheck = service_config.get('healthcheck', {})
        if healthcheck:
            test = healthcheck.get('test', [])
            if isinstance(test, list):
                test = ' '.join(test)
            # Extract endpoint from health check
            endpoint_match = re.search(r'(https?://[^\s]+|/[^\s]+)', str(test))
            if endpoint_match:
                service_info['healthcheck'] = endpoint_match.group(1)

        services_info[service_name] = service_info

        # Identify API services
        service_lower = service_name.lower()
        if any(pattern in service_lower for pattern in api_patterns):
            api_services.append(service_name)

            # Try to infer base URL from ports
            for port in service_info['ports']:
                if isinstance(port, str) and ':' in port:
                    host_port = port.split(':')[0]
                    if not inferred_base_url:
                        inferred_base_url = f"http://localhost:{host_port}"

    # Identify credential-related environment variables
    credential_patterns = {
        'client_id': ['CLIENT_ID', 'OAUTH_CLIENT_ID', 'AUTH_CLIENT_ID'],
        'client_secret': ['CLIENT_SECRET', 'OAUTH_CLIENT_SECRET', 'AUTH_CLIENT_SECRET'],
        'api_key': ['API_KEY', 'AUTH_API_KEY', 'X_API_KEY'],
        'auth_url': ['AUTH_URL', 'OAUTH_URL', 'TOKEN_URL', 'AUTH_ENDPOINT'],
        'base_url': ['BASE_URL', 'API_URL', 'SERVICE_URL', 'BACKEND_URL']
    }

    for cred_type, patterns in credential_patterns.items():
        for pattern in patterns:
            for env_var in all_env_vars.keys():
                if pattern.lower() in env_var.lower():
                    credentials_config[f'{cred_type}_var'] = env_var
                    break

    # Extract networks
    networks = list(compose.get('networks', {}).keys())

    return {
        'format': 'docker-compose',
        'services': services_info,
        'api_services': api_services,
        'environment_vars': all_env_vars,
        'credentials_config': credentials_config,
        'networks': networks,
        'inferred_base_url': inferred_base_url
    }


def parse_github_actions(path: str) -> Dict[str, Any]:
    """
    Parse GitHub Actions workflow file.

    Extracts:
    - Test configurations
    - Environment secrets used
    - Service containers
    - API testing steps

    Returns:
        {
            "workflow_name": "CI",
            "triggers": ["push", "pull_request"],
            "jobs": {...},
            "secrets_used": ["API_KEY", "CLIENT_SECRET"],
            "env_vars": {...},
            "test_commands": ["pytest", "npm test"],
            "service_containers": {...}
        }
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"GitHub Actions workflow not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    workflow = yaml.safe_load(content)

    secrets_used = set()
    env_vars = {}
    test_commands = []
    service_containers = {}

    # Extract workflow name
    workflow_name = workflow.get('name', file_path.stem)

    # Extract triggers
    triggers = []
    on_config = workflow.get('on', {})
    if isinstance(on_config, str):
        triggers = [on_config]
    elif isinstance(on_config, list):
        triggers = on_config
    elif isinstance(on_config, dict):
        triggers = list(on_config.keys())

    # Extract global environment
    global_env = workflow.get('env', {})
    env_vars.update(global_env)

    # Find secrets references in entire content
    secret_pattern = re.compile(r'\$\{\{\s*secrets\.(\w+)\s*\}\}')
    for match in secret_pattern.finditer(content):
        secrets_used.add(match.group(1))

    # Parse jobs
    jobs_info = {}
    jobs = workflow.get('jobs', {})

    for job_name, job_config in jobs.items():
        if not isinstance(job_config, dict):
            continue

        job_info = {
            'runs_on': job_config.get('runs-on', ''),
            'steps': [],
            'services': {}
        }

        # Extract job-level env
        job_env = job_config.get('env', {})
        env_vars.update(job_env)

        # Extract service containers
        services = job_config.get('services', {})
        for service_name, service_config in services.items():
            if isinstance(service_config, dict):
                service_containers[service_name] = {
                    'image': service_config.get('image', ''),
                    'ports': service_config.get('ports', []),
                    'env': service_config.get('env', {})
                }
                job_info['services'][service_name] = service_containers[service_name]

        # Parse steps
        steps = job_config.get('steps', [])
        for step in steps:
            if not isinstance(step, dict):
                continue

            step_info = {
                'name': step.get('name', ''),
                'run': step.get('run', ''),
                'uses': step.get('uses', '')
            }
            job_info['steps'].append(step_info)

            # Extract test commands
            run_cmd = step.get('run', '')
            if run_cmd:
                if any(test_tool in run_cmd.lower() for test_tool in
                       ['pytest', 'jest', 'npm test', 'yarn test', 'mvn test',
                        'gradle test', 'newman', 'karate']):
                    test_commands.append(run_cmd.strip())

            # Extract step-level env
            step_env = step.get('env', {})
            env_vars.update(step_env)

        jobs_info[job_name] = job_info

    return {
        'format': 'github-actions',
        'workflow_name': workflow_name,
        'triggers': triggers,
        'jobs': jobs_info,
        'secrets_used': list(secrets_used),
        'env_vars': env_vars,
        'test_commands': test_commands,
        'service_containers': service_containers
    }


def parse_gitlab_ci(path: str) -> Dict[str, Any]:
    """
    Parse GitLab CI configuration file.

    Returns: similar structure to GitHub Actions parser
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"GitLab CI config not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    ci_config = yaml.safe_load(content)

    secrets_used = set()
    env_vars = {}
    test_commands = []
    service_containers = {}

    # Find variable references
    var_pattern = re.compile(r'\$(\w+)|\$\{(\w+)\}')
    for match in var_pattern.finditer(content):
        var_name = match.group(1) or match.group(2)
        secrets_used.add(var_name)

    # Extract global variables
    variables = ci_config.get('variables', {})
    env_vars.update(variables)

    # Extract global services
    services = ci_config.get('services', [])
    for service in services:
        if isinstance(service, str):
            service_containers[service.split(':')[0]] = {'image': service}
        elif isinstance(service, dict):
            name = service.get('name', '').split(':')[0]
            service_containers[name] = service

    # Parse jobs (keys not in reserved words)
    reserved_keys = {'image', 'services', 'variables', 'stages', 'before_script',
                     'after_script', 'cache', 'include', 'default'}

    jobs_info = {}
    for key, value in ci_config.items():
        if key not in reserved_keys and isinstance(value, dict):
            job_info = {
                'stage': value.get('stage', ''),
                'script': value.get('script', []),
                'services': value.get('services', [])
            }
            jobs_info[key] = job_info

            # Extract test commands from script
            for cmd in value.get('script', []):
                if any(test_tool in str(cmd).lower() for test_tool in
                       ['pytest', 'jest', 'npm test', 'yarn test', 'mvn test',
                        'gradle test', 'newman', 'karate']):
                    test_commands.append(str(cmd))

    return {
        'format': 'gitlab-ci',
        'stages': ci_config.get('stages', []),
        'jobs': jobs_info,
        'secrets_used': list(secrets_used),
        'env_vars': env_vars,
        'test_commands': test_commands,
        'service_containers': service_containers
    }


def parse_jenkinsfile(path: str) -> Dict[str, Any]:
    """
    Parse Jenkinsfile (declarative or scripted).

    Returns: similar structure to other CI parsers
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Jenkinsfile not found: {path}")

    content = file_path.read_text(encoding='utf-8')

    secrets_used = set()
    env_vars = {}
    test_commands = []

    # Find environment variables
    env_pattern = re.compile(r"env\.(\w+)|environment\s*\{([^}]+)\}")
    for match in env_pattern.finditer(content):
        if match.group(1):
            secrets_used.add(match.group(1))
        if match.group(2):
            env_block = match.group(2)
            var_assignments = re.findall(r"(\w+)\s*=\s*['\"]?([^'\"}\n]+)", env_block)
            for var_name, var_value in var_assignments:
                env_vars[var_name] = var_value.strip()

    # Find credentials references
    cred_pattern = re.compile(r"credentials\s*\(\s*['\"](\w+)['\"]")
    for match in cred_pattern.finditer(content):
        secrets_used.add(match.group(1))

    # Find test commands in sh/bat steps
    sh_pattern = re.compile(r"sh\s+['\"]([^'\"]+)['\"]|sh\s+'''([^']+)'''")
    for match in sh_pattern.finditer(content):
        cmd = match.group(1) or match.group(2)
        if any(test_tool in cmd.lower() for test_tool in
               ['pytest', 'jest', 'npm test', 'yarn test', 'mvn test',
                'gradle test', 'newman', 'karate']):
            test_commands.append(cmd.strip())

    # Extract stages
    stages = []
    stage_pattern = re.compile(r"stage\s*\(\s*['\"]([^'\"]+)['\"]")
    for match in stage_pattern.finditer(content):
        stages.append(match.group(1))

    return {
        'format': 'jenkinsfile',
        'stages': stages,
        'secrets_used': list(secrets_used),
        'env_vars': env_vars,
        'test_commands': test_commands,
        'service_containers': {}
    }


def parse_circleci(path: str) -> Dict[str, Any]:
    """
    Parse CircleCI configuration.

    Returns: similar structure to other CI parsers
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"CircleCI config not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    ci_config = yaml.safe_load(content)

    secrets_used = set()
    env_vars = {}
    test_commands = []
    service_containers = {}

    # Find environment variable references
    var_pattern = re.compile(r'\$(\w+)|\$\{(\w+)\}')
    for match in var_pattern.finditer(content):
        var_name = match.group(1) or match.group(2)
        secrets_used.add(var_name)

    # Parse jobs
    jobs_info = {}
    jobs = ci_config.get('jobs', {})

    for job_name, job_config in jobs.items():
        if not isinstance(job_config, dict):
            continue

        job_info = {
            'docker': job_config.get('docker', []),
            'steps': []
        }

        # Extract docker images as service containers
        for docker_config in job_config.get('docker', []):
            if isinstance(docker_config, dict):
                image = docker_config.get('image', '')
                name = image.split(':')[0].split('/')[-1]
                service_containers[name] = {
                    'image': image,
                    'environment': docker_config.get('environment', {})
                }

        # Parse steps
        for step in job_config.get('steps', []):
            if isinstance(step, dict):
                run_config = step.get('run', {})
                if isinstance(run_config, dict):
                    cmd = run_config.get('command', '')
                elif isinstance(run_config, str):
                    cmd = run_config
                else:
                    cmd = ''

                if cmd and any(test_tool in cmd.lower() for test_tool in
                               ['pytest', 'jest', 'npm test', 'yarn test', 'mvn test',
                                'gradle test', 'newman', 'karate']):
                    test_commands.append(cmd.strip())

        jobs_info[job_name] = job_info

    return {
        'format': 'circleci',
        'jobs': jobs_info,
        'secrets_used': list(secrets_used),
        'env_vars': env_vars,
        'test_commands': test_commands,
        'service_containers': service_containers
    }


def detect_ci_format(path: str) -> str:
    """
    Detect which CI system a config file belongs to.

    Returns: 'github-actions' | 'gitlab-ci' | 'jenkins' | 'circleci' | 'unknown'
    """
    file_path = Path(path)
    if not file_path.exists():
        return "unknown"

    name = file_path.name.lower()
    parent = file_path.parent.name.lower()

    # GitHub Actions
    if parent == 'workflows' or name.endswith('.yml') and '.github' in str(file_path):
        return "github-actions"

    # GitLab CI
    if name == '.gitlab-ci.yml' or name == 'gitlab-ci.yml':
        return "gitlab-ci"

    # Jenkins
    if name == 'jenkinsfile' or name.startswith('jenkinsfile'):
        return "jenkins"

    # CircleCI
    if name == 'config.yml' and parent == '.circleci':
        return "circleci"

    # Docker Compose
    if 'docker-compose' in name or name == 'compose.yml' or name == 'compose.yaml':
        return "docker-compose"

    return "unknown"


def parse_devops_config(path: str) -> Dict[str, Any]:
    """
    Main entry point. Detects format and parses accordingly.

    Returns:
        {
            "format": "github-actions",
            "secrets_used": [...],
            "env_vars": {...},
            "test_commands": [...],
            "service_containers": {...}
        }
    """
    format_type = detect_ci_format(path)

    parsers = {
        "github-actions": parse_github_actions,
        "gitlab-ci": parse_gitlab_ci,
        "jenkins": parse_jenkinsfile,
        "circleci": parse_circleci,
        "docker-compose": parse_docker_compose
    }

    if format_type in parsers:
        try:
            return parsers[format_type](path)
        except Exception as e:
            return {"format": format_type, "error": str(e)}
    else:
        return {"format": "unknown", "error": "Unrecognized CI/DevOps config format"}


def scan_for_devops_configs(directory: str) -> Dict[str, List[str]]:
    """
    Scan a directory for DevOps configuration files.

    Returns:
        {
            "docker_compose": ["docker-compose.yml"],
            "github_actions": [".github/workflows/ci.yml"],
            "gitlab_ci": [".gitlab-ci.yml"],
            "jenkins": ["Jenkinsfile"],
            "circleci": [".circleci/config.yml"]
        }
    """
    dir_path = Path(directory)
    configs = {
        "docker_compose": [],
        "github_actions": [],
        "gitlab_ci": [],
        "jenkins": [],
        "circleci": []
    }

    # Docker Compose
    for pattern in ["docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml"]:
        configs["docker_compose"].extend(str(f) for f in dir_path.glob(pattern))

    # GitHub Actions
    workflows_dir = dir_path / ".github" / "workflows"
    if workflows_dir.exists():
        configs["github_actions"].extend(str(f) for f in workflows_dir.glob("*.yml"))
        configs["github_actions"].extend(str(f) for f in workflows_dir.glob("*.yaml"))

    # GitLab CI
    gitlab_ci = dir_path / ".gitlab-ci.yml"
    if gitlab_ci.exists():
        configs["gitlab_ci"].append(str(gitlab_ci))

    # Jenkins
    for pattern in ["Jenkinsfile", "Jenkinsfile.*"]:
        configs["jenkins"].extend(str(f) for f in dir_path.glob(pattern))

    # CircleCI
    circleci_config = dir_path / ".circleci" / "config.yml"
    if circleci_config.exists():
        configs["circleci"].append(str(circleci_config))

    return configs
