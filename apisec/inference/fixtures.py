"""
Parse test fixtures and seed data files.
These are goldmines for BOLA testing — they show exactly which users own which resources.
"""

import json
import re
import yaml
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class EntityData:
    """Data extracted for a single entity type."""
    name: str
    ids: List[str] = field(default_factory=list)
    ownership: Dict[str, List[str]] = field(default_factory=dict)
    sample_records: List[Dict] = field(default_factory=list)
    field_values: Dict[str, List[Any]] = field(default_factory=dict)


@dataclass
class FixtureData:
    """All data extracted from fixtures."""
    entities: Dict[str, EntityData] = field(default_factory=dict)
    users: List[Dict] = field(default_factory=list)
    relationships: Dict[str, str] = field(default_factory=dict)
    ownership_map: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    test_users: List[str] = field(default_factory=list)
    resources_by_type: Dict[str, List[Any]] = field(default_factory=dict)


def detect_fixtures_format(path: str) -> str:
    """
    Detect the format of a fixtures file.

    Returns: 'json' | 'yaml' | 'sql' | 'csv' | 'factory' | 'unknown'
    """
    file_path = Path(path)
    if not file_path.exists():
        return "unknown"

    suffix = file_path.suffix.lower()

    if suffix == ".json":
        return "json"
    elif suffix in [".yaml", ".yml"]:
        return "yaml"
    elif suffix == ".sql":
        return "sql"
    elif suffix == ".csv":
        return "csv"
    elif suffix == ".py":
        # Check if it's a factory file
        content = file_path.read_text(encoding='utf-8')
        if "factory" in content.lower() or "Factory" in content:
            return "factory"

    return "unknown"


def parse_json_fixtures(path: str) -> Dict[str, Any]:
    """
    Parse JSON fixture files.

    Common formats:
    1. Array of objects: [{"id": 1, "user_id": "user_a", ...}, ...]
    2. Keyed by table: {"users": [...], "orders": [...]}
    3. Nested with metadata: {"data": {"users": [...]}}

    Returns:
        {
            "entities": {
                "users": [{"id": "user_a", ...}],
                "orders": [{"id": 1001, "user_id": "user_a", ...}]
            },
            "ownership_map": {
                "user_a": {"orders": [1001, 1002], "profiles": ["user_a"]},
                "user_b": {"orders": [2001], "profiles": ["user_b"]}
            },
            "test_users": ["user_a", "user_b", "admin"],
            "resources_by_type": {
                "orders": [1001, 1002, 2001],
                "profiles": ["user_a", "user_b"]
            }
        }
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Fixtures file not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    data = json.loads(content)

    return _analyze_fixtures_data(data, file_path.stem)


def parse_yaml_fixtures(path: str) -> Dict[str, Any]:
    """
    Parse YAML fixture files.

    Returns: same structure as JSON parser
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Fixtures file not found: {path}")

    content = file_path.read_text(encoding='utf-8')
    data = yaml.safe_load(content)

    return _analyze_fixtures_data(data, file_path.stem)


def parse_sql_fixtures(path: str) -> Dict[str, Any]:
    """
    Parse SQL seed/fixture files.

    Looks for INSERT statements to extract data.

    Example:
    INSERT INTO users (id, username, role) VALUES ('user_a', 'User A', 'user');
    INSERT INTO orders (id, user_id, total) VALUES (1001, 'user_a', 99.99);

    Returns: same structure as JSON parser
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"SQL fixtures file not found: {path}")

    content = file_path.read_text(encoding='utf-8')

    entities = defaultdict(list)

    # Parse INSERT statements
    insert_pattern = re.compile(
        r"INSERT\s+INTO\s+[`\"]?(\w+)[`\"]?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)",
        re.IGNORECASE | re.MULTILINE
    )

    for match in insert_pattern.finditer(content):
        table = match.group(1).lower()
        columns = [c.strip().strip('`"') for c in match.group(2).split(',')]
        values_str = match.group(3)

        # Parse values (handle strings, numbers, NULL)
        values = _parse_sql_values(values_str)

        if len(columns) == len(values):
            record = dict(zip(columns, values))
            entities[table].append(record)

    # Handle multi-row INSERT
    multi_insert_pattern = re.compile(
        r"INSERT\s+INTO\s+[`\"]?(\w+)[`\"]?\s*\(([^)]+)\)\s*VALUES\s*((?:\([^)]+\),?\s*)+)",
        re.IGNORECASE | re.MULTILINE
    )

    for match in multi_insert_pattern.finditer(content):
        table = match.group(1).lower()
        columns = [c.strip().strip('`"') for c in match.group(2).split(',')]
        values_block = match.group(3)

        # Extract each value tuple
        value_tuples = re.findall(r'\(([^)]+)\)', values_block)
        for values_str in value_tuples:
            values = _parse_sql_values(values_str)
            if len(columns) == len(values):
                record = dict(zip(columns, values))
                entities[table].append(record)

    return _analyze_fixtures_data(dict(entities), Path(path).stem)


def parse_csv_fixtures(path: str) -> Dict[str, Any]:
    """
    Parse CSV fixture files.

    Returns: same structure as JSON parser
    """
    import csv

    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"CSV fixtures file not found: {path}")

    records = []
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert numeric strings to numbers
            processed = {}
            for key, value in row.items():
                if value.isdigit():
                    processed[key] = int(value)
                elif _is_float(value):
                    processed[key] = float(value)
                else:
                    processed[key] = value
            records.append(processed)

    # Use filename as table name
    table_name = file_path.stem.lower()
    if table_name.endswith("_fixtures") or table_name.endswith("_data"):
        table_name = table_name.rsplit("_", 1)[0]

    return _analyze_fixtures_data({table_name: records}, table_name)


def parse_factory_file(path: str) -> Dict[str, Any]:
    """
    Parse Python factory files (factory_boy, etc.).

    Extracts factory definitions to understand data models.

    Example:
    class UserFactory(factory.Factory):
        class Meta:
            model = User
        username = factory.Faker('user_name')
        role = 'user'

    Returns:
        {
            "factories": {
                "UserFactory": {
                    "model": "User",
                    "fields": {"username": "faker", "role": "user"}
                }
            },
            "relationships": [
                {"from": "OrderFactory", "to": "UserFactory", "field": "user"}
            ]
        }
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Factory file not found: {path}")

    content = file_path.read_text(encoding='utf-8')

    factories = {}
    relationships = []

    # Find factory class definitions
    class_pattern = re.compile(
        r'class\s+(\w+Factory)\s*\([^)]*(?:Factory|DjangoModelFactory)[^)]*\):',
        re.IGNORECASE
    )

    for match in class_pattern.finditer(content):
        factory_name = match.group(1)
        class_start = match.end()

        # Find the end of this class (next class or end of file)
        next_class = re.search(r'\nclass\s+\w+', content[class_start:])
        class_end = class_start + next_class.start() if next_class else len(content)
        class_body = content[class_start:class_end]

        # Extract model name
        model_match = re.search(r'model\s*=\s*(\w+)', class_body)
        model_name = model_match.group(1) if model_match else factory_name.replace('Factory', '')

        # Extract fields
        fields = {}
        field_pattern = re.compile(r'(\w+)\s*=\s*(.+)')
        for field_match in field_pattern.finditer(class_body):
            field_name = field_match.group(1)
            field_value = field_match.group(2).strip()

            # Skip Meta class and internal stuff
            if field_name in ['Meta', 'class', 'model']:
                continue

            # Detect SubFactory (relationships)
            if 'SubFactory' in field_value:
                sub_match = re.search(r'SubFactory\s*\(\s*(\w+)', field_value)
                if sub_match:
                    relationships.append({
                        "from": factory_name,
                        "to": sub_match.group(1),
                        "field": field_name
                    })
                    fields[field_name] = f"SubFactory({sub_match.group(1)})"
            elif 'Faker' in field_value or 'faker' in field_value:
                fields[field_name] = "faker"
            elif 'Sequence' in field_value:
                fields[field_name] = "sequence"
            elif 'LazyAttribute' in field_value:
                fields[field_name] = "lazy"
            else:
                # Try to extract literal value
                literal_match = re.search(r"['\"]([^'\"]+)['\"]", field_value)
                if literal_match:
                    fields[field_name] = literal_match.group(1)
                else:
                    fields[field_name] = field_value.split('#')[0].strip()

        factories[factory_name] = {
            "model": model_name,
            "fields": fields
        }

    return {
        "format": "factory",
        "factories": factories,
        "relationships": relationships,
        "entities": {},
        "ownership_map": {},
        "test_users": [],
        "resources_by_type": {}
    }


def _analyze_fixtures_data(data: Any, source_name: str) -> Dict[str, Any]:
    """
    Analyze fixtures data to extract ownership information.

    This is the core logic that identifies:
    - Which entities exist
    - Which users own which resources
    - What test users are available
    """
    entities = defaultdict(list)
    ownership_map = defaultdict(lambda: defaultdict(list))
    test_users = set()
    resources_by_type = defaultdict(list)

    # Normalize data structure
    if isinstance(data, list):
        # Array of objects - use source name as entity type
        entities[source_name] = data
    elif isinstance(data, dict):
        # Check for nested data
        if "data" in data and isinstance(data["data"], dict):
            data = data["data"]

        # Check if it's keyed by entity type
        for key, value in data.items():
            if isinstance(value, list):
                entities[key.lower()] = value
            elif isinstance(value, dict) and "records" in value:
                entities[key.lower()] = value["records"]

    # If no entities found, treat the whole thing as one entity type
    if not entities and isinstance(data, dict):
        entities[source_name] = [data]

    # Analyze each entity type
    user_id_fields = ['user_id', 'userId', 'owner_id', 'ownerId', 'created_by', 'createdBy', 'author_id']
    id_fields = ['id', 'ID', '_id', 'pk', 'uuid']

    for entity_type, records in entities.items():
        if not isinstance(records, list):
            continue

        for record in records:
            if not isinstance(record, dict):
                continue

            # Find the record's ID
            record_id = None
            for id_field in id_fields:
                if id_field in record:
                    record_id = record[id_field]
                    break

            if record_id:
                resources_by_type[entity_type].append(record_id)

            # Find user/owner reference
            owner_id = None
            for user_field in user_id_fields:
                if user_field in record:
                    owner_id = record[user_field]
                    break

            # If this is a users table, extract user IDs
            if entity_type in ['users', 'user', 'accounts', 'account']:
                user_id = record.get('id') or record.get('username') or record.get('email')
                if user_id:
                    test_users.add(str(user_id))

                    # Check for role information
                    role = record.get('role') or record.get('type') or record.get('user_type')
                    if role:
                        ownership_map[str(user_id)]['_role'] = role

            # Map ownership
            if owner_id and record_id:
                ownership_map[str(owner_id)][entity_type].append(record_id)

    # Convert defaultdicts to regular dicts
    ownership_map_dict = {}
    for user, resources in ownership_map.items():
        ownership_map_dict[user] = dict(resources)

    return {
        "format": "fixtures",
        "entities": dict(entities),
        "ownership_map": ownership_map_dict,
        "test_users": list(test_users),
        "resources_by_type": dict(resources_by_type)
    }


def _parse_sql_values(values_str: str) -> List[Any]:
    """Parse SQL VALUES clause into a list of values."""
    values = []
    current = ""
    in_string = False
    string_char = None

    for char in values_str:
        if char in ("'", '"') and not in_string:
            in_string = True
            string_char = char
        elif char == string_char and in_string:
            in_string = False
            string_char = None
        elif char == ',' and not in_string:
            values.append(_convert_sql_value(current.strip()))
            current = ""
            continue

        current += char

    if current.strip():
        values.append(_convert_sql_value(current.strip()))

    return values


def _convert_sql_value(value: str) -> Any:
    """Convert a SQL value string to appropriate Python type."""
    if value.upper() == 'NULL':
        return None

    # Remove quotes
    if (value.startswith("'") and value.endswith("'")) or \
       (value.startswith('"') and value.endswith('"')):
        return value[1:-1]

    # Try numeric conversion
    if value.isdigit():
        return int(value)

    if _is_float(value):
        return float(value)

    return value


def _is_float(value: str) -> bool:
    """Check if string is a valid float."""
    try:
        float(value)
        return '.' in value
    except ValueError:
        return False


def parse_fixtures(path: str) -> Dict[str, Any]:
    """
    Main entry point. Detects format and parses accordingly.

    Returns:
        {
            "format": "json",
            "entities": {...},
            "ownership_map": {...},
            "test_users": [...],
            "resources_by_type": {...}
        }
    """
    format_type = detect_fixtures_format(path)

    parsers = {
        "json": parse_json_fixtures,
        "yaml": parse_yaml_fixtures,
        "sql": parse_sql_fixtures,
        "csv": parse_csv_fixtures,
        "factory": parse_factory_file
    }

    if format_type in parsers:
        try:
            return parsers[format_type](path)
        except Exception as e:
            return {"format": format_type, "error": str(e)}
    else:
        return {"format": "unknown", "error": "Unrecognized fixtures format"}


def scan_for_fixtures(directory: str) -> List[str]:
    """
    Scan a directory for potential fixture files.

    Looks in common locations:
    - tests/fixtures/
    - fixtures/
    - testdata/
    - seed/
    - db/seeds/

    Returns: list of file paths
    """
    dir_path = Path(directory)
    fixtures = []

    # Common fixture directories
    fixture_dirs = [
        "fixtures", "testdata", "test_data", "seed", "seeds",
        "db/seeds", "db/fixtures", "tests/fixtures", "test/fixtures",
        "tests/data", "test/data", "sample_data"
    ]

    # Common fixture file patterns
    fixture_patterns = [
        "*fixtures*.json", "*fixtures*.yaml", "*fixtures*.yml",
        "*seed*.json", "*seed*.yaml", "*seed*.sql",
        "*testdata*.json", "*testdata*.yaml",
        "*.fixtures.json", "*.seed.sql"
    ]

    # Search in fixture directories
    for fixture_dir in fixture_dirs:
        full_dir = dir_path / fixture_dir
        if full_dir.exists():
            for ext in ["*.json", "*.yaml", "*.yml", "*.sql", "*.csv"]:
                fixtures.extend(str(f) for f in full_dir.glob(ext))

    # Search for fixture patterns in root and common dirs
    search_dirs = [dir_path, dir_path / "tests", dir_path / "test"]
    for search_dir in search_dirs:
        if search_dir.exists():
            for pattern in fixture_patterns:
                fixtures.extend(str(f) for f in search_dir.glob(pattern))

    # Look for factory files
    for py_file in dir_path.rglob("*factory*.py"):
        if "test" in str(py_file).lower() or "factories" in str(py_file).lower():
            fixtures.append(str(py_file))

    return list(set(fixtures))  # Remove duplicates


def format_fixture_summary(data: Dict[str, Any]) -> str:
    """
    Format fixture data for display.

    Args:
        data: Result from parse_fixtures()

    Returns:
        Formatted string for display
    """
    lines = []

    # Show entities and their IDs
    entities = data.get("entities", {})
    for entity_name, records in entities.items():
        if not records:
            continue

        lines.append(f"\n{entity_name}:")

        # Extract IDs from records
        ids = []
        for record in records[:10]:  # Limit to first 10
            if isinstance(record, dict):
                record_id = record.get("id") or record.get("_id") or record.get("pk")
                if record_id:
                    ids.append(str(record_id))

        if ids:
            ids_display = ids[:10]
            suffix = "..." if len(ids) > 10 else ""
            lines.append(f"  IDs found: {ids_display}{suffix}")

    # Show ownership mapping
    ownership_map = data.get("ownership_map", {})
    if ownership_map:
        lines.append(f"\nOwnership:")
        for owner, resources in list(ownership_map.items())[:5]:
            role = resources.pop("_role", None) if isinstance(resources, dict) else None
            role_str = f" (role: {role})" if role else ""
            lines.append(f"  {owner}{role_str} owns:")
            if isinstance(resources, dict):
                for resource_type, resource_ids in list(resources.items())[:3]:
                    ids_str = str(resource_ids[:5])
                    if len(resource_ids) > 5:
                        ids_str = ids_str[:-1] + ", ...]"
                    lines.append(f"    {resource_type}: {ids_str}")

    # Show test users
    test_users = data.get("test_users", [])
    if test_users:
        lines.append(f"\nTest users: {test_users[:10]}")

    # Show resources by type
    resources = data.get("resources_by_type", {})
    if resources:
        lines.append(f"\nResources by type:")
        for resource_type, resource_ids in list(resources.items())[:5]:
            count = len(resource_ids)
            sample = resource_ids[:5]
            lines.append(f"  {resource_type}: {count} items (sample: {sample})")

    return "\n".join(lines) if lines else "No fixture data found"


def parse_fixtures_directory(directory: str) -> FixtureData:
    """
    Parse all fixtures in a directory and return structured data.

    Args:
        directory: Path to fixtures directory

    Returns:
        FixtureData with all extracted information
    """
    result = FixtureData()
    fixture_files = scan_for_fixtures(directory)

    for file_path in fixture_files:
        try:
            data = parse_fixtures(file_path)

            # Merge entities
            for entity_name, records in data.get("entities", {}).items():
                if entity_name not in result.entities:
                    result.entities[entity_name] = EntityData(name=entity_name)

                entity = result.entities[entity_name]

                for record in records:
                    if isinstance(record, dict):
                        # Extract ID
                        record_id = record.get("id") or record.get("_id")
                        if record_id:
                            entity.ids.append(str(record_id))

                        # Store sample records
                        if len(entity.sample_records) < 3:
                            entity.sample_records.append(record)

            # Merge ownership
            for owner, resources in data.get("ownership_map", {}).items():
                if owner not in result.ownership_map:
                    result.ownership_map[owner] = {}
                for resource_type, ids in resources.items():
                    if resource_type not in result.ownership_map[owner]:
                        result.ownership_map[owner][resource_type] = []
                    result.ownership_map[owner][resource_type].extend(ids)

            # Merge test users
            result.test_users.extend(data.get("test_users", []))

            # Merge resources
            for resource_type, ids in data.get("resources_by_type", {}).items():
                if resource_type not in result.resources_by_type:
                    result.resources_by_type[resource_type] = []
                result.resources_by_type[resource_type].extend(ids)

        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")

    # Deduplicate
    result.test_users = list(set(result.test_users))

    return result
