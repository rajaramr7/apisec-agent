"""
Validate JWT tokens before using them.

Why this matters:
Expired tokens = 401 errors = wasted testing time.
We MUST validate tokens before using them in security tests.
"""

import time
import json
import base64
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class TokenValidation:
    """Result of token validation."""
    valid: bool
    expired: bool = False
    user: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    expires_in_seconds: Optional[int] = None
    expired_ago_seconds: Optional[int] = None
    issued_at: Optional[int] = None
    issuer: Optional[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.roles is None:
            self.roles = []


def decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT payload without verification.

    We just need to check expiry and extract claims, not verify signature.
    The actual API will verify the signature.

    Args:
        token: JWT token string

    Returns:
        Decoded payload dict, or None if invalid format
    """
    try:
        # JWT format: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            return None

        # Decode payload (second part)
        payload_b64 = parts[1]

        # Add padding if needed (base64url may not have padding)
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        # Decode base64url
        payload_json = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_json)

    except Exception:
        return None


def decode_jwt_header(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode JWT header to get algorithm and type.

    Args:
        token: JWT token string

    Returns:
        Decoded header dict, or None if invalid format
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64 = parts[0]
        padding = 4 - len(header_b64) % 4
        if padding != 4:
            header_b64 += "=" * padding

        header_json = base64.urlsafe_b64decode(header_b64)
        return json.loads(header_json)

    except Exception:
        return None


def validate_jwt_token(token: str) -> TokenValidation:
    """
    Validate a JWT token.

    Checks:
    1. Token is well-formed JWT
    2. Token is not expired
    3. Extracts user and roles

    Args:
        token: JWT token to validate

    Returns:
        TokenValidation with status and extracted info
    """
    # Handle empty or invalid input
    if not token or not isinstance(token, str):
        return TokenValidation(valid=False, error="Token is empty or invalid type")

    # Strip whitespace
    token = token.strip()

    # Remove "Bearer " prefix if present
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    # Check for obviously invalid tokens
    if len(token) < 10:
        return TokenValidation(valid=False, error="Token too short to be valid JWT")

    # Decode payload
    payload = decode_jwt_payload(token)

    if payload is None:
        return TokenValidation(valid=False, error="Invalid JWT format")

    # Extract common claims
    now = time.time()

    # Expiration check
    exp = payload.get("exp")
    iat = payload.get("iat")

    # Extract user identifier (try common claim names)
    user = (
        payload.get("sub") or
        payload.get("user") or
        payload.get("username") or
        payload.get("user_id") or
        payload.get("userId") or
        payload.get("email") or
        payload.get("name")
    )

    # Extract roles (try common claim names)
    roles = (
        payload.get("roles") or
        payload.get("role") or
        payload.get("permissions") or
        payload.get("groups") or
        payload.get("scope", "").split() or
        []
    )

    # Normalize roles to list
    if isinstance(roles, str):
        roles = [roles]
    elif not isinstance(roles, list):
        roles = []

    # Extract issuer
    issuer = payload.get("iss")

    # No expiration claim
    if exp is None:
        return TokenValidation(
            valid=True,
            expired=False,
            user=str(user) if user else None,
            roles=roles,
            issuer=issuer,
            issued_at=iat,
            error="No expiration claim (token may be valid indefinitely)"
        )

    # Check if expired
    if exp < now:
        expired_ago = int(now - exp)
        return TokenValidation(
            valid=False,
            expired=True,
            user=str(user) if user else None,
            roles=roles,
            expired_ago_seconds=expired_ago,
            issuer=issuer,
            issued_at=iat,
            error=f"Token expired {format_duration(expired_ago)} ago"
        )

    # Token is valid
    expires_in = int(exp - now)
    return TokenValidation(
        valid=True,
        expired=False,
        user=str(user) if user else None,
        roles=roles,
        expires_in_seconds=expires_in,
        issuer=issuer,
        issued_at=iat
    )


def format_duration(seconds: int) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 0:
        return "in the future"
    if seconds < 60:
        return f"{seconds} seconds"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    else:
        days = seconds // 86400
        return f"{days} day{'s' if days != 1 else ''}"


def format_token_validation(result: TokenValidation) -> str:
    """
    Format validation result for display.

    Args:
        result: TokenValidation result

    Returns:
        Formatted string (e.g., "Valid (user: john, roles: admin, expires in: 6 days)")
    """
    if result.valid:
        parts = []

        if result.user:
            parts.append(f"user: {result.user}")

        if result.roles:
            roles_str = ", ".join(result.roles[:3])
            if len(result.roles) > 3:
                roles_str += f" +{len(result.roles) - 3} more"
            parts.append(f"roles: {roles_str}")

        if result.expires_in_seconds:
            parts.append(f"expires in: {format_duration(result.expires_in_seconds)}")

        details = ", ".join(parts) if parts else "valid"
        return f"Valid ({details})"
    else:
        if result.expired:
            return f"EXPIRED {format_duration(result.expired_ago_seconds)} ago (user: {result.user})"
        else:
            return f"Invalid: {result.error}"


def validate_multiple_tokens(tokens: Dict[str, str]) -> Dict[str, TokenValidation]:
    """
    Validate multiple tokens at once.

    Args:
        tokens: Dictionary of token_name -> token_value

    Returns:
        Dictionary of token_name -> TokenValidation
    """
    results = {}
    for name, token in tokens.items():
        results[name] = validate_jwt_token(token)
    return results


def get_expired_tokens(tokens: Dict[str, str]) -> List[str]:
    """
    Get list of expired token names.

    Args:
        tokens: Dictionary of token_name -> token_value

    Returns:
        List of token names that are expired
    """
    expired = []
    for name, token in tokens.items():
        validation = validate_jwt_token(token)
        if validation.expired:
            expired.append(name)
    return expired


def get_valid_tokens(tokens: Dict[str, str]) -> List[str]:
    """
    Get list of valid (non-expired) token names.

    Args:
        tokens: Dictionary of token_name -> token_value

    Returns:
        List of token names that are valid
    """
    valid = []
    for name, token in tokens.items():
        validation = validate_jwt_token(token)
        if validation.valid:
            valid.append(name)
    return valid


def format_token_validation_summary(validations: Dict[str, TokenValidation]) -> str:
    """
    Format multiple token validations for display.

    Args:
        validations: Dictionary of token_name -> TokenValidation

    Returns:
        Formatted summary string
    """
    lines = []

    valid_count = sum(1 for v in validations.values() if v.valid)
    expired_count = sum(1 for v in validations.values() if v.expired)
    invalid_count = len(validations) - valid_count - expired_count

    lines.append(f"Token validation summary: {valid_count} valid, {expired_count} expired, {invalid_count} invalid\n")

    for name, result in validations.items():
        if result.valid:
            status = "+"
        elif result.expired:
            status = "!"
        else:
            status = "x"

        formatted = format_token_validation(result)
        lines.append(f"  {status} {name}: {formatted}")

    return "\n".join(lines)


# Convenience function for agent tool
def check_tokens(tokens: Dict[str, str]) -> Dict[str, Any]:
    """
    Check multiple tokens and return structured result.

    This is the main entry point for the agent tool.

    Args:
        tokens: Dictionary of token_name -> token_value

    Returns:
        {
            "all_valid": True/False,
            "valid": ["token1", "token2"],
            "expired": ["token3"],
            "invalid": ["token4"],
            "details": {
                "token1": {"valid": True, "user": "...", "expires_in": "6 days"},
                ...
            },
            "summary": "Formatted summary string"
        }
    """
    validations = validate_multiple_tokens(tokens)

    valid = []
    expired = []
    invalid = []
    details = {}

    for name, result in validations.items():
        if result.valid:
            valid.append(name)
        elif result.expired:
            expired.append(name)
        else:
            invalid.append(name)

        details[name] = {
            "valid": result.valid,
            "expired": result.expired,
            "user": result.user,
            "roles": result.roles,
            "expires_in": format_duration(result.expires_in_seconds) if result.expires_in_seconds else None,
            "expired_ago": format_duration(result.expired_ago_seconds) if result.expired_ago_seconds else None,
            "error": result.error
        }

    return {
        "all_valid": len(expired) == 0 and len(invalid) == 0,
        "valid": valid,
        "expired": expired,
        "invalid": invalid,
        "details": details,
        "summary": format_token_validation_summary(validations)
    }
