"""
APIsec Platform connector for uploading API configs.

After the agent generates a config, this connector uploads it to the APIsec
platform where users can run security scans.
"""

import requests
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class UploadResult:
    """Result of uploading config to APIsec platform."""
    success: bool
    api_id: Optional[str] = None
    api_url: Optional[str] = None
    scan_url: Optional[str] = None
    error: Optional[str] = None
    tenant_name: Optional[str] = None


class APIsecPlatformConnector:
    """Connector for APIsec platform API.

    Handles authentication, config upload, and API management.
    """

    DEFAULT_BASE_URL = "https://api.apisec.ai"
    APP_BASE_URL = "https://app.apisec.ai"

    def __init__(self, api_token: str = None, base_url: str = None):
        """Initialize connector.

        Args:
            api_token: APIsec API token for authentication
            base_url: API base URL (defaults to production)
        """
        self.api_token = api_token
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.tenant_name = None
        self.tenant_id = None

    def _headers(self) -> Dict[str, str]:
        """Build request headers with auth."""
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
            "User-Agent": "apisec-agent/1.0"
        }

    def validate_token(self, token: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate API token and get tenant info.

        Args:
            token: APIsec API token to validate

        Returns:
            Tuple of (is_valid, tenant_name, error_message)
        """
        self.api_token = token

        try:
            response = requests.get(
                f"{self.base_url}/v1/me",
                headers=self._headers(),
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.tenant_name = data.get("tenant", {}).get("name", "Unknown")
                self.tenant_id = data.get("tenant", {}).get("id")
                return True, self.tenant_name, None
            elif response.status_code == 401:
                return False, None, "Invalid token. Please check and try again."
            elif response.status_code == 403:
                return False, None, "Token doesn't have permission to access this tenant."
            else:
                return False, None, f"API error: {response.status_code}"

        except requests.exceptions.Timeout:
            return False, None, "Connection timed out. Check your network."
        except requests.exceptions.ConnectionError:
            return False, None, "Could not connect to APIsec. Check your network."
        except Exception as e:
            return False, None, f"Error: {str(e)}"

    def check_api_exists(self, api_name: str) -> Tuple[bool, Optional[Dict]]:
        """Check if an API with this name already exists.

        Args:
            api_name: Name of the API to check

        Returns:
            Tuple of (exists, api_data)
        """
        try:
            response = requests.get(
                f"{self.base_url}/v1/apis",
                headers=self._headers(),
                params={"name": api_name},
                timeout=10
            )

            if response.status_code == 200:
                apis = response.json().get("apis", [])
                for api in apis:
                    if api.get("name", "").lower() == api_name.lower():
                        return True, api
            return False, None

        except Exception:
            return False, None

    def upload_config(self, config: Dict, api_name: str, update_existing: bool = False) -> UploadResult:
        """Upload API config to APIsec platform.

        Args:
            config: The API configuration dict
            api_name: Name for the API in APIsec
            update_existing: If True, update existing API with same name

        Returns:
            UploadResult with success status and URLs
        """
        if not self.api_token:
            return UploadResult(success=False, error="No API token configured")

        # Check if API already exists
        exists, existing_api = self.check_api_exists(api_name)

        if exists and not update_existing:
            return UploadResult(
                success=False,
                error=f"API '{api_name}' already exists. Use --update to overwrite."
            )

        try:
            if exists and update_existing:
                # Update existing API
                api_id = existing_api["id"]
                response = requests.put(
                    f"{self.base_url}/v1/apis/{api_id}",
                    headers=self._headers(),
                    json={"name": api_name, "config": config},
                    timeout=30
                )
            else:
                # Create new API
                response = requests.post(
                    f"{self.base_url}/v1/apis",
                    headers=self._headers(),
                    json={"name": api_name, "config": config},
                    timeout=30
                )

            if response.status_code in [200, 201]:
                data = response.json()
                api_id = data.get("id", data.get("api_id"))

                return UploadResult(
                    success=True,
                    api_id=api_id,
                    api_url=f"{self.APP_BASE_URL}/api/{api_id}",
                    scan_url=f"{self.APP_BASE_URL}/api/{api_id}/scan",
                    tenant_name=self.tenant_name
                )
            elif response.status_code == 401:
                return UploadResult(success=False, error="Token expired or invalid")
            elif response.status_code == 403:
                return UploadResult(success=False, error="Permission denied")
            elif response.status_code == 409:
                return UploadResult(success=False, error=f"API '{api_name}' already exists")
            else:
                error_detail = response.json().get("error", response.text)
                return UploadResult(success=False, error=f"Upload failed: {error_detail}")

        except requests.exceptions.Timeout:
            return UploadResult(success=False, error="Upload timed out")
        except requests.exceptions.ConnectionError:
            return UploadResult(success=False, error="Connection failed")
        except Exception as e:
            return UploadResult(success=False, error=str(e))

    def get_token_instructions(self) -> str:
        """Get instructions for creating an APIsec API token."""
        return """To create an APIsec API token:

1. Go to APIsec → Settings → API Tokens
   (https://app.apisec.ai/settings/tokens)

2. Click "Create Token"

3. Name it (e.g., "cli-agent")

4. Select permissions: APIs Read & Write

5. Click "Create" and copy the token

Paste your token here:"""


# Standalone functions for tool registration

def validate_apisec_token(token: str) -> Dict:
    """Validate APIsec platform API token.

    Args:
        token: APIsec API token

    Returns:
        Dict with valid, tenant, and error fields
    """
    connector = APIsecPlatformConnector()
    is_valid, tenant_name, error = connector.validate_token(token)

    return {
        "valid": is_valid,
        "tenant": tenant_name,
        "error": error
    }


def upload_to_apisec(config: Dict, api_name: str, token: str, update_existing: bool = False) -> Dict:
    """Upload API config to APIsec platform.

    Args:
        config: API configuration dict
        api_name: Name for the API
        token: APIsec API token
        update_existing: Update if API exists

    Returns:
        Dict with success, api_id, api_url, scan_url, tenant, error
    """
    connector = APIsecPlatformConnector(api_token=token)

    # Validate token first
    is_valid, tenant_name, error = connector.validate_token(token)
    if not is_valid:
        return {"success": False, "error": error}

    # Upload config
    result = connector.upload_config(config, api_name, update_existing)

    return {
        "success": result.success,
        "api_id": result.api_id,
        "api_url": result.api_url,
        "scan_url": result.scan_url,
        "tenant": result.tenant_name,
        "error": result.error
    }


def get_apisec_token_instructions() -> str:
    """Get instructions for creating APIsec API token."""
    connector = APIsecPlatformConnector()
    return connector.get_token_instructions()
