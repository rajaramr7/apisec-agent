"""
Upload flow handler for APIsec platform integration.

Manages the conversation flow after config generation:
1. Offer to upload
2. Collect API token
3. Validate and upload
4. Show success/failure
"""

from typing import Dict, Optional, Tuple
from apisec.connectors.apisec_platform import APIsecPlatformConnector


class UploadFlow:
    """Handles the upload-to-APIsec conversation flow."""

    def __init__(self):
        """Initialize upload flow."""
        self.connector = APIsecPlatformConnector()
        self.api_token = None
        self.tenant_name = None

    def get_upload_prompt(self, config_summary: Dict) -> str:
        """Generate the upload offer message.

        Args:
            config_summary: Dict with endpoint_count, payload_count, etc.

        Returns:
            Formatted prompt asking user to upload
        """
        endpoints = config_summary.get("endpoint_count", 0)
        payloads = config_summary.get("payload_count", 0)
        tokens = config_summary.get("token_count", 0)
        bola_users = config_summary.get("bola_user_count", 0)
        api_name = config_summary.get("api_name", "your-api")
        config_path = config_summary.get("config_path", ".apisec/config.yaml")

        return f"""✓ Config ready! I found:
  • {endpoints} endpoints
  • {payloads} working payloads
  • {tokens} valid tokens
  • BOLA test cases for {bola_users} users

Config saved to: {config_path}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Want me to upload this to APIsec so you can start security scanning?

This will:
  • Create "{api_name}" in your APIsec tenant
  • Configure all {endpoints} endpoints for testing
  • Set up authentication with your tokens
  • Enable BOLA vulnerability detection

You'll be able to run security scans immediately after upload.

Upload to APIsec? [Y/n]"""

    def get_token_prompt(self) -> str:
        """Get the token request prompt with instructions.

        Returns:
            Formatted prompt for API token
        """
        return """I need an APIsec API token to upload to your tenant.

To create one:
  1. Go to APIsec → Settings → API Tokens
     (https://app.apisec.ai/settings/tokens)

  2. Click "Create Token"

  3. Name it (e.g., "cli-agent")

  4. Copy the token

Paste your APIsec API token:"""

    def validate_token(self, token: str) -> Tuple[bool, str]:
        """Validate the provided API token.

        Args:
            token: APIsec API token

        Returns:
            Tuple of (success, message)
        """
        is_valid, tenant_name, error = self.connector.validate_token(token)

        if is_valid:
            self.api_token = token
            self.tenant_name = tenant_name
            return True, f"✓ Token valid. Connected to tenant: {tenant_name}"
        else:
            return False, f"✗ {error}"

    def upload(self, config: Dict, api_name: str, update_existing: bool = False) -> Tuple[bool, str]:
        """Upload config to APIsec platform.

        Args:
            config: API configuration dict
            api_name: Name for the API
            update_existing: Update if API already exists

        Returns:
            Tuple of (success, message)
        """
        if not self.api_token:
            return False, "✗ No API token. Please provide a token first."

        result = self.connector.upload_config(config, api_name, update_existing)

        if result.success:
            return True, f"""✓ Upload complete!

{api_name} is now in APIsec and ready for security scanning.

Next steps:
  • View in APIsec: {result.api_url}
  • Run security scan: {result.scan_url}

Or run from CLI:
  apisec scan {api_name}"""
        else:
            if "already exists" in result.error:
                return False, f"""✗ {result.error}

Do you want to update the existing config? [y/N]"""
            else:
                return False, f"✗ Upload failed: {result.error}"

    def get_skip_message(self, config_path: str, api_name: str) -> str:
        """Get message when user skips upload.

        Args:
            config_path: Path where config was saved
            api_name: Name of the API

        Returns:
            Message with manual upload instructions
        """
        return f"""No problem! Your config is saved locally.

When you're ready to upload:
  apisec upload {config_path}

Or upload manually through the APIsec dashboard:
  https://app.apisec.ai/apis/new"""
