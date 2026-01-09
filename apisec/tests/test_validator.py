"""Tests for the response validator (bullshit detector)."""

import pytest
from apisec.agent.validator import (
    validate_response,
    strip_consultant_speak,
    count_matches,
    is_legitimate_limitation,
    get_directness_score,
    BULLSHIT_PATTERNS,
    ACTION_INDICATORS,
)


class TestValidateResponse:
    """Test the main validate_response function."""

    def test_catches_consultant_speak(self):
        """Test that consultant-speak responses are caught."""
        bullshit_response = """I will validate your token by checking the JWT structure.
        This involves verifying the expiration claim and extracting user information.
        The process ensures that your token is properly formatted."""

        is_valid, response = validate_response(bullshit_response, tools_called=[])
        assert is_valid is False
        assert "describing" in response.lower() or "actually" in response.lower()

    def test_allows_real_results(self):
        """Test that responses with actual tool results pass."""
        good_response = """✓ Token validated

User: alice
Roles: admin
Expires: 2024-02-15 (5 days)"""

        is_valid, response = validate_response(good_response, tools_called=["validate_token"])
        assert is_valid is True
        assert response == good_response

    def test_allows_honest_limitations(self):
        """Test that honest limitation explanations pass."""
        limitation_response = """I can't do that yet.

Postman API integration isn't available.

What I can do:
✓ Scan local folders
✓ Parse OpenAPI specs"""

        is_valid, response = validate_response(limitation_response, tools_called=[])
        assert is_valid is True

    def test_catches_numbered_steps(self):
        """Test that numbered step-by-step process explanations are caught."""
        process_response = """Here's how I'll validate your token:

1. **Parse the JWT** - Extract the header and payload
2. **Check Expiration** - Verify the exp claim
3. **Extract User** - Get the sub claim"""

        is_valid, response = validate_response(process_response, tools_called=[])
        assert is_valid is False

    def test_catches_i_will_by_pattern(self):
        """Test that 'I will X by Y' patterns are caught."""
        response = "I will analyze your OpenAPI spec by parsing the endpoints and security schemes."
        is_valid, corrected = validate_response(response, tools_called=[])
        assert is_valid is False

    def test_catches_process_involves(self):
        """Test that 'process involves' phrases are caught."""
        response = """The process involves scanning your repository for API artifacts.
        This ensures we capture all relevant endpoints."""
        is_valid, corrected = validate_response(response, tools_called=[])
        assert is_valid is False

    def test_allows_questions(self):
        """Test that clarifying questions pass validation."""
        response = "Which folder contains your API project?"
        is_valid, corrected = validate_response(response, tools_called=[])
        assert is_valid is True

    def test_allows_short_responses(self):
        """Test that short direct responses pass."""
        response = "Give me the path and I'll scan it."
        is_valid, corrected = validate_response(response, tools_called=[])
        assert is_valid is True

    def test_allows_with_tool_calls(self):
        """Test that any response passes if tools were called."""
        # Even consultant-speak should pass if tools were actually called
        response = "I will now analyze the results by checking each endpoint."
        is_valid, corrected = validate_response(response, tools_called=["scan_repo"])
        assert is_valid is True

    def test_catches_sequential_steps(self):
        """Test that sequential 'First I will, Then I will' patterns are caught."""
        response = """First, I will scan your repository.
        Next, I will parse the OpenAPI spec.
        Finally, I will generate the configuration."""
        is_valid, corrected = validate_response(response, tools_called=[])
        assert is_valid is False


class TestStripConsultantSpeak:
    """Test the strip_consultant_speak cleanup function."""

    def test_removes_this_ensures(self):
        """Test removal of 'This ensures' filler."""
        text = "I found 5 endpoints. This ensures we have complete coverage. Moving on."
        result = strip_consultant_speak(text)
        assert "This ensures" not in result

    def test_removes_by_doing(self):
        """Test removal of 'By doing/checking' filler."""
        text = "Token is valid. By checking the signature we confirmed authenticity."
        result = strip_consultant_speak(text)
        assert "By checking" not in result

    def test_removes_numbered_headers(self):
        """Test removal of numbered bold headers."""
        text = """1. **Parse the JWT** - Extract header
Some content here
2. **Check Expiration** - Verify exp
More content"""
        result = strip_consultant_speak(text)
        assert "1. **Parse" not in result

    def test_preserves_actual_content(self):
        """Test that actual content is preserved."""
        text = "✓ Found 5 endpoints. User: alice."
        result = strip_consultant_speak(text)
        assert "✓ Found 5 endpoints" in result
        assert "User: alice" in result


class TestPatternMatching:
    """Test the pattern matching utilities."""

    def test_count_bullshit_patterns(self):
        """Test counting bullshit patterns."""
        text = "I will validate by checking. The process involves parsing. This ensures success."
        count = count_matches(text, BULLSHIT_PATTERNS)
        assert count >= 3

    def test_count_action_indicators(self):
        """Test counting action indicators."""
        text = "✓ Token valid. Found 5 endpoints. User: alice."
        count = count_matches(text, ACTION_INDICATORS)
        assert count >= 2

    def test_no_false_positives_on_clean_text(self):
        """Test that clean action text doesn't trigger bullshit patterns."""
        text = "✓ Scanned folder\n✓ Found OpenAPI spec\n✓ Parsed 12 endpoints"
        count = count_matches(text, BULLSHIT_PATTERNS)
        assert count == 0


class TestLegitimationDetection:
    """Test legitimate limitation detection."""

    def test_detects_cant(self):
        """Test detection of 'can't' limitations."""
        assert is_legitimate_limitation("I can't access that API.")

    def test_detects_not_available(self):
        """Test detection of 'not available' limitations."""
        assert is_legitimate_limitation("Kong connector is not available yet.")

    def test_detects_not_implemented(self):
        """Test detection of 'not implemented' limitations."""
        assert is_legitimate_limitation("This feature isn't implemented.")

    def test_doesnt_match_normal_text(self):
        """Test that normal text doesn't trigger limitation detection."""
        assert not is_legitimate_limitation("I found 5 endpoints.")


class TestDirectnessScore:
    """Test the directness scoring for debugging."""

    def test_scores_consultant_speak(self):
        """Test that consultant speak gets high bullshit score."""
        text = """I will validate your token by checking the JWT structure.
        This involves verifying the expiration claim.
        The process ensures proper validation."""

        score = get_directness_score(text)
        assert score["bullshit_score"] >= 3
        assert score["action_score"] == 0

    def test_scores_action_text(self):
        """Test that action text gets high action score."""
        text = "✓ Token valid. Found user: alice. Expires in 5 days."

        score = get_directness_score(text)
        assert score["action_score"] >= 2
        assert score["bullshit_score"] <= 1


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_response(self):
        """Test handling of empty response."""
        is_valid, response = validate_response("", tools_called=[])
        assert is_valid is True  # Short responses pass

    def test_very_long_consultant_speak(self):
        """Test detection in long responses."""
        response = """I will start by scanning your repository for API artifacts.
        This involves checking for OpenAPI specs, Postman collections, and environment files.
        The process ensures we capture all relevant configuration.

        Next, I will parse each discovered file.
        This involves extracting endpoints, authentication schemes, and request bodies.
        The approach ensures comprehensive coverage.

        Finally, I will generate the configuration.
        This involves compiling all extracted data into a YAML file.
        The result ensures your API is ready for security testing."""

        is_valid, corrected = validate_response(response, tools_called=[])
        assert is_valid is False

    def test_mixed_content(self):
        """Test response with both action and consultant speak."""
        # This has both patterns - should pass because of action indicators
        response = """✓ Found 5 endpoints

I will now analyze each endpoint by checking the security configuration.
This ensures we identify potential vulnerabilities."""

        is_valid, corrected = validate_response(response, tools_called=[])
        # With high action score, might pass despite some bullshit
        # This tests the balance between the two
        assert is_valid is True or "describing" in corrected.lower()

    def test_question_with_explanation(self):
        """Test that questions with explanations pass."""
        response = """Which environment do you want to use?

- Development (local testing)
- Staging (integration testing)
- Production (careful!)"""

        is_valid, corrected = validate_response(response, tools_called=[])
        assert is_valid is True
