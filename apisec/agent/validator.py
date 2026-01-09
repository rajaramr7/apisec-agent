"""
Response validator to catch consultant-speak and enforce tool usage.

This module detects when the LLM describes processes instead of actually
executing tools. It enforces honest, action-oriented responses.

PROBLEM:
    User: "Can you validate my token?"
    BAD: "I will validate your token by checking the JWT structure..."
    GOOD: *calls validate_token* "Token valid. User: alice. Expires in 5 days."
"""

import re
from typing import List, Tuple


# Patterns that indicate consultant-speak (describing instead of doing)
# KEEP THIS LIST TIGHT - only clear bullshit patterns
# These should only trigger when user asked to DO something and agent describes instead
BULLSHIT_PATTERNS = [
    # Sequential process descriptions (clear bullshit when action requested)
    r"\bFirst,?\s+I (?:will|would)\b",
    r"\bNext,?\s+I (?:will|would)\b",
    r"\bThen,?\s+I (?:will|would)\b",
    r"\bFinally,?\s+I (?:will|would)\b",

    # Numbered steps (clear process explanation)
    r"\bStep \d+[:\s]\b",
    r"\d+\.\s*\*\*[A-Z][^*\n]+\*\*",  # Markdown numbered bold headers like "1. **Validation**"

    # Clear process description phrases
    r"\bThe process (?:is|involves|includes)\b",
    r"\bThis ensures that\b",
    r"\binvolved the following\b",
    r"\bthe following steps\b",

    # Document-style headers (dead giveaway)
    r"\bProcess Overview\b",
    r"\bConclusion\b",

    # Systematic/methodical jargon
    r"\bThis systematic approach\b",
    r"\bThis methodology\b",

    # Bullet list with process labels
    r"[-•]\s*\w+\s+Check:",
    r"[-•]\s*\w+\s+Extraction:",
    r"[-•]\s*\w+\s+Validation:",

    # "I will X by Y" when describing instead of doing
    r"\bI will\b.{1,30}\bby\b.{1,30}\b(?:checking|validating|parsing|analyzing)\b",

    # Breakdown/walkthrough (when user asked for action)
    r"\bHere'?s a (?:clear )?breakdown\b",
    r"\bLet me walk you through\b",
]

# Patterns that indicate actual action/results (not just describing)
ACTION_INDICATORS = [
    # Result markers
    r"✓",
    r"✗",
    r"\bFound \d+\b",
    r"\bExtracted \d+\b",
    r"\bParsed\b",
    r"\bValidated\b",
    r"\bScanned\b",
    r"\bCloned\b",

    # Error/success indicators
    r"\bError:\b",
    r"\bFailed:\b",
    r"\bResult:\b",
    r"\bSuccess\b",
    r"\bCompleted\b",

    # Actual findings
    r"\bHere'?s what I found\b",
    r"\bI found\b",
    r"\btoken (?:is )?valid\b",
    r"\btoken (?:is )?expired\b",
    r"\bendpoints?\b.{1,20}\bfound\b",

    # Data presentation
    r"\bIDs?:\s*\[",
    r"\bowners?:\s*\[",
    r"\bUser:\s*\w+",
    r"\bRoles?:\s*\w+",
    r"\bExpires?(?:s| in):\s*",
]

# Legitimate phrases when explaining limitations (not bullshit)
LEGITIMATE_LIMITATION_PHRASES = [
    "i can't",
    "not available",
    "not yet",
    "coming soon",
    "don't have",
    "unable to",
    "isn't available",
    "isn't implemented",
    "not implemented",
    "planned but",
    "not built yet",
    "doesn't exist",
    "no tool for",
]

# Question patterns (asking for input is OK)
QUESTION_PATTERNS = [
    r"\?$",
    r"which (?:one|path|folder|repo)",
    r"what (?:is|would you like)",
    r"where (?:is|should)",
    r"do you (?:have|want)",
    r"can you (?:provide|share|give)",
    r"please (?:provide|share|give)",
]

# Patterns indicating user is asking for INFO, not asking agent to DO something
# BE VERY INCLUSIVE - better to allow explanations than to block legitimate questions
INFO_REQUEST_PATTERNS = [
    # Capability questions
    "what can you",
    "what do you",
    "what are you",
    "what all",
    "whats your",
    "what's your",
    "who are you",
    "tell me about",
    "explain",
    "how do you",
    "how does",
    "how will you",
    "how would you",
    "capabilities",
    "features",
    "help",
    "what is your",
    "describe",
    "what tools",
    "list",
    "show me what",
    "what kind of",
    "how can you",
    "purpose",

    # Source/integration questions - VERY INCLUSIVE
    "what sources",
    "which sources",
    "where can you",
    "where do you",
    "from where",
    "integrate",  # catches "integrate to", "integrations", etc.
    "connector",  # catches "connectors"
    "gather",
    "pull from",
    "get data",
    "what can you access",
    "what can you read",
    "what do you support",
    "what formats",
    "supported",
    "work with",
    "compatible",
    "sources",

    # User describing their situation
    "i have",
    "we have",
    "my code",
    "my api",
    "my repo",
    "our code",
    "our api",

    # Security/trust questions
    "security",
    "privacy",
    "safe",
    "trust",
    "data handling",
    "where does my data",
    "what do you do with",
    "credentials",
    "secrets",
    "confidential",
    "encrypt",
    "compliance",
    "gdpr",
    "soc",

    # How it works questions
    "how does this work",
    "how do you work",
    "what happens when",
    "walk me through",
    "what's the process",
    "how will",
    "what will",
]


def is_information_request(user_message: str) -> bool:
    """Check if user is asking for info/help, not asking to DO something.

    When user asks "what can you do?" they WANT an explanation.
    We should NOT validate these as bullshit.
    """
    msg_lower = user_message.lower()
    return any(pattern in msg_lower for pattern in INFO_REQUEST_PATTERNS)


def count_matches(text: str, patterns: List[str]) -> int:
    """Count how many patterns match in the text."""
    count = 0
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            count += 1
    return count


def get_corrected_response(user_message: str) -> str:
    """Generate context-appropriate rejection message.

    Called when bullshit is detected. Returns a one-liner
    that offers to demonstrate based on what the user asked about.
    """
    msg_lower = user_message.lower()

    if "postman" in msg_lower:
        return "Give me a Postman collection file and I'll parse it."
    elif "insomnia" in msg_lower:
        return "Give me an Insomnia export and I'll parse it."
    elif "bruno" in msg_lower:
        return "Give me a Bruno collection and I'll parse it."
    elif "token" in msg_lower or "jwt" in msg_lower:
        return "Give me a token and I'll validate it."
    elif "bola" in msg_lower or "authorization" in msg_lower:
        return "Give me test fixtures with user ownership and I'll identify BOLA test cases."
    elif "github" in msg_lower:
        return "Give me a GitHub repo (owner/repo) and I'll clone and scan it."
    elif "repo" in msg_lower:
        return "Give me a repo URL or local path and I'll scan it."
    elif "scan" in msg_lower:
        return "Give me a folder path or repo URL and I'll scan it."
    elif "fixture" in msg_lower:
        return "Give me a fixtures directory and I'll extract IDs and ownership."
    elif "openapi" in msg_lower or "swagger" in msg_lower:
        return "Give me an OpenAPI spec and I'll parse it."
    elif "har" in msg_lower:
        return "Give me a HAR file and I'll extract the requests."
    elif "env" in msg_lower or "environment" in msg_lower:
        return "Give me an .env file path and I'll parse the credentials."
    elif "test" in msg_lower:
        return "Give me a test file and I'll extract the working payloads."
    elif "config" in msg_lower:
        return "Give me a repo or folder to scan and I'll generate a config."
    else:
        return "What would you like me to do? Give me a repo, folder, or file to work with."


def is_legitimate_limitation(text: str) -> bool:
    """Check if response is honestly explaining a limitation."""
    text_lower = text.lower()
    return any(phrase in text_lower for phrase in LEGITIMATE_LIMITATION_PHRASES)


def is_asking_question(text: str) -> bool:
    """Check if response is asking a clarifying question."""
    return any(
        re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        for pattern in QUESTION_PATTERNS
    )


def validate_response(
    response: str,
    tools_called: List[str],
    user_message: str = "",
) -> Tuple[bool, str]:
    """
    Validate response - but BE LENIENT. Only catch clear bullshit.

    The goal is to catch consultant-speak when user asked to DO something
    and agent described instead of doing. NOT to block helpful explanations.

    Args:
        response: The LLM's response text
        tools_called: List of tool names called during this turn
        user_message: The original user message (for context-aware rejection)

    Returns:
        Tuple of (is_valid, corrected_response)
        - is_valid: True if response is acceptable
        - corrected_response: Original or corrected response
    """
    # ALWAYS allow responses to information requests
    # This is the FIRST check - be very inclusive about what counts as info request
    if user_message and is_information_request(user_message):
        return True, response

    # ALWAYS allow if tools were called - agent did something
    if len(tools_called) > 0:
        return True, response

    # ALWAYS allow honest limitations
    if is_legitimate_limitation(response):
        return True, response

    # ALWAYS allow questions - agent is asking for clarification
    if is_asking_question(response):
        return True, response

    # ALWAYS allow short-to-medium responses (not bullshit, just concise)
    if len(response) < 300:
        return True, response

    # ALWAYS allow responses with action/result indicators
    action_score = count_matches(response, ACTION_INDICATORS)
    if action_score > 0:
        return True, response

    # Only NOW check for bullshit - require HIGH score (3+)
    bullshit_score = count_matches(response, BULLSHIT_PATTERNS)

    # Must have 3+ bullshit patterns to be rejected
    if bullshit_score >= 3:
        corrected = get_corrected_response(user_message)
        return False, corrected

    # Default: ALLOW the response
    return True, response


def strip_consultant_speak(response: str) -> str:
    """
    Remove common consultant-speak patterns from a response.

    This is a lighter-touch cleanup that can be applied to responses
    that pass validation but still have some fluff.
    """
    # Remove numbered bold headers with their descriptions (step-by-step format)
    # Matches: "1. **Title** - description" or "1. **Title**: description"
    response = re.sub(
        r'\d+\.\s*\*\*[^*]+\*\*\s*[-:][^\n]*\n?',
        '',
        response
    )

    # Remove "This ensures/means/allows" filler
    response = re.sub(
        r'This (?:ensures|means|allows|enables|guarantees)[^.]+\.\s*',
        '',
        response
    )

    # Remove "By doing/checking..." filler
    response = re.sub(
        r'By (?:doing|checking|validating|parsing|analyzing)[^.]+\.\s*',
        '',
        response
    )

    # Remove "The process involves" type phrases
    response = re.sub(
        r'The (?:process|approach|method) (?:is|involves|includes)[^.]+\.\s*',
        '',
        response
    )

    return response.strip()


def get_directness_score(response: str) -> dict:
    """
    Get a breakdown of directness metrics for debugging.

    Returns dict with scores and matched patterns.
    """
    bullshit_matches = []
    action_matches = []

    for pattern in BULLSHIT_PATTERNS:
        match = re.search(pattern, response, re.IGNORECASE | re.MULTILINE)
        if match:
            bullshit_matches.append({
                "pattern": pattern,
                "matched": match.group(0)
            })

    for pattern in ACTION_INDICATORS:
        match = re.search(pattern, response, re.IGNORECASE | re.MULTILINE)
        if match:
            action_matches.append({
                "pattern": pattern,
                "matched": match.group(0)
            })

    return {
        "bullshit_score": len(bullshit_matches),
        "action_score": len(action_matches),
        "bullshit_matches": bullshit_matches,
        "action_matches": action_matches,
        "is_limitation": is_legitimate_limitation(response),
        "is_question": is_asking_question(response),
    }
