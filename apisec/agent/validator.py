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
BULLSHIT_PATTERNS = [
    # "I will/would/can X by Y" patterns
    r"\bI will\b.{1,50}\bby\b",
    r"\bI would\b.{1,50}\bby\b",
    r"\bI can\b.{1,50}\bby\b",
    r"\bI'll\b.{1,50}\bby\b",

    # Process description phrases
    r"\bThis involves\b",
    r"\bThe process (?:is|involves|includes)\b",
    r"\bHere'?s how I (?:will|would)\b",
    r"\bThis ensures\b",  # No "that" required
    r"\bThis means (?:that )?I\b",

    # "I will verb" patterns (common consultant-speak)
    r"\bI (?:will|would) implement\b",
    r"\bI (?:will|would) validate\b",
    r"\bI (?:will|would) parse\b",
    r"\bI (?:will|would) extract\b",
    r"\bI (?:will|would) cross-reference\b",
    r"\bI (?:will|would) check\b",
    r"\bI (?:will|would) analyze\b",
    r"\bI (?:will|would) process\b",
    r"\bI (?:will|would) scan\b",
    r"\bI (?:will|would) fetch\b",
    r"\bI (?:will|would) clone\b",

    # Explaining methodology
    r"\bLet me explain (?:how|what)\b",
    r"\bThe (?:approach|strategy|method) (?:is|involves)\b",
    r"\bBy (?:doing|checking|validating|parsing)\b",

    # Sequential process descriptions
    r"\bFirst,?\s+I (?:will|would)\b",
    r"\bNext,?\s+I (?:will|would)\b",
    r"\bThen,?\s+I (?:will|would)\b",
    r"\bFinally,?\s+I (?:will|would)\b",

    # Numbered steps (process explanation)
    r"\bStep \d+[:\s]\b",
    r"\d+\.\s*\*\*[A-Z][^*\n]+\*\*",  # Markdown numbered bold headers

    # Future tense action without doing
    r"\bI'm going to (?:validate|parse|check|analyze|scan)\b",
    r"\bI'll (?:start|begin) by\b",

    # "How it works" explanations (when asked "how did you do X")
    r"\binvolved the following\b",
    r"\bthe following steps\b",
    r"\bhere'?s (?:how|what) (?:it|the|this) works\b",
    r"\bthe validation involved\b",
    r"\bthe process worked\b",
    r"\bworked by\b.{1,30}\b(?:first|then|next)\b",

    # Past-tense process explanation (describing what "happened" theoretically)
    r"\d+\.\s*(?:Token|Format|Decoding|Extraction|Check|Validation)\b",
    r"\bI (?:checked|validated|parsed|extracted) (?:the|each|all)\b.{1,50}\bby\b",

    # Theoretical/hypothetical explanations
    r"\bwould (?:work|happen|be done) by\b",
    r"\btypically involves\b",
    r"\bgenerally works by\b",
    r"\bthe way (?:it|this) works\b",

    # Document-style headers (dead giveaway of process explanation)
    r"\bProcess Overview\b",
    r"\bOverview\b.*:",
    r"\bConclusion\b",
    r"\bSummary\b.*:",
    r"\bIn summary\b",

    # Systematic/methodical explanations
    r"\bThis systematic approach\b",
    r"\bThis approach ensures\b",
    r"\bThis methodology\b",
    r"\bsystematic (?:validation|check|process)\b",

    # Bullet list with "Check/Extraction/Validation" labels
    r"[-•]\s*\w+\s+Check:",
    r"[-•]\s*\w+\s+Extraction:",
    r"[-•]\s*\w+\s+Validation:",
    r"[-•]\s*(?:Success|Validity|Format|Token)\s+Check\b",

    # "The function does X" explanations
    r"\bThe function (?:checks|verifies|validates|extracts|parses)\b",
    r"\bThe tool (?:checks|verifies|validates|extracts|parses)\b",
    r"\bEach token was\b",
    r"\bwas submitted to\b",

    # Breakdown/walkthrough language
    r"\bHere'?s a (?:clear )?breakdown\b",
    r"\bLet me walk you through\b",
    r"\bHere'?s (?:how|what) happens\b",

    # "My approach" explanations
    r"\bmy approach (?:includes|involves|is)\b",
    r"\bBy combining (?:these|the) (?:methods|steps|approaches)\b",
    r"\bthe following steps\b",
    r"\bWould you like (?:more )?(?:elaboration|details)\b",
    r"\bmore elaboration on\b",
    r"\bany specific (?:step|area|part)\b",
    r"\bLet me (?:outline|describe|explain)\b",
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


def count_matches(text: str, patterns: List[str]) -> int:
    """Count how many patterns match in the text."""
    count = 0
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            count += 1
    return count


def get_corrected_response(user_message: str) -> str:
    """Generate context-appropriate rejection message.

    Instead of a hardcoded response, this returns a one-liner
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
    elif "repo" in msg_lower or "scan" in msg_lower or "github" in msg_lower:
        return "Give me a repo URL or local path and I'll scan it."
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
    else:
        return "Give me something specific and I'll run a tool on it."


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
    Validate that response shows action, not consultant-speak.

    Args:
        response: The LLM's response text
        tools_called: List of tool names called during this turn
        user_message: The original user message (for context-aware rejection)

    Returns:
        Tuple of (is_valid, corrected_response)
        - is_valid: True if response is honest/actionable
        - corrected_response: Original or corrected response
    """
    # If tools were called, response is valid (showing real results)
    if len(tools_called) > 0:
        return True, response

    # If honestly explaining limitations, that's fine
    if is_legitimate_limitation(response):
        return True, response

    # Score the response FIRST - bullshit check takes priority
    bullshit_score = count_matches(response, BULLSHIT_PATTERNS)
    action_score = count_matches(response, ACTION_INDICATORS)

    # STRICT: Any bullshit pattern when no tools were called = fail
    # Even if it ends with a question, consultant-speak with trailing "?" is still BS
    if bullshit_score >= 1:
        # Context-aware rejection - one line offering to demonstrate
        corrected = get_corrected_response(user_message)
        return False, corrected

    # Only allow pure questions (no bullshit patterns)
    if is_asking_question(response):
        return True, response

    # Very short responses with no bullshit patterns are OK (simple acknowledgments)
    if len(response) < 100 and bullshit_score == 0:
        return True, response

    # Long response with no tools called and no action indicators = suspicious
    if len(response) > 300 and action_score == 0:
        corrected = get_corrected_response(user_message)
        return False, corrected

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
