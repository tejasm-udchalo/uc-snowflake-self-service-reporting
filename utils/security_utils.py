# Security utilities for SQL injection prevention and rate limiting
import hashlib
import streamlit as st
from datetime import datetime, timedelta
from typing import Tuple, Dict, List, Optional
import time


def check_rate_limit(
    username: str,
    max_queries_per_hour: int = 50,
    session_state: Optional[dict] = None
) -> Tuple[bool, str]:
    """
    Rate limiting to prevent query abuse.
    
    Args:
        username: Username to rate limit
        max_queries_per_hour: Maximum queries allowed per hour
        session_state: Streamlit session state (uses st.session_state if None)
    
    Returns:
        Tuple[bool, str]: (allowed, message)
    
    Example:
        >>> allowed, msg = check_rate_limit("user123", 50)
        >>> if not allowed:
        ...     st.error(msg)
        ...     st.stop()
    """
    if session_state is None:
        session_state = st.session_state
    
    key = f"rate_limit_{username}"
    
    if key not in session_state:
        session_state[key] = []
    
    now = datetime.now()
    cutoff = now - timedelta(hours=1)
    
    # Remove old queries outside 1-hour window
    session_state[key] = [t for t in session_state[key] if t > cutoff]
    
    if len(session_state[key]) >= max_queries_per_hour:
        remaining_queries = max_queries_per_hour - len(session_state[key])
        return (
            False,
            f"⚠️ Rate limit exceeded: {max_queries_per_hour} queries/hour. "
            f"Try again in {int((session_state[key][0] - cutoff).total_seconds() / 60)} minutes."
        )
    
    session_state[key].append(now)
    return True, "OK"


def validate_query_size(query: str, max_bytes: int = 50000) -> Tuple[bool, str]:
    """
    Validate query doesn't exceed size limit (DoS prevention).
    
    Args:
        query: SQL query string
        max_bytes: Maximum query size in bytes
    
    Returns:
        Tuple[bool, str]: (valid, message)
    """
    query_size = len(query.encode('utf-8'))
    
    if query_size > max_bytes:
        return False, f"Query too large: {query_size} bytes (max {max_bytes})"
    
    return True, "OK"


def validate_filter_value(
    operator: str,
    value: str,
    column_name: str
) -> Tuple[bool, str]:
    """
    Validate filter value for safety and correctness.
    
    Args:
        operator: Filter operator (=, LIKE, IN, etc.)
        value: Filter value
        column_name: Column name
    
    Returns:
        Tuple[bool, str]: (valid, message)
    """
    # Check for NULL/NOT NULL operators which don't need value
    if operator in ["IS NULL", "IS NOT NULL"]:
        return True, "OK"
    
    # Value required for other operators
    if not value.strip():
        return False, f"Value required for operator '{operator}'"
    
    # Validate IN operator has comma-separated values
    if operator == "IN":
        parts = [p.strip() for p in value.split(",") if p.strip()]
        if not parts:
            return False, "IN operator requires comma-separated values"
    
    # Prevent extremely long values (potential DoS)
    if len(value) > 1000:
        return False, "Filter value too long (max 1000 characters)"
    
    return True, "OK"


def get_query_hash(query: str) -> str:
    """
    Generate deterministic hash of query for caching.
    
    Args:
        query: SQL query string
    
    Returns:
        SHA256 hex digest of query
    
    Example:
        >>> hash1 = get_query_hash("SELECT * FROM table")
        >>> hash2 = get_query_hash("SELECT * FROM table")
        >>> hash1 == hash2
        True
    """
    return hashlib.sha256(query.encode('utf-8')).hexdigest()


def sanitize_column_name(name: str) -> str:
    """
    Basic sanitization of column names (Snowflake specific).
    Should be used with parameterized queries in production.
    
    Args:
        name: Column name
    
    Returns:
        Sanitized column name
    """
    # Only allow alphanumeric, underscore, quotes for Snowflake
    import re
    
    # Snowflake identifiers can contain: letters, numbers, underscore
    # or be quoted identifiers
    if '"' in name:
        # Already quoted
        return name
    
    # Check if valid unquoted identifier
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
        return name
    
    # Quote if contains special chars
    return f'"{name}"'


def build_safe_filter_sql(
    column: str,
    operator: str,
    value: str,
    logic: Optional[str] = None
) -> Optional[str]:
    """
    Build safe SQL filter clause.
    
    SECURITY NOTE: For production, this should use parameterized queries
    via Snowflake Snowpark DataFrame API instead of string building.
    This is a basic safety wrapper.
    
    Args:
        column: Column name
        operator: Comparison operator
        value: Filter value
        logic: AND/OR prefix
    
    Returns:
        SQL clause or None if invalid
    
    Example:
        >>> sql = build_safe_filter_sql("name", "LIKE", "john%")
        >>> sql
        "name LIKE 'john%'"
    """
    # Validate inputs
    valid, msg = validate_filter_value(operator, value, column)
    if not valid:
        return None
    
    # Sanitize column name
    safe_column = sanitize_column_name(column)
    
    # Build condition
    condition_sql = ""
    
    if operator in ["IS NULL", "IS NOT NULL"]:
        condition_sql = f"{safe_column} {operator}"
    
    elif operator == "IN":
        values = [v.strip() for v in value.split(",") if v.strip()]
        # Escape single quotes in each value
        escaped_values = [f"'{v.replace(chr(39), chr(39) + chr(39))}'" for v in values]
        condition_sql = f"{safe_column} IN ({', '.join(escaped_values)})"
    
    elif operator == "LIKE":
        # Add % automatically if not provided
        like_value = value.strip()
        if "%" not in like_value:
            like_value = f"%{like_value}%"
        # Escape single quotes
        escaped_value = like_value.replace(chr(39), chr(39) + chr(39))
        condition_sql = f"{safe_column} LIKE '{escaped_value}'"
    
    else:
        # Standard operators: =, >, <, >=, <=
        # Escape single quotes
        escaped_value = value.replace(chr(39), chr(39) + chr(39))
        condition_sql = f"{safe_column} {operator} '{escaped_value}'"
    
    # Add logic prefix
    if logic and logic.upper() in ["AND", "OR"]:
        condition_sql = f"{logic.upper()} {condition_sql}"
    
    return condition_sql


__all__ = [
    "check_rate_limit",
    "validate_query_size",
    "validate_filter_value",
    "get_query_hash",
    "sanitize_column_name",
    "build_safe_filter_sql",
]
