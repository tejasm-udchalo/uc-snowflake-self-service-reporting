# Configuration management for Streamlit app
import os
from typing import Dict, Any

# Environment
ENV = os.getenv("STREAMLIT_ENV", "dev").lower()

# Base configuration
BASE_CONFIG: Dict[str, Any] = {
    "query_timeout_seconds": 180,
    "cache_ttl_seconds": 300,
    "max_query_size_bytes": 50000,
    "max_queries_per_hour": 50,
    "page_size_rows": 50,
    "export_formats": ["csv", "parquet"],
    "audit_enabled": True,
    "compression_threshold_bytes": 100_000_000,
    "secret_rotation_warning_days": 90,
}

# Environment-specific overrides
ENV_CONFIGS = {
    "dev": {
        "warehouse": "DEV_XS",
        "query_timeout_seconds": 300,
        "cache_ttl_seconds": 60,
        "rate_limit_per_hour": 100,
    },
    "prod": {
        "warehouse": "PROD_M",
        "query_timeout_seconds": 180,
        "cache_ttl_seconds": 300,
        "rate_limit_per_hour": 50,
    },
}

# Merge configs
CONFIG = {**BASE_CONFIG, **ENV_CONFIGS.get(ENV, {})}

# Export
__all__ = ["CONFIG", "ENV"]
