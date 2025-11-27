"""
Central configuration module for BareMetalHost Generator Operator.

This module provides ONLY:
- Centralized logging configuration
- Buffer management constants

All vendor-specific logic (BMC credentials, address formats) is in yaml_generators.py.
Management system credentials are read directly in unified_server_client.py.
"""

import logging
import os


# ============================================================================
# Logging Configuration
# ============================================================================

def get_log_level() -> int:
    """Get log level from environment variable or default to INFO."""
    log_level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    return log_levels.get(log_level_str, logging.INFO)


def setup_logging():
    """Configure logging for the entire application."""
    logging.basicConfig(
        level=get_log_level(),
        format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )


# Initialize logging on module import
setup_logging()

# Create specialized loggers and set their levels
bmh_logger = logging.getLogger('bmh_generator')
bmh_logger.setLevel(get_log_level())

ucs_logger = logging.getLogger('ucs_client')
ucs_logger.setLevel(get_log_level())

operator_logger = logging.getLogger('k8s_operator')
operator_logger.setLevel(get_log_level())

buffer_logger = logging.getLogger('bmh_buffer')
buffer_logger.setLevel(get_log_level())


# ============================================================================
# Buffer Management Configuration
# ============================================================================

# Maximum number of available (non-provisioned) BareMetalHosts allowed
MAX_AVAILABLE_SERVERS = int(os.getenv('MAX_AVAILABLE_SERVERS', '20'))

# Interval in seconds between buffer checks
BUFFER_CHECK_INTERVAL = int(os.getenv('BUFFER_CHECK_INTERVAL', '30'))
