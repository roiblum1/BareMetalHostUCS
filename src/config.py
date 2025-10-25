import logging

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)

# Create separate loggers for different components
logger = logging.getLogger(__name__)
bmh_logger = logging.getLogger('bmh_generator')
ucs_logger = logging.getLogger('ucs_client')
operator_logger = logging.getLogger('k8s_operator')
buffer_logger = logging.getLogger('bmh_buffer')

# Global configuration
MAX_AVAILABLE_SERVERS = 20  # Maximum number of servers that can be available (not in cluster)
BUFFER_CHECK_INTERVAL = 30  # Seconds between buffer checks