from connectors import connector
from connectors import connector_https
from connectors import connector_file
import logging.config

#============================ logging =========================================

logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
log = logging.getLogger("connector")
