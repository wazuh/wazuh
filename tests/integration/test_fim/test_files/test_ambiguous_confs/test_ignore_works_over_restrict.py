
import sys

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.modules.syscheck.configuration import SYSCHECK_DEBUG


# Set local internal options
local_internal_options = {SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS:
    local_internal_options += {AGENTD_WINDOWS_DEBUG: 2}