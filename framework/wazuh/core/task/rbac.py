from logging import Logger

from wazuh.core.commands_manager import CommandsManager
from wazuh.core.exception import WazuhError, WazuhIndexerError
from wazuh.core.rbac import RBACManager

# TODO: this target ID should be the server one when we implement their registration in the indexer
TARGET_ID = 'rbac'


async def get_rbac_info(logger: Logger, commands_manager: CommandsManager, rbac_manager: RBACManager):
    """Get RBAC information from the indexer.

    Parameters
    ----------
    logger : Logger
        Logging instance.
    commands_manager : CommandsManager
        Commands manager.
    rbac_manager : RBACManager
        RBAC manager.
    """
    while True:
        try:
            logger.info('Updating RBAC information')
            await rbac_manager.update()

            # Block until a RBAC command is received
            _ = commands_manager.get_commands(TARGET_ID)

        except (WazuhError, WazuhIndexerError) as e:
            logger.error(f'Failed updating RBAC information: {str(e)}', exc_info=False)
        except EOFError:
            logger.info('Cancelling RBAC task')
            return
