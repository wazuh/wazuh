import contextlib
from enum import Enum
from xmlrpc.client import Boolean

from wazuh.core import utils
from wazuh.core.common import DECIMALS_DATE_FORMAT


class AgentsReconnectionPhases(str, Enum):
    NOT_STARTED = "Not started"
    CHECK_WORKERS_STABILITY = "Check workers stability"
    CHECK_PREVIOUS_RECONNECTIONS = "Check previous reconnections"
    CHECK_AGENTS_BALANCE = "Check agents balance"
    RECONNECT_AGENTS = "Reconnect agents"
    BALANCE_SLEEPING = "Sleeping"
    HALT = "Halt"


class AgentsReconnect:
    """Class that encapsulates everything related to the agent reconnection algorithm."""

    def __init__(self, logger, nodes, blacklisted_nodes, workers_stability_threshold) -> None:
        """Class constructor.

        Parameters
        ----------
        logger : Logger object
            Logger to use.
        nodes : list
            List of nodes in the environment.
        blacklisted_nodes : set
            Set of nodes that are not taken into account for the agents reconnection.
        workers_stability_threshold : int
            Number of consecutive checks that must be successful to consider the environment stable.
        """
        # Logger
        self.logger = logger

        # Check workers stability
        self.nodes = nodes.keys()
        self.blacklisted_nodes = blacklisted_nodes
        self.previous_workers = set()
        self.workers_stability_counter = 0
        self.workers_stability_threshold = workers_stability_threshold

        # Timestamps
        self.last_workers_stability_check = 0

        # Check agents balance -> Provisional
        self.balance_counter = 0
        self.balance_threshold = 3

        # General
        self.current_phase = AgentsReconnectionPhases.NOT_STARTED

        # Provisional
        self.posbalance_sleep = 60

    async def reset_counter(self) -> None:
        """Reset all counters of the reconnection procedure."""
        self.balance_counter = 0
        self.workers_stability_counter = 0

    async def check_workers_stability(self) -> Boolean:
        """Function in charge of determining whether an environment is stable.

        To verify the stability, the function uses the consecutive verification
        of the number of workers in the environment.

        Returns
        -------
        stability : bool
        """
        self.current_phase = AgentsReconnectionPhases.CHECK_WORKERS_STABILITY
        if len(self.nodes) == 0:
            self.logger.info("No nodes to check. Skipping...")
            return False

        current_worker_list = set(self.nodes) - self.blacklisted_nodes
        self.logger.debug(f"Current detected workers: {current_worker_list}.")

        if self.previous_workers == current_worker_list or len(self.previous_workers) == 0:
            if self.workers_stability_counter < self.workers_stability_threshold:
                self.workers_stability_counter += 1
            if self.previous_workers == set():
                self.previous_workers = current_worker_list
        else:
            self.logger.info("Workers changed, restarting workers stability phase.")
            self.previous_workers = current_worker_list
            await self.reset_counter()

        self.last_workers_stability_check = utils.get_utc_now()
        if self.workers_stability_counter >= self.workers_stability_threshold:
            self.logger.info(f"Cluster is ready {self.workers_stability_counter}/{self.workers_stability_threshold}. "
                             f"Workers stability phase finished at "
                             f"{self.last_workers_stability_check.strftime(DECIMALS_DATE_FORMAT)}.")
            return True

        self.logger.info(f"Workers are not stable at this moment. "
                         f"Counter: {self.workers_stability_counter}/{self.workers_stability_threshold}.")
        return False

    def get_current_phase(self) -> AgentsReconnectionPhases:
        """Return the current phase of the algorithm.

        Returns
        -------
        result : dict
        """
        return self.current_phase

    def get_workers_stability_info(self) -> dict:
        """Return the information related to the phase 'Workers stability'.

        Returns
        -------
        result : dict
        """
        with contextlib.suppress(AttributeError):
            self.last_workers_stability_check = self.last_workers_stability_check.strftime(DECIMALS_DATE_FORMAT)

        return {
            "workers_stability_counter": self.workers_stability_counter,
            "workers_stability_threshold": self.workers_stability_threshold,
            "last_workers_stability_check": self.last_workers_stability_check,
            "last_register_workers": str(list(self.previous_workers))
        }

    def to_dict(self) -> dict:
        """Returns the model properties as a dict.

        Returns
        -------
        result : dict
        """
        NotImplementedError("Not implemented yet")
