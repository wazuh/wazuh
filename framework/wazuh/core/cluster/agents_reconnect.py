import contextlib
from enum import Enum
from xmlrpc.client import Boolean

from wazuh.core import utils
from wazuh.core.cluster.utils import setup_dynamic_logger
from wazuh.core.common import DECIMALS_DATE_FORMAT


class Agents_Reconnection_Phases(str, Enum):
    no_started = "No started"
    check_workers_stability = "Check workers stability"
    check_previous_reconnections = "Check previous reconnections"
    check_agents_balance = "Check agents balance"
    reconnect_agents = "Reconnect agents"
    balance_sleeping = "Sleeping"
    halt = "Halt"


class Agents_reconnect:
    """Class that encapsulates everything related to the agent reconnection algorithm."""

    def __init__(self, logger, nodes, blacklisted_nodes, workers_stability_threshold) -> None:
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
        self.current_phase = Agents_Reconnection_Phases.no_started

        # Provisional
        self.posbalance_sleep = 60

    async def reset_counter(self) -> None:
        """Resets all counters of the reconnection procedure.
        """
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
        logger = setup_dynamic_logger(
            self.logger, Agents_Reconnection_Phases.check_workers_stability.value)
        self.current_phase = Agents_Reconnection_Phases.check_workers_stability
        if len(self.nodes) == 0:
            logger.info("No nodes to check. Skipping...")
            return False

        current_worker_list = set(self.nodes) - self.blacklisted_nodes
        logger.debug(f"Current detected workers: {current_worker_list}.")

        if self.previous_workers == current_worker_list or len(self.previous_workers) == 0:
            if self.workers_stability_counter < self.workers_stability_threshold:
                self.workers_stability_counter += 1
            if self.previous_workers == set():
                self.previous_workers = current_worker_list
        else:
            logger.info("Workers changed, restarting workers stability phase.")
            self.previous_workers = current_worker_list
            await self.reset_counter()

        self.last_workers_stability_check = utils.get_utc_now()
        if self.workers_stability_counter >= self.workers_stability_threshold:
            logger.info(f"Cluster is ready {self.workers_stability_counter}/{self.workers_stability_threshold}. "
                        f"Workers stability phase finished at "
                        f"{self.last_workers_stability_check.strftime(DECIMALS_DATE_FORMAT)}.")
            return True

        logger.info(f"Workers are not stable at this moment. "
                    f"Counter: {self.workers_stability_counter}/{self.workers_stability_threshold}.")
        return False

    def get_current_phase(self) -> Agents_Reconnection_Phases:
        """Return the current phase of the algorithm.

        Returns
        -------
        result : dict
        """
        return self.current_phase

    def get_workers_stability_info(self) -> dict:
        """Returns the information related to the phase 'Workers stability'.

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
