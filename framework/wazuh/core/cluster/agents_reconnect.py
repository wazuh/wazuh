import contextlib

from collections import defaultdict
from datetime import timedelta
from enum import Enum
from typing import overload
from xmlrpc.client import Boolean

from wazuh.core import utils
from wazuh.core.cluster import control, local_client
from wazuh.core.common import DECIMALS_DATE_FORMAT


class AgentsReconnectionPhases(str, Enum):
    NOT_STARTED = "Not started"
    CHECK_NODES_STABILITY = "Check nodes stability"
    CHECK_PREVIOUS_RECONNECTIONS = "Check previous reconnections"
    CHECK_AGENTS_BALANCE = "Check agents balance"
    RECONNECT_AGENTS = "Reconnect agents"
    BALANCE_SLEEPING = "Sleeping"
    HALT = "Halt"


class AgentsReconnect:
    """Class that encapsulates everything related to the agent reconnection algorithm."""

    def __init__(self, logger, nodes, blacklisted_nodes, nodes_stability_threshold) -> None:
        """Class constructor.

        Parameters
        ----------
        logger : Logger object
            Logger to use.
        nodes : list
            List of nodes in the environment.
        blacklisted_nodes : set
            Set of nodes that are not taken into account for the agents reconnection.
        nodes_stability_threshold : int
            Number of consecutive checks that must be successful to consider the environment stable.
        """
        # Logger
        self.logger = logger

        # Check nodes stability
        self.nodes = nodes
        self.blacklisted_nodes = blacklisted_nodes
        self.previous_nodes = set()
        self.nodes_stability_counter = 0
        self.nodes_stability_threshold = nodes_stability_threshold

        # Timestamps
        self.last_nodes_stability_check = 0

        # Check previous balance
        self.nodes_agents_dikt = {}

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
        self.nodes_stability_counter = 0

    async def check_nodes_stability(self) -> Boolean:
        """Function in charge of determining whether an environment is stable.

        To verify the stability, the function uses the consecutive verification
        of the number of nodes in the environment.

        Returns
        -------
        stability : bool
        """
        self.current_phase = AgentsReconnectionPhases.CHECK_NODES_STABILITY
        node_list = set(self.nodes.keys()).union({"master"}) - self.blacklisted_nodes

        if len(node_list) <= 1:
            self.logger.info("No nodes to check. Skipping...")
            self.reset_counter()
            self.previous_nodes = {}

            return False

        self.logger.debug(f"Current detected nodes: {node_list}.")

        if self.previous_nodes == node_list or len(self.previous_nodes) == 0:
            if self.nodes_stability_counter < self.nodes_stability_threshold:
                self.nodes_stability_counter += 1
            if self.previous_nodes == set():
                self.previous_nodes = node_list.copy()
        else:
            self.logger.info("Nodes changed, restarting nodes stability phase.")
            self.previous_nodes = node_list.copy()
            await self.reset_counter()

        self.last_nodes_stability_check = utils.get_utc_now()
        if self.nodes_stability_counter >= self.nodes_stability_threshold:
            self.logger.info(f"Cluster is ready {self.nodes_stability_counter}/{self.nodes_stability_threshold}. "
                             f"Nodes stability phase finished at "
                             f"{self.last_nodes_stability_check.strftime(DECIMALS_DATE_FORMAT)}.")
            return True

        self.logger.info(f"Nodes are not stable at this moment. "
                         f"Counter: {self.nodes_stability_counter}/{self.nodes_stability_threshold}.")
        return False

    async def check_previous_reconnections(self) -> Boolean:
        """Function in charge of checking whether the previous reconnections were successful. TODO: Implement.
        """
        self.current_phase = AgentsReconnectionPhases.CHECK_PREVIOUS_RECONNECTIONS
        if len(self.nodes_agents_dikt.keys()) == 0:  # TODO
            return True

        # TODO
        return False

    async def get_agents_balance(self) -> defaultdict:
        """TODO
        """
        def check_lastkeepalive(lastkeepalive):
            """TODO"""
            try:
                return lastkeepalive >= lka_threshold and lastkeepalive < datetime_upper_limit
            except TypeError:
                return False

        def difference_calculator(nodes_agents):
            """TODO"""
            try:
                mean = sum(len(lst) for lst in nodes_agents.values()) / len(nodes_agents.keys())
            except ZeroDivisionError:
                return True

            return any(len(node_agents) > mean for node_agents in nodes_agents.values())

        self.current_phase = AgentsReconnectionPhases.CHECK_AGENTS_BALANCE
        lc = local_client.LocalClient()
        # When one node has not agents this function does not return anything. MOD TODO
        # "global sql select count(*) from (select node_name as 'node_name',version as 'version',id as 'id',last_keepalive as 'lastKeepAlive',coalesce(ip,register_ip) as 'ip',name as 'name',connection_status as 'status' from agent where (node_name = 'worker2,worker1' collate nocase)  )"
        # current_connected_agents = await control.get_agents(lc, filter_node=self.previous_nodes)
        current_connected_agents = await control.get_agents(lc)

        agents_delay = 30
        datetime_upper_limit = utils.get_utc_now() + timedelta(seconds=agents_delay)  # Detect agent 000
        lka_threshold = utils.get_utc_now() - timedelta(seconds=agents_delay)

        nodes_agents_dikt = {}
        for node in self.previous_nodes:
            nodes_agents_dikt[node] = []

        for agent_registry in filter(lambda aregistry: check_lastkeepalive(aregistry['lastKeepAlive']),
                                     current_connected_agents['items']):
            if agent_registry['node_name'] not in self.blacklisted_nodes:
                nodes_agents_dikt[agent_registry['node_name']].append(agent_registry['id'])

        self.logger.info(f"Current connected agents: {nodes_agents_dikt}")
        self.logger.info(f"Checking current balance...")

        if nodes_agents_dikt == {}:
            self.logger.info("No agents connected. Skipping...")

            return nodes_agents_dikt

        if not difference_calculator(nodes_agents_dikt):
            self.logger.info(f"The cluster is balanced.")
            nodes_agents_dikt.clear()
        else:
            self.logger.info(f"The cluster is not balanced.")

        return nodes_agents_dikt

    async def balance_previous_conditions(self) -> Boolean:
        """TODO
        """
        await self.check_previous_reconnections()  # TODO
        self.nodes_agents_dikt = await self.get_agents_balance()  # TODO: Send to Selu
        return

    def get_current_phase(self) -> AgentsReconnectionPhases:
        """Return the current phase of the algorithm.

        Returns
        -------
        result : dict
        """
        return self.current_phase

    def get_nodes_stability_info(self) -> dict:
        """Return the information related to the phase nodes stability'.

        Returns
        -------
        result : dict
        """
        with contextlib.suppress(AttributeError):
            self.last_nodes_stability_check = self.last_nodes_stability_check.strftime(DECIMALS_DATE_FORMAT)

        return {
            "nodes_stability_counter": self.nodes_stability_counter,
            "nodes_stability_threshold": self.nodes_stability_threshold,
            "last_nodes_stability_check": self.last_nodes_stability_check,
            "last_register_nodes": str(list(self.previous_nodes))
        }

    def to_dict(self) -> dict:
        """Returns the model properties as a dict.

        Returns
        -------
        result : dict
        """
        NotImplementedError("Not implemented yet")
