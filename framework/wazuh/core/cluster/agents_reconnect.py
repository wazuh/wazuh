import contextlib

from datetime import timedelta
from enum import Enum
from math import ceil

from wazuh.core import utils
from wazuh.core.agent import Agent
from wazuh.core.cluster import utils as cluster_utils
from wazuh.core.common import DECIMALS_DATE_FORMAT


class AgentsReconnectionPhases(str, Enum):
    NOT_STARTED = "Not started"
    CHECK_NODES_STABILITY = "Check nodes stability"
    CHECK_PREVIOUS_RECONNECTIONS = "Check previous reconnections"
    CHECK_AGENTS_BALANCE = "Check agents balance"
    RECONNECT_AGENTS = "Reconnect agents"
    BALANCE_SLEEPING = "Sleeping"
    NOT_ENOUGH_NODES = "Not enough nodes"
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
        self.previous_agents_nodes = {}
        self.lost_agents_percent = 0.1  # 10%
        self.same_agents_node_percent = 0.5  # 50%

        # Check agents balance -> Provisional
        self.balance_counter = 0
        self.balance_threshold = 3

        # Reconnection phase
        self.reconnection_timestamp = 0

        # General
        self.current_phase = AgentsReconnectionPhases.NOT_STARTED

        # Provisional
        self.posbalance_sleep = 60
        self.agents_connection_delay = 30

    async def reset_counter(self) -> None:
        """Reset all counters of the reconnection procedure."""
        self.balance_counter = 0
        self.nodes_stability_counter = 0

    async def check_nodes_stability(self) -> bool:
        """Function in charge of determining whether an environment is stable.

        To verify the stability, the function uses the consecutive verification
        of the number of nodes in the environment.

        Returns
        -------
        bool
            True if the environment is stable, False otherwise.
        """
        self.current_phase = AgentsReconnectionPhases.CHECK_NODES_STABILITY
        node_list = set(self.nodes.keys()).union({"master-node"}) - self.blacklisted_nodes

        if len(node_list) <= 1:
            self.reset_counter()
            self.previous_nodes = set()
            self.current_phase = AgentsReconnectionPhases.NOT_ENOUGH_NODES

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

    async def get_agents_in_nodes(self) -> dict:
        """Get all agents in the system flagged as active and connected to nodes to watch.

        Returns
        -------
        dict
            Dictionary with agents information.
        """
        return await cluster_utils.forward_function(
            func=Agent.get_agents_overview,
            f_kwargs={"filters": {"status": "active"},
                      "select": ["id", "node_name", "lastKeepAlive"],
                      "q": ",".join([f"node_name={node}" for node in self.previous_nodes])})

    async def check_previous_reconnections(self) -> bool:
        """Check the agents status after the previous reconnection.

        Returns
        -------
        bool
            True if the agents are connected and the tolerance criteria are met or no agent has been reconnected,
            False otherwise.
        """
        def check_lastkeepalive(lastkeepalive):
            """Check that the agent's last_keepalive is greater than the time saved in the previous reconnection.

            Parameters
            ----------
            lastkeepalive : datetime
                Agent's last keep alive.

            Returns
            -------
            bool
                True if the criteria for determining that an agent is connected are met. False otherwise.
            """
            try:
                return lastkeepalive > self.reconnection_timestamp + timedelta(seconds=self.agents_connection_delay)
            except TypeError:
                return False

        self.current_phase = AgentsReconnectionPhases.CHECK_PREVIOUS_RECONNECTIONS
        # If no agent has been balanced in the previous iteration return True
        if all(agents == [] for agents in self.previous_agents_nodes.values()):
            return True

        lost_agents_threshold = sum(len(lst) for lst in self.previous_agents_nodes.values()) * self.lost_agents_percent
        same_agents_node_threshold = sum(
            len(lst) for lst in self.previous_agents_nodes.values()) * self.same_agents_node_percent

        current_agents = await self.get_agents_in_nodes()
        lost_agents = []
        agents_still_previous_node = []

        for agent_info in current_agents['items']:
            if not check_lastkeepalive(agent_info['lastKeepAlive']):
                lost_agents.append(agent_info['id'])
                if len(lost_agents) >= lost_agents_threshold:
                    self.logger.info(f'Too many lost agents. Halting reconnection procedure.')
                    self.logger.debug(f'Lost agents: {lost_agents}.')
                    self.current_phase = AgentsReconnectionPhases.HALT
                    return False

            if agent_info['node_name'] not in self.blacklisted_nodes and \
                    agent_info['id'] in self.previous_agents_nodes[agent_info['node_name']]:
                agents_still_previous_node.append(agent_info['id'])
                if len(agents_still_previous_node) >= same_agents_node_threshold:
                    self.logger.info(f'Too many agents still in the previous node. Halting reconnection procedure.')
                    self.logger.debug(f'Agents still in the previous node: {agents_still_previous_node}.')
                    self.current_phase = AgentsReconnectionPhases.HALT
                    return False

        return True

    async def get_agents_balance(self) -> dict:
        """Function in charge of checking the balance of the agents.

        Returns
        -------
        dict
            Dictionary with the agents that are not balanced.
            The keys of the dictionary are the names of the nodes and the values are the agents.
        """
        def check_lastkeepalive(lastkeepalive) -> bool:
            """Check whether an agent is connected or not, by checking the
            last_keepalive of the agent vs. an established threshold.

            Parameters
            ----------
            lastkeepalive : datetime
                Agent last_keepalive.

            Returns
            -------
            bool
                True if the agent is connected, False otherwise.
            """
            try:
                # Detect agent 000
                datetime_upper_limit = utils.get_utc_now() + timedelta(seconds=self.agents_connection_delay)
                lka_threshold = utils.get_utc_now() - timedelta(seconds=self.agents_connection_delay)
                return lastkeepalive >= lka_threshold and lastkeepalive < datetime_upper_limit
            except TypeError:
                return False

        def difference_calculator(nodes_agents) -> dict:
            """Calculate the average number of agents per worker and get
            the difference between the number of agents each worker has.

            Parameters
            ----------
            nodes_agents : dict
                Dictionary whose keys are the names of the nodes and whose values are the agents connected to them.

            Returns
            -------
            dict
                Dictionary whose keys are the names of the nodes and the values of the agents that need reconnection.
            """
            try:
                mean = ceil(sum(len(lst) for lst in nodes_agents.values()) / len(nodes_agents.keys()))
            except ZeroDivisionError:
                return {}

            agents_nodes_exceeded = {}
            for node, agents in nodes_agents.items():
                with contextlib.suppress(IndexError):
                    agents_nodes_exceeded[node] = agents[int(mean):]

            return agents_nodes_exceeded

        self.current_phase = AgentsReconnectionPhases.CHECK_AGENTS_BALANCE
        current_connected_agents = await self.get_agents_in_nodes()

        nodes_agents_dikt = {}
        for node in self.previous_nodes:
            nodes_agents_dikt[node] = []

        for agent_registry in filter(lambda aregistry: check_lastkeepalive(aregistry['lastKeepAlive']),
                                     current_connected_agents['items']):
            if agent_registry['node_name'] not in self.blacklisted_nodes:
                nodes_agents_dikt[agent_registry['node_name']].append(agent_registry['id'])

        nodes_agents_dikt = difference_calculator(nodes_agents_dikt)
        if all(agents == [] for agents in nodes_agents_dikt.values()):
            self.logger.info('The agents connected to the cluster are balanced.')
            nodes_agents_dikt.clear()
        else:
            self.logger.info('The agents connected to the cluster are not balanced.')
        self.reconnection_timestamp = utils.get_utc_now()

        return nodes_agents_dikt

    async def balance_previous_conditions(self) -> None:
        """Controller function for the pre-reconnection phase of agents.
        This function encapsulates the entire phase prior to agent balancing.
        """
        if await self.check_previous_reconnections():
            self.previous_agents_nodes = await self.get_agents_balance()
            self.logger.debug(f'Agents to reconnect: {self.previous_agents_nodes}')

    def get_current_phase(self) -> AgentsReconnectionPhases:
        """Return the current phase of the algorithm.

        Returns
        -------
        AgentsReconnectionPhases
        """
        return self.current_phase

    def get_nodes_stability_info(self) -> dict:
        """Return the information related to the phase nodes stability.

        Returns
        -------
        dict
        """
        with contextlib.suppress(AttributeError):
            self.last_nodes_stability_check = self.last_nodes_stability_check.strftime(DECIMALS_DATE_FORMAT)

        return {
            'nodes_stability_counter': self.nodes_stability_counter,
            'nodes_stability_threshold': self.nodes_stability_threshold,
            'last_nodes_stability_check': self.last_nodes_stability_check,
            'last_register_nodes': str(list(self.nodes.keys()) + ['master-node']),
            'blacklisted_nodes': str(list(self.blacklisted_nodes)),
            'last_register_agents_nodes': str(list(self.previous_agents_nodes))
        }

    def to_dict(self) -> dict:
        """Returns the model properties as a dict.

        Returns
        -------
        dict
        """
        NotImplementedError("Not implemented yet")
