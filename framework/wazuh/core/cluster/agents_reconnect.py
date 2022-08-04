import contextlib
from datetime import timedelta
from enum import Enum
from math import ceil

from wazuh.core import utils
from wazuh.core.agent import WazuhDBQueryAgents
from wazuh.core.common import DECIMALS_DATE_FORMAT
from wazuh.core.exception import WazuhError


class SkippingException(Exception):
    """Custom exception to control phase skips.
    """
    pass


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

    def __init__(self, logger, nodes, master_name, blacklisted_nodes, nodes_stability_threshold) -> None:
        """Class constructor.

        Parameters
        ----------
        logger : Logger object
            Logger to use.
        nodes : list
            List of nodes in the environment.
        master_name : str
            Name of the master node.
        blacklisted_nodes : set
            Set of nodes that are not taken into account for the agents reconnection.
        nodes_stability_threshold : int
            Number of consecutive checks that must be successful to consider the environment stable.
        """
        # Logger
        self.logger = logger

        # Check nodes stability
        self.nodes = nodes
        self.master_name = master_name
        self.blacklisted_nodes = blacklisted_nodes
        self.previous_nodes = set()
        self.nodes_stability_counter = 0
        self.nodes_stability_threshold = nodes_stability_threshold

        # Timestamps
        self.last_nodes_stability_check = 0

        # Check previous balance
        self.env_status = {}
        self.lost_agents_percent = 0.1  # 10%

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

    def wazuh_exception_handler(func):
        async def wrapper(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            except WazuhError as e:
                self.logger.error(f"Error in {func.__name__}: {e}")
                self.reset_counters()

                raise SkippingException from e

        return wrapper

    def reset_counters(self, node_name=None) -> None:
        """Reset all counters of the reconnection procedure.
        If the node is specified, it will be checked if it is on the blacklist.

        Parameters
        ----------
        node_name : str, optional
            Name of the node to be checked against the blacklist, by default None.
        """
        if node_name not in self.blacklisted_nodes:
            self.balance_counter = 0
            self.nodes_stability_counter = 0
            self.logger.debug("Reset all counters.")
        else:
            self.logger.debug(f"Disconnected {node_name} node, it is blacklisted, skipping counters reset.")

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
        node_list = set(self.nodes.keys()).union({self.master_name}) - self.blacklisted_nodes

        if len(node_list) <= 1:
            self.reset_counters()
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
            self.reset_counters()

        self.last_nodes_stability_check = utils.get_utc_now()
        if self.nodes_stability_counter >= self.nodes_stability_threshold:
            self.logger.info(f"Cluster is ready {self.nodes_stability_counter}/{self.nodes_stability_threshold}. "
                             f"Nodes stability phase finished at "
                             f"{self.last_nodes_stability_check.strftime(DECIMALS_DATE_FORMAT)}.")
            return True

        self.logger.info(f"Nodes are not stable at this moment. "
                         f"Counter: {self.nodes_stability_counter}/{self.nodes_stability_threshold}.")
        return False

    @wazuh_exception_handler
    async def get_reconnected_agents(self, agents_list) -> dict:
        """Check that the specified agents reconnected correctly after the request.

        Parameters
        ----------
        agents_list : list
            Agents to check.

        Returns
        -------
        dict
            Dictionary with IDs that satisfy the lastKeepAlive verification.
        """
        agent_query = WazuhDBQueryAgents(
            count=False, filters={"id": agents_list}, select={"id"},
            query=f"lastKeepAlive>{self.reconnection_timestamp + timedelta(seconds=self.agents_connection_delay)}")

        return agent_query.run()

    async def check_previous_reconnections(self) -> bool:
        """Check the agents status after the previous reconnection.

        Returns
        -------
        bool
            True if the agents are connected and the tolerance criteria are met or no agent has been reconnected,
            False otherwise.
        """
        self.current_phase = AgentsReconnectionPhases.CHECK_PREVIOUS_RECONNECTIONS
        # If no agent has been balanced in the previous iteration return True
        if self.env_status == {}:
            return True

        lost_agents_threshold = sum(len(info['agents']) for info in self.env_status.values()) * self.lost_agents_percent

        # Provisional until the balance_agents function is implemented
        list_of_reconnected_agents = []
        for d in self.env_status.values():
            list_of_reconnected_agents.extend(d['agents'])

        connected_agents = await self.get_reconnected_agents(list_of_reconnected_agents)
        connected_agents = connected_agents['items']
        if len(list_of_reconnected_agents) != len(connected_agents):
            lost_agents = []
            connected_agents = [d['id'] for d in connected_agents]
            lost_agents.extend(agent for agent in list_of_reconnected_agents if agent not in connected_agents)
            if len(lost_agents) >= lost_agents_threshold:
                self.logger.info('Too many lost agents. Halting reconnection procedure.')
                self.logger.debug(f'Lost agents: {lost_agents}.')
                self.current_phase = AgentsReconnectionPhases.HALT
                return False

        return True

    @wazuh_exception_handler
    async def get_agents_balance(self) -> dict:
        """Function in charge of checking the balance of the agents.

        Returns
        -------
        dict
            Dictionary with the agents that are not balanced.
            The keys of the dictionary are the names of the nodes and the values are the agents.
        """
        async def need_balance() -> dict:
            """Get the number of active agents per node and the number of
            agents that exceed the average number of agents per node.

            Returns
            -------
            dict
                Dictionary with the agents that exceed the average number of
                agents per node and the total number of active agents of each node.
            """
            agents_count = {}
            total = 0
            for node in self.previous_nodes:
                agent_query = WazuhDBQueryAgents(count=True, filters={"status": "active", "node_name": node},
                                                 select={"id"})
                agent_query._get_total_items(add_filters=True)
                agents_count[node] = agent_query.total_items
                total += agent_query.total_items

            try:
                mean = ceil(total / len(self.previous_nodes))
            except ZeroDivisionError:
                return {}

            unbalanced_agents = {}
            for node, agents in agents_count.items():
                difference = agents - mean
                if node not in unbalanced_agents.keys():
                    unbalanced_agents[node] = {}
                unbalanced_agents[node]['agents'] = 0
                unbalanced_agents[node]['total'] = agents
                if difference > 0:
                    unbalanced_agents[node]['agents'] = difference

            return unbalanced_agents

        async def get_agents(current_balance) -> dict:
            """Get the last X IDs of the agents that exceed the average number of agents per node.
            Modify the original dictionary by replacing the number of agents by their IDs.

            Parameters
            ----------
            current_balance : dict
                Dictionary with the number of active agents per node and
                the agents that exceed the average number of agents per node.

            Returns
            -------
            dict
                Dictionary with the IDs to reconnect and the number of active agents per node.
            """
            for node, info in current_balance.items():
                if info['agents'] > 0:
                    agent_query = WazuhDBQueryAgents(
                        count=False, filters={"status": "active", "node_name": node},
                        limit=info['agents'], sort={"fields": ["id"], "order": "desc"}, select=["id"],
                        query="(version>Wazuh v4.3.0,version=Wazuh v4.3.0);id!=000")
                    current_balance[node]['agents'] = [info["id"] for info in agent_query.run()["items"]]
                else:
                    current_balance[node]['agents'] = []

            return current_balance

        self.current_phase = AgentsReconnectionPhases.CHECK_AGENTS_BALANCE
        need_balance = await need_balance()
        if need_balance == {}:
            return {}

        current_unbalanced_agents = await get_agents(need_balance)
        if all(info['agents'] == [] for info in current_unbalanced_agents.values()):
            self.logger.info('The agents connected to the cluster are balanced.')
            current_unbalanced_agents.clear()
        else:
            self.logger.info('The agents connected to the cluster are not balanced.')
        self.reconnection_timestamp = utils.get_utc_now()

        return current_unbalanced_agents

    async def balance_previous_conditions(self) -> None:
        """Controller function for the pre-reconnection phase of agents.
        This function encapsulates the entire phase prior to agent balancing.
        """
        if await self.check_previous_reconnections():
            self.env_status = await self.get_agents_balance()
            self.logger.debug("Agents that need to be reconnected: "
                              f"{str({node: info['agents'] for node, info in self.env_status.items()})}.")

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
            'last_register_nodes': str(list(self.nodes.keys()) + [self.master_name]),
            'blacklisted_nodes': str(list(self.blacklisted_nodes)),
            'last_register_agents_nodes': str({node: info['agents'] for node, info in self.env_status.items()})
        }

    def to_dict(self) -> dict:
        """Returns the model properties as a dict.

        Returns
        -------
        dict
        """
        NotImplementedError("Not implemented yet")
