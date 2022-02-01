from wazuh import agent

print(agent.get_agents(select=['status'], filters={'status': 'active'})._affected_items)
