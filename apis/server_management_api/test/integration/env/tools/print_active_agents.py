from wazuh import agent

if __name__ == '__main__':
    print(agent.get_agents(select=['status'], filters={'status': 'active'}).affected_items)
