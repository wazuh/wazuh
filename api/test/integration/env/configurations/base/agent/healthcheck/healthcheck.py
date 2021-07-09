import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base

try:
    agent_old = sys.argv[1]
except IndexError:
    agent_old = False

if __name__ == "__main__":
    exit(get_agent_health_base(agent_old=agent_old))
