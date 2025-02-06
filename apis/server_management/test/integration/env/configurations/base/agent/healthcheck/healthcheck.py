import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base

if __name__ == "__main__":
    exit(get_agent_health_base())
