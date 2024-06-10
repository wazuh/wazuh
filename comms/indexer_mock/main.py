from argparse import ArgumentParser, Namespace
from requests import post
from signal import signal, SIGINT
from sys import exit
from time import sleep


def signal_handler(n_signal, frame):
    print("")
    exit(1)

def get_script_arguments() -> Namespace:
    """Get script arguments.

    Returns
    -------
    argparse.Namespace
        Arguments passed to the script.
    """
    parser = ArgumentParser()
    parser.add_argument("-a", "--agent_ids", nargs='+', help="List of agent IDs.")
    parser.add_argument("-u", "--url", type=str, dest="url", default="http://localhost:5000", help="Agent comms API url.")
    parser.add_argument("-l", "--loop", type=bool, help="Execute the request every 10 seconds.")

    return parser.parse_args()

def main(agent_ids: list[str], url: str) -> str:
    """Main function.

    Parameters
    ----------
    agent_ids : list[str]
        List of agent IDs to send the commands to.
    url : str
        Agent comms API url.

    Returns
    -------
    str
        Response text.
    """
    token = login(url)
    return send_command(agent_ids, url, token)

def login(url: str) -> str:
    body = {
        "uuid": "1",
        "password": "pass"
    }
    resp = post(f"{url}/api/v1/login", json=body)
    if resp.status_code != 200:
        raise Exception("Invalid request")
    
    return resp.json()["token"]

def send_command(agent_ids: list[str], url: str, token: str):
    if len(agent_ids) == 0:
        ## Mock ID to send the command to at least one agent
        agent_ids = ["018fe477-31c8-7580-ae4a-e0b36713eb05"]

    command = {"id": "1", "type": "restart", "agent_ids": agent_ids}
    headers = {'Authorization': f"Bearer {token}"}

    resp = post(f"{url}/api/v1/commands", json={"commands": [command]}, headers=headers)
    return resp.text

if __name__ == "__main__":
    # Capture Ctrl + C
    signal(SIGINT, signal_handler)

    args = get_script_arguments()

    try:
        main(args.agent_ids, args.url)

        if args.loop:
            while True:
                sleep(10)
                main(args.agent_ids, args.url)
    except Exception as e:
        print(f"Internal error: {e}")
        exit(1)
