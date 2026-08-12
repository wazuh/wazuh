#!/usr/bin/env python3
"""
Manual/end-to-end driver for the whole-agent deletion endpoint (`DELETE /agents`).

Speaks the same bytes authd puts on the wire over the module's UDS socket, so it exercises the
real deletion path rather than an approximation of it. Standard library only, so it runs on the
manager's own embedded interpreter.

The endpoint deletes every document of one agent across the whole deletion scope:

    wazuh-states-*        the agent's state documents (generated ids, deleted by query)
    wazuh-agent-config    its reported configuration  (one document, agent id as _id)
    wazuh-agent-stats     its reported statistics     (one document, agent id as _id)

The server does NOT refresh the indices first, and a delete-by-query is a SEARCH: documents the
agent's last session wrote inside the index refresh interval are invisible to the query and survive a
deletion that answered 200. That is a known limitation (`_refresh` needs `indices:admin/refresh`,
which the manager's indexer role does not grant); re-running the deletion clears the leftovers, since
it is idempotent.

`--verify` reads the three index scopes off the indexer before and after the deletion, refreshing
them itself first, which is the only way to see what the 200 actually did — including a leftover from
the window above. Without it this tool proves the UDS hop and the status, nothing more.

Examples:
    # Delete agent 007, no indexer access needed
    ./send_delete_agent.py --agent-id 7

    # Same, but count the agent's documents before and after
    sudo ./send_delete_agent.py --agent-id 7 --verify

    # Prove the deletion is scoped: 900 goes, 901 stays
    sudo ./send_delete_agent.py --agent-id 900 --verify --witness 901

    # The POST alias authd uses (its HTTP helper only speaks POST)
    ./send_delete_agent.py --agent-id 7 --alias

    # Contract checks: missing and non-numeric ids (both expect 400)
    ./send_delete_agent.py --agent-id ''
    ./send_delete_agent.py --agent-id not-numeric

Run it from the manager's home directory so the default relative socket path resolves, or pass
--socket with an absolute path.
"""

import argparse
import http.client
import json
import os
import socket
import subprocess
import sys

DEFAULT_SOCKET = "queue/sockets/inventory-sync.sock"
# Mirror invsync::endpoints::delete_agent::path()/altPath(). Source of truth:
# src/wazuh_modules/inventory_sync_server/src/endpoints/deleteAgentEndpoint.hpp
DELETE_PATH = "/agents"
ALIAS_PATH = "/agents/delete"
AGENT_ID_HEADER = "X-Wazuh-Agent-Id"

# Mirror invsync::sync::AGENT_DELETION_SCOPE. Source of truth:
# src/wazuh_modules/inventory_sync_server/src/sync/stateIndexAllowlist.hpp
DELETION_SCOPE = ("wazuh-states-*", "wazuh-agent-config", "wazuh-agent-stats")

DEFAULT_INDEXER = "https://127.0.0.1:9200"
DEFAULT_CERT = "/etc/wazuh-indexer/certs/admin.pem"
DEFAULT_KEY = "/etc/wazuh-indexer/certs/admin-key.pem"
DEFAULT_CLIENT_KEYS = "etc/client.keys"


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over an AF_UNIX stream socket."""

    def __init__(self, socket_path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def send_delete(socket_path, path, method, agent_id, timeout):
    """Returns (status, reason, body). The body is ignored by the endpoint."""
    connection = UnixHTTPConnection(socket_path, timeout=timeout)
    try:
        headers = {"Host": "localhost", "Connection": "close", "Content-Length": "0"}
        if agent_id:
            # What authd sets for the agent it just removed from client.keys.
            headers[AGENT_ID_HEADER] = agent_id
        connection.request(method, path, body=b"", headers=headers)
        response = connection.getresponse()
        return response.status, response.reason, response.read().decode(errors="replace")
    finally:
        connection.close()


# --- Optional indexer side (--verify) --------------------------------------------------------
# Shelling out to curl instead of importing requests keeps this tool standard-library-only, which
# is what lets it run on the manager's embedded interpreter with nothing installed.

def curl(indexer, cert, key, *args):
    result = subprocess.run(["curl", "-sk", "--cert", cert, "--key", key, *args],
                            capture_output=True, text=True)
    return result.stdout


def count_documents(agent_id, indexer, cert, key):
    """Documents of one agent per index in the deletion scope, or None on an unreadable answer.

    Refreshes first, deliberately: this reports the TRUTH, not what the deletion's own
    delete-by-query was able to see.
    """
    counts = {}
    for index in DELETION_SCOPE:
        curl(indexer, cert, key, "-X", "POST", f"{indexer}/{index}/_refresh", "-o", "/dev/null")
        body = curl(indexer, cert, key, "-X", "POST", f"{indexer}/{index}/_search?size=0",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps({"query": {"term": {"wazuh.agent.id": agent_id}}}))
        try:
            parsed = json.loads(body)
        except ValueError:
            counts[index] = None          # curl failed outright (certs? indexer down?)
            continue
        if "hits" in parsed:
            counts[index] = parsed["hits"]["total"]["value"]
        elif parsed.get("status") == 404:
            counts[index] = 0             # the index does not exist yet
        else:
            counts[index] = None          # an error we should not silently read as zero
    return counts


def print_counts(label, agent_id, counts):
    cells = []
    for index, value in counts.items():
        shown = "ERROR" if value is None else value
        cells.append(f"{index}={shown}")
    print(f"    {label:8s} agent {agent_id}: " + "   ".join(cells))


def indexer_unreadable(counts):
    return any(value is None for value in counts.values())


def same_agent(one, other):
    """Compare ids the way the manager does: NUMERICALLY. client.keys stores them zero-padded to
    three characters and the endpoint pads before deleting, so a raw "7" and an enrolled "007" are
    the same agent -- comparing the strings is what let `--agent-id 7` (this tool's own documented
    example for agent 007) walk straight past the enrolled-agent guard."""
    try:
        return int(one) == int(other)
    except (TypeError, ValueError):
        return one == other                # non-numeric: the endpoint answers 400 anyway


def warn_if_enrolled(agent_id, client_keys):
    """A deletion targeting an ENROLLED agent destroys live data that only a full resync brings
    back. This tool is for manual testing, so it refuses instead of asking."""
    try:
        with open(client_keys) as handle:
            enrolled = {line.split()[0] for line in handle if line.strip() and line[0] not in "#"}
    except OSError:
        return None                        # cannot read it; not this tool's job to insist
    return any(same_agent(agent_id, enrolled_id) for enrolled_id in enrolled)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--socket", default=DEFAULT_SOCKET,
                        help=f"socket path, relative to the current directory (default: {DEFAULT_SOCKET})")
    parser.add_argument("--agent-id", default="900",
                        help="agent to delete; pass an empty string to omit the header (expects 400)")
    parser.add_argument("--alias", action="store_true",
                        help=f"use POST {ALIAS_PATH} (authd's route) instead of DELETE {DELETE_PATH}")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="per-request timeout in seconds (default: 60; the deletion does indexer I/O)")
    parser.add_argument("--verify", action="store_true",
                        help="count the agent's documents on the indexer before and after")
    parser.add_argument("--witness", default=None, metavar="AGENT_ID",
                        help="with --verify, a second agent that must be left untouched")
    parser.add_argument("--indexer", default=DEFAULT_INDEXER, help="indexer base URL, for --verify")
    parser.add_argument("--cert", default=DEFAULT_CERT, help="client certificate, for --verify")
    parser.add_argument("--key", default=DEFAULT_KEY, help="client key, for --verify")
    parser.add_argument("--client-keys", default=DEFAULT_CLIENT_KEYS,
                        help=f"client.keys, checked to refuse enrolled agents (default: {DEFAULT_CLIENT_KEYS})")
    parser.add_argument("--force", action="store_true",
                        help="delete even if the agent is enrolled in client.keys")
    args = parser.parse_args()

    if not os.path.exists(args.socket):
        print(f"error: no socket at '{args.socket}'.", file=sys.stderr)
        print("       Run this from the manager's home directory, or pass --socket with a full path.",
              file=sys.stderr)
        print("       If the module is running, check that it logged 'listening on'.", file=sys.stderr)
        return 2

    if args.agent_id and not args.force and warn_if_enrolled(args.agent_id, args.client_keys):
        print(f"error: agent {args.agent_id} is ENROLLED in {args.client_keys}.", file=sys.stderr)
        print("       Deleting it destroys inventory that only a full agent resync restores.",
              file=sys.stderr)
        print("       Use an id that is not enrolled, or --force if you really mean it.",
              file=sys.stderr)
        return 2

    method, path = ("POST", ALIAS_PATH) if args.alias else ("DELETE", DELETE_PATH)

    before = None
    if args.verify:
        print("--- before ---")
        before = count_documents(args.agent_id, args.indexer, args.cert, args.key)
        print_counts("before", args.agent_id, before)
        if args.witness:
            print_counts("before", args.witness,
                         count_documents(args.witness, args.indexer, args.cert, args.key))
        if indexer_unreadable(before):
            print("\nerror: could not read the indexer (certificates? is it running?).", file=sys.stderr)
            print("       Refusing to continue: every count would read as a reassuring zero.",
                  file=sys.stderr)
            return 2
        if not any(before.values()):
            print(f"\nwarning: agent {args.agent_id} has no documents. The deletion will answer 200 "
                  f"with nothing to delete, which proves nothing -- seed some first "
                  f"(POST /config, POST /stats).")

    print(f"\n--> {method} {path}   {AGENT_ID_HEADER}: {args.agent_id or '(omitted)'}")
    try:
        status, reason, body = send_delete(args.socket, path, method, args.agent_id, args.timeout)
    except Exception as error:  # noqa: BLE001 - a manual tool should report, not traceback
        print(f"<-- request failed: {error}", file=sys.stderr)
        return 1
    print(f"<-- {status} {reason} {body}")

    if status == 503:
        print("\n    503 means no configured indexer host is healthy, or the pipeline is shutting "
              "down. The deletion was NOT performed; this is the endpoint telling the caller to "
              "retry, which is exactly what authd does.")
    elif status == 400:
        print("\n    400 means the agent id header was missing or non-numeric.")

    if not args.verify:
        return 0 if status == 200 else 1

    print("\n--- after ---")
    after = count_documents(args.agent_id, args.indexer, args.cert, args.key)
    print_counts("after", args.agent_id, after)
    if args.witness:
        witness_after = count_documents(args.witness, args.indexer, args.cert, args.key)
        print_counts("after", args.witness, witness_after)

    # Same guard as the `before` snapshot, and for the same reason: an unreadable indexer answers
    # None for every count, and `if value` treats None exactly like 0 -- so without this the tool
    # would print "clean" and exit 0 precisely when it verified nothing.
    if indexer_unreadable(after):
        print("\nerror: could not read the indexer after the deletion, so nothing was verified.",
              file=sys.stderr)
        print("       The deletion itself answered "
              f"{status if status else 'no status'}; re-run with --verify once the indexer is readable.",
              file=sys.stderr)
        return 2

    leftovers = {index: value for index, value in after.items() if value}
    if leftovers:
        print(f"\n    LEFTOVERS: agent {args.agent_id} still has documents in {leftovers}")
        return 1

    print(f"\n    clean: agent {args.agent_id} has no documents left in any index of the scope")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
