#!/usr/bin/env python3
"""
Is a revoked configuration refused as soon as a worker applies the change -- not when its cache expires?

On a worker, remoted answers a config download from the agent's cached membership while it is
fresh (remoted.control_groups_refresh_interval, 60 s by default). When the master reassigns the
agent's groups, the worker's cluster daemon applies the change to its local database and then
publishes it to the local remoted (POST /_internal/agents/groups on its admin socket), which
replaces the cached membership at once. Without that publication the old selector would keep
being served until the cached membership expired.

So: /control on one worker (a fresh cached membership), move the agent to a new group through the
master's API, and poll that worker. PASS when the old selector is refused (403) before the cached
membership could have expired, and the new one is then served. Nothing else refreshes the entry
meanwhile: this probe sends no /control while it polls.

Exit status 0 on PASS, 1 otherwise; --json-out writes the timeline.
"""
import argparse
import json
import sys
import time

import requests
import urllib3

sys.path.insert(0, "/tools")

from cross_node_download import control, download, brief
from download_convergence import enroll

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ManagerApi:
    """The few master API calls the probe needs: a group, and an agent moved into it alone."""

    def __init__(self, url, user, password):
        self.url = url.rstrip("/")
        r = requests.post(f"{self.url}/security/user/authenticate?raw=true", auth=(user, password),
                          verify=False, timeout=30)
        r.raise_for_status()
        self.headers = {"Authorization": f"Bearer {r.text.strip()}", "Content-Type": "application/json"}

    def create_group(self, name):
        r = requests.post(f"{self.url}/groups", headers=self.headers, data=json.dumps({"group_id": name}),
                          verify=False, timeout=30)
        r.raise_for_status()

    def assign_only(self, agent_id, group):
        r = requests.put(f"{self.url}/agents/{agent_id}/group/{group}",
                         params={"force_single_group": "true", "wait_for_complete": "true"},
                         headers=self.headers, verify=False, timeout=60)
        r.raise_for_status()
        return r.json()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--password", required=True, help="enrollment password")
    p.add_argument("--enroll-url", default="https://wazuh-lb-haproxy:1518")
    p.add_argument("--worker", default="https://wazuh-worker1:1517")
    p.add_argument("--api", default="https://wazuh-master:55000")
    p.add_argument("--api-user", default="wazuh")
    p.add_argument("--api-password", default="wazuh")
    p.add_argument("--prefix", default="/wazuh-manager/")
    p.add_argument("--ca", default="/certs/root-ca.pem")
    p.add_argument("--expiry", type=float, default=60.0,
                   help="remoted.control_groups_refresh_interval on the worker, in seconds")
    p.add_argument("--within", type=float, default=180.0)
    p.add_argument("--json-out", default=None)
    args = p.parse_args()

    pre, ca, w = args.prefix, args.ca, args.worker
    ident = enroll(args.enroll_url, pre, f"revoke-{int(time.time())}", args.password, ca, 20)
    a, k = ident["id"], ident["key"]
    out = {"agent_id": a, "worker": w, "timeline": [], "result": "FAIL", "reason": ""}

    def note(event, **fields):
        out["timeline"].append({"t": round(time.monotonic() - start, 2), "event": event, **fields})

    start = time.monotonic()
    print(f"agent {a}, worker {w}\n")

    # 1. The worker must know the agent: its key (else 401) and its row (else 503).
    deadline = time.monotonic() + args.within
    while True:
        r = control(w, pre, a, k, ca, "startup")
        if r.status_code == 200 or time.monotonic() > deadline:
            break
        time.sleep(2)
    note("control_startup", status=r.status_code)
    if r.status_code != 200:
        out["reason"] = f"the worker never accepted /control startup: {brief(r)}"
        return finish(out, args)

    # 2. A fresh cached membership, and the old selector served from it.
    r = control(w, pre, a, k, ca, "notify")
    fresh_at = time.monotonic()
    old = r.json()["agent"]["config_token"]
    note("control_notify", status=r.status_code, config_token=old)
    r = download(w, pre, a, k, ca, "config", old)
    note("download_old_before", status=r.status_code)
    print(f"1. /control on the worker: config_token {old!r}; download of it -> {brief(r)}")
    if r.status_code != 200:
        out["reason"] = f"the old selector was not served before the change: {brief(r)}"
        return finish(out, args)

    # 3. Move the agent, on the master, to a group of its own.
    group = f"lab-revoke-{int(time.time())}"
    api = ManagerApi(args.api, args.api_user, args.api_password)
    api.create_group(group)
    api.assign_only(a, group)
    changed_at = time.monotonic()
    note("group_changed_on_master", group=group)
    print(f"2. on the master: agent {a} now belongs to {group!r} only")

    # 4. The worker refuses the old selector -- before its cached membership could have expired.
    refused_at = None
    while time.monotonic() - fresh_at < args.expiry:
        r = download(w, pre, a, k, ca, "config", old)
        if r.status_code == 403:
            refused_at = time.monotonic()
            break
        time.sleep(1)
    note("download_old_after", status=r.status_code)
    if refused_at is None:
        out["reason"] = (f"the old selector was still answered ({r.status_code}) when the cached "
                         f"membership could expire ({args.expiry:.0f} s after /control)")
        return finish(out, args)
    out["seconds_change_to_refusal"] = round(refused_at - changed_at, 2)
    out["seconds_before_expiry"] = round(args.expiry - (refused_at - fresh_at), 2)
    print(f"3. old selector refused {out['seconds_change_to_refusal']} s after the change, "
          f"{out['seconds_before_expiry']} s before the cached membership could expire")

    # 5. And the new one is served (its merged.mg may take a sync round to reach the worker).
    deadline = time.monotonic() + args.within
    while True:
        r = download(w, pre, a, k, ca, "config", group)
        if r.status_code == 200 or time.monotonic() > deadline:
            break
        time.sleep(2)
    note("download_new", status=r.status_code)
    print(f"4. download of {group!r} -> {brief(r)}")
    if r.status_code != 200:
        out["reason"] = f"the new selector was not served: {brief(r)}"
        return finish(out, args)

    out["result"] = "PASS"
    return finish(out, args)


def finish(out, args):
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwritten: {args.json_out}")
    print(f"\nresult: {out['result']}{'' if out['result'] == 'PASS' else ' -- ' + out['reason']}")
    return 0 if out["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
