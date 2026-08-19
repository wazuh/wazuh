#!/usr/bin/env python3
"""
Stand-in for modulesd's task manager, for the #38283 sealed-identifier PoC.

remoted asks the task manager for an agent's pending tasks over a Unix socket at
`queue/tasks/task` (post-chroot), sending `{"action":"get_pending_tasks","agent_id":"001"}`
framed as a 4-byte native-endian length followed by the JSON body (SizeHeaderProtocol,
src/shared_modules/utils/socketWrapper.hpp).

Running the real task manager would mean running modulesd, the upgrade module and a populated
tasks.db just to get one `remote_upgrade` row in front of remoted. This answers that one query
with a canned row instead, which is all the mint path needs to be exercised: what remoted does
with the payload is the thing under test, not where the payload came from.

Every query gets the same task, so a notify always has one pending upgrade to deliver. That is
deliberately unlike the real task manager, which marks a task delivered on read -- it makes the
sealing path repeatable without recreating a task each time.

Run as root on the manager:
  python3 poc38283_taskd.py --wpk-file wazuh-agent_5.0.0-0_amd64_c21ecaa.deb.wpk
"""
import argparse
import json
import os
import socket
import struct
import sys
import threading

DEFAULT_SOCKET = "/var/wazuh-manager/queue/tasks/task"
# UUID-shaped, like the first 16 bytes of the SHA-256 wm_task_manager_tasks.c prints.
DEFAULT_TASK_ID = "3f2a1c9e-7b40-4d18-9c5e-a1b2c3d4e5f6"


def recv_exactly(conn, count):
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def serve_connection(conn, response_for):
    with conn:
        while True:
            header = recv_exactly(conn, 4)
            if header is None:
                return
            (size,) = struct.unpack("=I", header)
            body = recv_exactly(conn, size)
            if body is None:
                return

            try:
                request = json.loads(body)
            except ValueError:
                print(f"  <- unparseable request: {body!r}", flush=True)
                continue

            print(f"  -> {request}", flush=True)
            reply = json.dumps(response_for(request)).encode()
            conn.sendall(struct.pack("=I", len(reply)) + reply)
            print(f"  <- {reply.decode()}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--socket", default=DEFAULT_SOCKET)
    parser.add_argument("--task-id", default=DEFAULT_TASK_ID)
    parser.add_argument("--wpk-file", required=True,
                        help="Filename under var/upgrade/ the canned task advertises.")
    parser.add_argument("--wpk-sha1", default="0" * 40)
    parser.add_argument("--installer", default="upgrade.sh")
    parser.add_argument("--owner", default="wazuh-manager:wazuh-manager",
                        help="user:group to give the socket, so remoted can reach it after chroot.")
    parser.add_argument("--agent-id", default=None,
                        help="Only answer with a task for this agent id (zero-padded, e.g. 001). "
                             "Default: every agent gets one.")
    args = parser.parse_args()

    def response_for(request):
        if args.agent_id is not None and request.get("agent_id") != args.agent_id:
            return {"status": "ok", "tasks": []}
        return {
            "status": "ok",
            "tasks": [{
                "task_id": args.task_id,
                "task_type": "remote_upgrade",
                "payload": {
                    "wpk_file": args.wpk_file,
                    "wpk_sha1": args.wpk_sha1,
                    "installer": args.installer,
                },
            }],
        }

    os.makedirs(os.path.dirname(args.socket), exist_ok=True)
    if os.path.exists(args.socket):
        os.unlink(args.socket)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(args.socket)
    os.chmod(args.socket, 0o660)
    # remoted connects post-chroot as the runtime user, so the socket has to be reachable by it
    # -- the real task manager runs as that user and gets this for free.
    if args.owner:
        import grp
        import pwd
        user, _, group = args.owner.partition(":")
        os.chown(args.socket, pwd.getpwnam(user).pw_uid, grp.getgrnam(group or user).gr_gid)
    server.listen(16)

    print(f"fake task manager listening on {args.socket}", flush=True)
    print(f"  serving remote_upgrade task {args.task_id} -> {args.wpk_file}", flush=True)

    try:
        while True:
            conn, _ = server.accept()
            threading.Thread(target=serve_connection, args=(conn, response_for), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        if os.path.exists(args.socket):
            os.unlink(args.socket)

    return 0


if __name__ == "__main__":
    sys.exit(main())
