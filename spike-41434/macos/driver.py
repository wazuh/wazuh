"""Test driver: runs the scenarios and prints the ground truth as JSON lines.

driver.py         all scenarios (as the runner user; root parts through sudo)
driver.py ports   only the fast-port scenario, as the current user
"""
import json, os, pwd, socket, subprocess, sys, time


def out(**r):
    print(json.dumps(r), flush=True)


def proc(cmd, code, euid, wait=True):
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    if not wait:
        return p, t0
    o, _ = p.communicate()
    t1 = time.time()
    pid = int(o) if o.strip() else p.pid  # sudo cases print the shell pid
    out(kind="proc", pid=pid, code=code, rc=p.returncode, euid=euid, t0=t0, t1=t1)


def storm(uid):
    for i in range(200):  # sequential, under 10 ms each
        proc(["/bin/sh", "-c", f"exit {i % 250 + 1}"], i % 250 + 1, uid)
    for b in range(10):  # parallel batches of 20
        ps = [(proc(["/bin/sh", "-c", f"exit {b * 20 + j + 1}"], 0, 0, wait=False), b * 20 + j + 1) for j in range(20)]
        for (p, t0), code in ps:
            p.wait()
            out(kind="proc", pid=p.pid, code=code, rc=p.returncode, euid=uid, t0=t0, t1=time.time())


def users():
    nobody = pwd.getpwnam("nobody").pw_uid & 0xFFFFFFFF
    for _ in range(5):
        proc(["sudo", "-n", "-u", "nobody", "/bin/sh", "-c", "echo $$; exit 3"], 3, nobody)
        proc(["sudo", "-n", "/bin/sh", "-c", "echo $$; exit 4"], 4, 0)


def ports():
    cases = [("tcp", socket.AF_INET, "127.0.0.1"), ("tcp", socket.AF_INET6, "::1"),
             ("udp", socket.AF_INET, "127.0.0.1"), ("udp", socket.AF_INET6, "::1")]
    for hold in [0.3] * 5 + [3.0]:
        for proto, fam, addr in cases:
            s = socket.socket(fam, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
            s.bind((addr, 0))
            if proto == "tcp":
                s.listen()
            t0 = time.time()
            port = s.getsockname()[1]
            time.sleep(hold)
            s.close()
            out(kind="port", proto=proto, fam=6 if fam == socket.AF_INET6 else 4, port=port, pid=os.getpid(), uid=os.geteuid(),
                hold=hold, t0=t0, t1=time.time())
            time.sleep(0.2)


if __name__ == "__main__":
    if sys.argv[1:] == ["ports"]:
        ports()
        sys.exit()
    uid = os.geteuid()
    storm(uid)
    users()
    ports()
    sys.stdout.write(subprocess.run(["sudo", "-n", sys.executable, os.path.abspath(__file__), "ports"],
                                    capture_output=True, text=True).stdout)
