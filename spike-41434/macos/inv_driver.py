"""Inventory change driver: one change per action, spaced out, printed as JSON lines with the time it started.

Each action lists the notification keys expected per source (substring match), used by analyze.py.
"""
import json, os, subprocess, time

H = os.path.expanduser("~")
CHROME = f"{H}/Library/Application Support/Google/Chrome/Default/Extensions/wzpocext"
FIREFOX = f"{H}/Library/Application Support/Firefox/Profiles/wzpoc.default"
PLIST = """<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>{0}</string>
<key>RunAtLoad</key><true/><key>ProgramArguments</key><array><string>/bin/sleep</string><string>600</string></array></dict></plist>"""
NET = {"scdynamicstore": "{if}", "route": "{if}", "notify": "network_change"}
USER = {"es": "wzpoc", "fsevents": "dslocal/nodes/Default/users/wzpoc", "notify": "InvalidateCache"}
GROUP = {"es": "wzpocgrp", "fsevents": "dslocal/nodes/Default/groups/wzpocgrp", "notify": "InvalidateCache"}
SVC = {"fsevents": "com.wazuh.wzpoc.plist", "es": "com.wazuh.wzpoc"}
AGENT = {"fsevents": "com.wazuh.wzpocagent.plist", "es": "com.wazuh.wzpocagent"}

ACTIONS = [
    ("network", "address add", "sudo ifconfig lo0 alias 127.0.0.2 up", NET, "lo0"),
    ("network", "address remove", "sudo ifconfig lo0 -alias 127.0.0.2", NET, "lo0"),
    ("network", "interface create", "sudo ifconfig feth0 create", NET, "feth0"),
    ("network", "interface address", "sudo ifconfig feth0 inet 10.99.0.1/24 up", NET, "feth0"),
    ("network", "MTU change", "sudo ifconfig feth0 mtu 1400", NET, "feth0"),
    ("network", "interface destroy", "sudo ifconfig feth0 destroy", NET, "feth0"),
    ("packages", "app add", "sudo mkdir -p /Applications/WzPoc.app/Contents && sudo cp Info.plist /Applications/WzPoc.app/Contents/",
     {"fsevents": "/Applications/WzPoc.app"}, ""),
    ("packages", "app remove", "sudo rm -rf /Applications/WzPoc.app", {"fsevents": "/Applications/WzPoc.app"}, ""),
    ("packages", "pkg install", "sudo installer -pkg wzpoc.pkg -target /", {"fsevents": "receipts/com.wazuh.wzpoc"}, ""),
    ("packages", "pkg forget", "sudo pkgutil --forget com.wazuh.wzpoc", {"fsevents": "receipts/com.wazuh.wzpoc"}, ""),
    ("packages", "brew install", "brew install --quiet hello", {"fsevents": "Cellar/hello"}, ""),
    ("packages", "brew uninstall", "brew uninstall --quiet hello", {"fsevents": "Cellar/hello"}, ""),
    ("services", "daemon plist add", f"echo '{PLIST.format('com.wazuh.wzpoc')}' | sudo tee /Library/LaunchDaemons/com.wazuh.wzpoc.plist", SVC, ""),
    ("services", "daemon load", "sudo launchctl bootstrap system /Library/LaunchDaemons/com.wazuh.wzpoc.plist",
     {"es": "launchd exec /bin/sleep"}, ""),
    ("services", "daemon unload", "sudo launchctl bootout system/com.wazuh.wzpoc", {"es": "launchd exit /bin/sleep"}, ""),
    ("services", "daemon plist remove", "sudo rm /Library/LaunchDaemons/com.wazuh.wzpoc.plist", SVC, ""),
    ("services", "user agent add", f"echo '{PLIST.format('com.wazuh.wzpocagent')}' > {H}/Library/LaunchAgents/com.wazuh.wzpocagent.plist", AGENT, ""),
    ("services", "user agent remove", f"rm {H}/Library/LaunchAgents/com.wazuh.wzpocagent.plist", AGENT, ""),
    ("users", "user create", "sudo dscl . -create /Users/wzpoc && sudo dscl . -create /Users/wzpoc UniqueID 5055", USER, ""),
    ("users", "user delete", "sudo dscl . -delete /Users/wzpoc", USER, ""),
    ("groups", "group create", "sudo dseditgroup -o create wzpocgrp", GROUP, ""),
    ("groups", "member add", "sudo dseditgroup -o edit -a runner -t user wzpocgrp", GROUP, ""),
    ("groups", "group delete", "sudo dseditgroup -o delete wzpocgrp", GROUP, ""),
    ("browser extensions", "Chrome extension add", f"mkdir -p '{CHROME}/1.0' && echo '{{}}' > '{CHROME}/1.0/manifest.json'", {"fsevents": "wzpocext"}, ""),
    ("browser extensions", "Chrome extension remove", f"rm -rf '{CHROME}'", {"fsevents": "wzpocext"}, ""),
    ("browser extensions", "Firefox extensions.json", f"mkdir -p '{FIREFOX}' && echo '{{}}' > '{FIREFOX}/extensions.json'", {"fsevents": "wzpoc.default"}, ""),
]

for inv, name, cmd, expect, iface in ACTIONS:
    t0 = time.time()
    rc = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    t1 = time.time()
    print(json.dumps(dict(inv=inv, action=name, rc=rc, t0=t0, t1=t1, expect={k: v.replace("{if}", iface) for k, v in expect.items()})),
          flush=True)
    time.sleep(4)
