#! /usr/bin/python3
# June 21, 2023

# Syntax: wdb-query.py <AGENT ID> <PATH>

from socket import socket, AF_UNIX, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit
from json import dumps, loads
from json.decoder import JSONDecodeError

def db_query(agent_id, path):

    #convert agent id to agent text, example: agent 0 to agent 000... agent 1 to agent 001... agent 10 to agent 010... agent 100 to agent 100... agent 1000 to agent 1000
    agent_id_text = str(agent_id).zfill(3)

    WDB = '/var/ossec/queue/db/wdb'

    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(WDB)

    #load information from plain file that have osquery output for deb_packages
    jsonPackagesFile = open(path + agent_id + "/packages.json")

    #load information from plain file that have osquery output for os_version
    jsonOsVersionFile = open(path + agent_id + "/osinfo.json")

    #load information from plain file that have osquery output for system_info
    jsonSystemInfoFile = open(path + agent_id + "/systeminfo.json")

    #parse jsons.
    jsonPackages = loads(jsonPackagesFile.read())
    jsonOsVersion = loads(jsonOsVersionFile.read())
    jsonSystemInfo = loads(jsonSystemInfoFile.read())

    #convert from osquery json to wazuh syscollector delta json.
    #wazuh example for os:
    # {"checksum":"1634140017886803554","architecture":"x86_64","hostname":"UBUNTU",
    #  "os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601",
    #  "os_build":"7601","os_display_version":"test"}
    #osquery example for os:
    #[
    #  {"arch":"x86_64","build":"","codename":"jammy","major":"22","minor":"4","name":"Ubuntu","patch":"0","platform":"ubuntu","platform_like":"debian","version":"22.04.2 LTS (Jammy Jellyfish)"}
    #]

    jsonWazuhOsVersion = []
    os = jsonOsVersion[0]
    systeminfo = jsonSystemInfo[0]

    element = {
        "checksum": "1634140017886803554",
        "architecture": os["arch"],
        "hostname": systeminfo["hostname"],
        "os_major": os["major"],
        "os_minor": os["minor"],
        "os_name": os["name"],
        "os_release": os["codename"],
        "os_version": os["version"],
        "os_build": os["build"],
        "os_display_version": os["version"]
    }
    finalQuery = "agent " + agent_id_text + " dbsync osinfo INSERTED " + dumps(element)
    print(finalQuery)
    msg = finalQuery.encode()
    sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))

    length = unpack("<I", sock.recv(4))[0]
    pretty(sock.recv(length).decode(errors='ignore'))


    #input: global update-agent-data {"id":1,"os_name":"TestOsName","os_version":"TestOsVersion","os_major":"TestOsMajor","os_minor":"TestOsMinor","os_codename":"TestOsCodeName","os_platform":"TestOsPlatfor","os_build":"TestOsBuild","os_uname":"TestOsUname","os_arch":"TestOsArch","version":"TestVersion","config_sum":"TestConfigSum","merged_sum":"TestMergedSum","manager_host":"TestManagerHost","node_name":"TestNodeName","agent_ip":"0.0.0.1","sync_status":"syncreq","group_config_status":"not synced","connection_status":"never_connected","labels":"TestKey1:TestLabel1"}
#convert agent_id to integer.
    element = {
        "id": int(agent_id),
        "os_name": os["name"],
        "os_version": os["version"],
        "os_major": os["major"],
        "os_minor": os["minor"],
        "os_codename": os["codename"],
        "os_platform": os["platform"],
        "os_build": os["build"],
        "os_uname": "Linux |6063a4f66199 |x86_64",
        "os_arch": os["arch"],
        "version": "TestVersion",
        "config_sum": "TestConfigSum",
        "merged_sum": "TestMergedSum",
        "manager_host": "TestManagerHost",
        "node_name": "TestNodeName",
        "agent_ip": "127.0.0.1",
        "sync_status": "synced",
        "group_config_status": "synced",
        "connection_status": "never_connected",
        "labels": "TestKey1:TestLabel1"
    }
    finalQuery = "global update-agent-data " + dumps(element)
    print(finalQuery)
    msg = finalQuery.encode()
    sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))

    length = unpack("<I", sock.recv(4))[0]
    pretty(sock.recv(length).decode(errors='ignore'))

    #wazuh example for packages:
    #{"checksum":"1c1bf8bbc20caef77010f960461cc20fb9c67568",
    #"architecture":"amd64","description":"Qt 5 OpenGL module","format":"deb","groups":"libs",
    #"item_id":"caa4868d177fbebc5b145a2a92497ebcf566838a","multiarch":"same","name":"libqt5opengl5",
    #"priority":"optional","scan_time":"2021/10/13 15:10:49","size":572,"source":"qtbase-opensource-src",
    #"vendor":"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>","version":"5.12.8+dfsg-0ubuntu1"}
    #osquery example for packages:
    #[
    #{"admindir":"/var/lib/dpkg","arch":"amd64","maintainer":"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>","name":"zlib1g","priority":"required","revision":"2ubuntu9.2","section":"libs","size":"164","source":"zlib","status":"install ok installed","version":"1:1.2.11.dfsg-2ubuntu9.2"}
    #]
    for package in jsonPackages:
        element = {
            "checksum": "1634140017886803554",
            "architecture": package["arch"],
            "description": "Not provided by osquery",
            "format": "rpm" if package["source"].endswith(".rpm") else "deb",
            "groups": package["section"] if "section" in package else package["package_group"],
            "item_id": "caa4868d177fbebc5b145a2a92497ebcf566838a",
            "multiarch": "Not provided by osquery",
            "name": package["name"],
            "priority": package["priority"] if "priority" in package else "Not provided by osquery",
            "scan_time": "2021/10/13 15:10:49",
            "size": package["size"],
            "source": package["source"],
            "vendor": package["maintainer"] if "maintainer" in package else package["vendor"],
            "version": package["version"]
        }

        finalQuery = "agent " + agent_id_text + " dbsync packages INSERTED " + dumps(element)
        print(finalQuery)
        msg = finalQuery.encode()
        sock.send(pack("<I{0}s".format(len(msg)), len(msg), msg))

        length = unpack("<I", sock.recv(4))[0]
        pretty(sock.recv(length).decode(errors='ignore'))

def pretty(response):
    if response.startswith('ok '):
        try:
            data = loads(response[3:])
            return dumps(data, indent=4)
        except JSONDecodeError:
            return response[3:]
    else:
        return response

if __name__ == "__main__":
    if len(argv) < 3 or (len(argv) > 1 and argv[1] in ('-h', '--help')):
        print("Syntax: {0} <agent id> <path>")
        exit(1)

    db_query(argv[1], argv[2])
