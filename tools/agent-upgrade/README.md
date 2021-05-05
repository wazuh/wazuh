# How to create and install custom WPK packages

## Get a X509 certificate and CA

### Create root CA

```
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout wpk_root.key -out wpk_root.pem -batch -days 1825
```

### Create certificate and key

```
openssl req -new -nodes -newkey rsa:2048 -keyout wpkcert.key -out wpkcert.csr -subj '/C=US/ST=CA/O=Wazuh'
```

- `/C=US` is the country.
- `/ST=CA` is the state.
- `/O=Wazuh` is the organization's name.

Sign this certificate with the root CA:

```
openssl x509 -req -days 730 -in wpkcert.csr -CA wpk_root.pem -CAkey wpk_root.key -out wpkcert.pem -CAcreateserial
```

## Compile a package

WPK packages will usually contain a complete agent code, but this is not necessary.

A WPK package must contain an installation program, in binary form or a script in any language supported by the agent (Bash, Python, etc). Canonical WPK packages should contain a Bash script with name `upgrade.sh` for UNIX or `upgrade.bat` for Windows. This program must:

1. Fork itself, the parent will return 0 immediately.
2. Restart the agent.
3. Before exiting, the installer must write a file called `upgrade_result` containing a status number (`0` means *OK*). For instance:

```
0
```

### Requirements

- Python 2.7 or 3.5+
- Cryptography package for Python.

You may get the Cryptography package using Pip:

```
pip install cryptography
```

### Canonical WPK package example

1. Download sources from GitHub at branch 3.0:

```
curl -Lo wazuh-3.0.zip https://github.com/wazuh/wazuh/archive/3.0.zip
unzip wazuh-3.0.zip
```

2. Compile the project:

```
make -C wazuh-3.0/src TARGET=agent
```

3. Change to the base directory:

```
cd wazuh-3.0
```

4. Install the root CA, only if you want to **overwrite the root CA** with the file you created before:

```
cp path/to/wpk_root.pem etc/wpk_root.pem
```

5. Compile the WPK package. You need your SSL certificate and key:

```
tools/agent-upgrade/wpkpack.py output/myagent.wpk path/to/wpkcert.pem path/to/wpkcert.key *
```

- `output/myagent.wpk` is the name of the output WPK package.
- `path/to/wpkcert.pem` is the path to your SSL certificate.
- `path/to/wpkcert.key` is the path to your SSL certificate's key.
- `*` is the file (or the files) to be included into the WPK package.

In this particular case, the Wazuh Project's root directory contains the proper `upgrade.sh` file.

*Note: this is a mere example. If you want to distribute a WPK package this way you should first clean the directory.*

## Install a custom WPK package

### Install the root CA into the agent

The root CA certificate, or failing that, the certificate used to sign the WPK package, must be installed in the agent before running an upgrade.

You have two options:

1. Overwrite the shipped root CA with your certificate. This will prevent your agent from upgrading using WPK packages from Wazuh.

```
cp /path/to/certificate etc/wpk_root.pem
```

2. Add a new certificate by editing the `ossec.conf` file:

```
<active-response>
  <ca_store>/var/ossec/etc/wpk_root.pem</ca_store>
  <ca_store>/path/to/certificate</ca_store>
</active-response>
```

### Run the upgrade

Get the WPK package into the Wazuh manager and run:

```
/var/ossec/bin/agent_upgrade -a 001 -f path/to/myagent.wpk -x upgrade.sh
```

- `-a 001` specifies the agent to upgrade.
- `-f path/to/myagent.wpk` is the path to the WPK package.
- `-x upgrade.sh` is the name of the upgrading script contained in the package.

Output example:

```
Sending WPK: [=========================] 100%
Installation started... Please wait.
Agent upgraded successfully
```

## Create a WPK package repository

WPK files must be named matching this pattern:

> wazuh_agent_W_X_Y_Z

- `W` is the version of the released version.
- `X` is the name of the operating system.
- `Y` is the version of the operating system.
- `Z` is the machine's architecture.

For instance:

> wazuh_agent_v3.0.0-beta7_centos_7_x86_64.wpk

Such files must also be classified in this folder tree:

> X/Y/Z

For instance:

> centos/7/x86_64

Every folder must contain a file named `versions` that contain each version contained in the folder and the file's SHA1 hash. The **latest version must be placed in the first line**. For instance:

```
v3.0.0-beta7 0e116931df8edd6f4382f6f918d76bc14d9caf10
v3.0.0-beta6 ba45f0fe9ca4b3c3b4c3b42b4a2e647f3e2df4a3
v3.0.0-beta5 30e750a84bc8333cb77995d99694425cacdad30d
```

## Install a canonical WPK package

In the same way, the root CA certificate must be installed in the agent prior to run an upgrade.

Run this command from the manager:

```
/var/ossec/bin/agent_upgrade -a 001 -r https://example.com/repo
```

- `-a 001` specifies the agent to upgrade.
- `-r https://example.com/repo` is the URL to your own WPK repository.
