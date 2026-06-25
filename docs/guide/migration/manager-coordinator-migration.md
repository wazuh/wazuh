# Migrating Manager Coordinator from 4.x to 5.x

Coordinator migration requires almost no steps, as the coordinator only runs HAProxy and the dataplaneapi — there is no Wazuh manager package installed on it to upgrade. The migration mainly consists of refreshing the HAProxy and dataplaneapi configuration so they work with the 5.0 HAProxy helper.

## Migration procedure

### 1. Prepare HAProxy migration

> [!IMPORTANT]
> Make sure to have HAProxy installed on a dedicated machine, not alongside a Wazuh manager (master or worker). HAProxy binds ports `1514` and `1515`, the same ports the manager's `remoted` and `authd` use, so sharing a host causes a port conflict that stops `remoted` and breaks the HAProxy helper.

#### 1.1. HAProxy configuration changes

There have been some changes in the basic HAProxy configuration file. You can keep your previous configuration as it still works, or use the new basic configuration below:

```cfg
global
  maxconn 4000
  user haproxy
  group haproxy
  daemon
  stats socket /run/haproxy/admin.sock user haproxy group haproxy mode 660 level admin
  stats timeout 30s

defaults
  mode tcp
  timeout connect 10s
  timeout client 1m
  timeout server 1m

# Enrollment (authd) — static, NOT managed by the HAProxy helper
frontend wazuh_register
  bind :1515
  default_backend wazuh_register

backend wazuh_register
  balance leastconn
  server master <MASTER_NODE>:1515 check
  server worker1 <WORKER_NODE>:1515 check
  # add one 'server worker<n> <WORKER_NODE>:1515 check' line per extra worker

# Reporting/connection (remoted) — managed by the HAProxy helper.
# The helper creates the frontend (wazuh_reporting_front) bound to 1514 and
# populates this backend with the cluster nodes at runtime. Do NOT define a
# frontend here or list servers statically, or the helper will add its own
# frontend and servers on top, causing a duplicate 1514 bind and stale servers.
backend wazuh_reporting
  balance leastconn
```

> [!NOTE]
> The HAProxy helper requires a runtime `stats socket` (defined in the `global` section above) and it manages port `1514` itself. If your 4.x coordinator already ran the HAProxy helper, its configuration already omits the `wazuh_reporting` frontend and works under 5.0 unchanged. If it used a **static** `wazuh_reporting` frontend instead (helper disabled), remove that frontend and its static servers before enabling the helper, or HAProxy will end up with a duplicate frontend on port `1514`.

#### 1.2. Dataplaneapi configuration changes

The `dataplaneapi.yml` file has also had some configuration changes. The former base file still works fine, but you can update it to use the new base YAML file:

```yaml
dataplaneapi:
  host: 0.0.0.0
  port: 5555
  user:
    - name: <USER>
      password: <PASSWORD>
      insecure: true

haproxy:
  config_file: /etc/haproxy/haproxy.cfg
  haproxy_bin: /usr/sbin/haproxy
  reload:
    reload_cmd: service haproxy reload
    restart_cmd: service haproxy restart
```

#### 1.3. HAProxy configuration backup

Stop the services and prepare the backup directory:

```bash
sudo service haproxy stop
sudo pkill -9 dataplaneapi

sudo mkdir -p /var/coordinator-4-x-backup
```

You have two alternatives: keep the configurations your load balancer already uses, or start fresh with the new base files.

##### Alternative 1 — keep your existing configuration

```bash
sudo cp /etc/haproxy/haproxy.cfg /var/coordinator-4-x-backup/haproxy.cfg
sudo cp /etc/haproxy/dataplaneapi.yml /var/coordinator-4-x-backup/dataplaneapi.yml
```

##### Alternative 2 — start fresh with the new base files

Remember to replace `<MASTER_NODE>`, `<WORKER_NODE>`, `<USER>`, and `<PASSWORD>` with your real values after generating the files.

```bash
sudo tee /var/coordinator-4-x-backup/haproxy.cfg > /dev/null << 'EOF'
global
  maxconn 4000
  user haproxy
  group haproxy
  daemon
  stats socket /run/haproxy/admin.sock user haproxy group haproxy mode 660 level admin
  stats timeout 30s

defaults
  mode tcp
  timeout connect 10s
  timeout client 1m
  timeout server 1m

frontend wazuh_register
  bind :1515
  default_backend wazuh_register

backend wazuh_register
  balance leastconn
  server master <MASTER_NODE>:1515 check
  server worker1 <WORKER_NODE>:1515 check
  # add one 'server worker<n> <WORKER_NODE>:1515 check' line per extra worker

backend wazuh_reporting
  balance leastconn
EOF

sudo tee /var/coordinator-4-x-backup/dataplaneapi.yml > /dev/null << 'EOF'
dataplaneapi:
  host: 0.0.0.0
  port: 5555
  user:
    - name: <USER>
      password: <PASSWORD>
      insecure: true

haproxy:
  config_file: /etc/haproxy/haproxy.cfg
  haproxy_bin: /usr/sbin/haproxy
  reload:
    reload_cmd: service haproxy reload
    restart_cmd: service haproxy restart
EOF
```

### 2. Migrate coordinator

Do these steps on your machine with HAProxy installed.

#### 2.1. Install a supported dataplaneapi version

Use dataplaneapi `2.9.0`. Newer `2.x` releases are listed [here](https://github.com/haproxytech/dataplaneapi/releases/).

```bash
sudo rm /usr/local/bin/dataplaneapi
curl -sL https://github.com/haproxytech/dataplaneapi/releases/download/v2.9.0/dataplaneapi_2.9.0_linux_x86_64.tar.gz | tar xz
sudo mv build/dataplaneapi /usr/local/bin/ 2>/dev/null || sudo mv dataplaneapi /usr/local/bin/
```

#### 2.2. Restore the HAProxy service and dataplaneapi process

The new configuration uses a runtime socket under `/run/haproxy`. Make sure the directory exists before starting HAProxy, otherwise it cannot create the socket and the helper fails with `Error 3045`:

```bash
sudo mkdir -p /run/haproxy
sudo chown haproxy:haproxy /run/haproxy
```

Restore the configuration files and start the services:

```bash
sudo cp /var/coordinator-4-x-backup/haproxy.cfg /etc/haproxy
sudo cp /var/coordinator-4-x-backup/dataplaneapi.yml /etc/haproxy

sudo service haproxy start
sudo nohup dataplaneapi -f /etc/haproxy/dataplaneapi.yml > /var/log/dataplaneapi.log 2>&1 &
```

Ensure dataplaneapi is working correctly with:

```bash
curl -X GET --user <DATAPLANE_USER>:<DATAPLANE_PASSWORD> http://<COORDINATOR_IP>:5555/v2/info
```

You will see a response similar to this if everything works correctly:

```json
{"api":{"build_date":"2023-12-08T14:53:01.000Z","version":"v2.9.0 91da11d"},"system":{}}
```

> [!NOTE]
> Run this `curl` on the coordinator (or replace `<COORDINATOR_IP>` with the coordinator's address). The dataplaneapi listens only on the coordinator, so it is not reachable as `localhost` from the manager nodes.

Then restart each manager so the HAProxy helper reconnects:

```bash
sudo systemctl restart wazuh-manager
```

#### 2.3. Verify the HAProxy helper

On the master node, check the cluster log:

```bash
tail -f /var/wazuh-manager/logs/cluster.log
```

A successful migration shows the helper creating the reporting frontend and balancing the backend:

```
INFO: [HAPHelper] [Main] Proxy was initialized
INFO: [HAPHelper] [Main] Added Wazuh frontend
INFO: [HAPHelper] [Main] Detected changes in Wazuh cluster nodes. Current cluster: {'master-node': '...', 'worker-node': '...'}
INFO: [HAPHelper] [Main] Load balancer backend is up to date
INFO: [HAPHelper] [Main] Load balancer backend is balanced
```

> [!NOTE]
> The HAProxy helper rewrites `/etc/haproxy/haproxy.cfg` at runtime: it adds the `wazuh_reporting_front` frontend on port `1514` and the cluster nodes (e.g. `master-node`, `worker-node`) to the `wazuh_reporting` backend. This is expected, so the on-disk file will not stay byte-for-byte identical to what you wrote.

If you see `Error 3045 - Could not connect to HAProxy: runtime: option is not available`, the `stats socket` is missing from the `global` section of `haproxy.cfg` (or `/run/haproxy` does not exist). If you see `Several frontends exist binding the port "1514"`, you still have a static `wazuh_reporting` frontend that must be removed.

#### 2.4. HAProxy helper variables

No HAProxy helper variables have changed in 5.0, so you do not need to modify the `<haproxy_helper>` block in the manager configuration. Any value you do not set falls back to its default (for example, `haproxy_backend` defaults to `wazuh_reporting`).
