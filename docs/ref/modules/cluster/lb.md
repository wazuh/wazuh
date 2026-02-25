# Load balancers

A load balancer distributes workloads across multiple resources. In a Wazuh server cluster, it distributes Wazuh agents among worker nodes to improve scalability, availability, and performance.

## Overview

Load balancers allow agents to enroll and report to different Wazuh server nodes transparently. If a node becomes unavailable, agents reconnect to another available node.

This document covers two commonly used load balancers:

- NGINX
- HAProxy

---

## NGINX

NGINX can be used as a TCP load balancer to distribute Wazuh agent traffic across cluster nodes.

### Installation

Install NGINX using the packages provided by your Linux distribution.

### Configuration

Edit the `nginx.conf` file and add the following configuration:

```nginx
stream {
    upstream master {
        server <MASTER_NODE_IP>:1515;
    }

    upstream cluster {
        hash $remote_addr consistent;
        server <MASTER_NODE_IP>:1514;
        server <WORKER_NODE_IP>:1514;
        server <WORKER_NODE_IP>:1514;
    }

    server {
        listen 1515;
        proxy_pass master;
    }

    server {
        listen 1514;
        proxy_pass cluster;
    }
}
```

Replace the placeholder IP addresses with your cluster node addresses.

Reload the service to apply changes:

```bash
nginx -t
nginx -s reload
```

---

## HAProxy

HAProxy provides high availability and load balancing for TCP-based services such as Wazuh agent connections.

### Installation

Install HAProxy using system packages or Docker, depending on your environment.

### Basic configuration

Create `/etc/haproxy/haproxy.cfg` with the following configuration:

```cfg
global
    maxconn 4000
    user haproxy
    group haproxy
    daemon

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

frontend wazuh_reporting
    bind :1514
    default_backend wazuh_reporting

backend wazuh_reporting
    balance leastconn
    server master <MASTER_NODE>:1514 check
    server worker1 <WORKER_NODE>:1514 check
```

Start the service:

```bash
service haproxy start
```

---

## HAProxy helper

The HAProxy helper automatically updates HAProxy backend servers based on cluster status.

### Dataplane API configuration

Create a Dataplane API configuration file:

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
```

### Enable helper in Wazuh master

Add the following section to `wazuh-manager.conf`:

```xml
<haproxy_helper>
  <haproxy_disabled>no</haproxy_disabled>
  <haproxy_address><HAPROXY_ADDRESS></haproxy_address>
  <haproxy_user><USER></haproxy_user>
  <haproxy_password><PASSWORD></haproxy_password>
</haproxy_helper>
```

Restart the manager:

```bash
systemctl restart wazuh-manager
```

Verify logs:

```bash
tail /var/wazuh-manager/logs/cluster.log
```
