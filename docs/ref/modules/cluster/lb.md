# Load balancers

A load balancer distributes workloads across multiple resources. In a Wazuh server cluster, it distributes Wazuh agents among worker nodes to improve scalability, availability, and performance.

> **Note:** The `<cluster>` XML section referenced throughout the cluster
> docs is not parsed or validated by the shared C configuration library — it
> is recognized but otherwise ignored at that layer, with all parsing and
> validation performed later in Python. See
> [Cluster Configuration](configuration.md) for details.

## Overview

Load balancers allow agents to enroll and report to different Wazuh server nodes transparently. If a node becomes unavailable, agents reconnect to another available node.

> **For 5.x agents, see the Remoted load-balancer guides instead.** A 5.x agent enrolls and reports
> over the HTTPS agent API on port `1517`, not the ports below. Balancing HTTPS has its own
> requirements — TLS 1.3 on the backend, body-size and timeout alignment, no PROXY protocol, retry
> safety, and no URL path prefix — covered in
> [Remoted load balancers](../remoted/load-balancers/README.md), with worked configurations for
> [NGINX](../remoted/load-balancers/nginx.md) and [HAProxy](../remoted/load-balancers/haproxy.md).
>
> The examples on this page balance the **legacy** channel: agent traffic on `1514` and legacy
> enrollment on `1515`. They apply only to a cluster still serving 4.x agents, with
> `<remote><legacy>` and `<auth><legacy_enrollment>` enabled.

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
