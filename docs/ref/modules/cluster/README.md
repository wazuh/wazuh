# Wazuh server cluster

## Introduction

The Wazuh server cluster is composed of multiple Wazuh server nodes running in a distributed environment. This deployment strategy provides horizontal scalability and improved performance. In environments with a large number of monitored endpoints, this setup can be combined with a network load balancer to distribute Wazuh agent connections across multiple nodes. This allows the Wazuh platform to manage a high number of agents efficiently while ensuring high availability.

The Wazuh server cluster consists of one **master node** and multiple **worker nodes**. Wazuh agents are configured to report to the server nodes within the cluster. This architecture improves scalability and overall server performance.

---

## Architecture

There are two types of nodes in a Wazuh server cluster: **master nodes** and **worker nodes**. These roles define the responsibilities of each node and establish a hierarchy used during synchronization processes.

A Wazuh server cluster can have only one master node. During synchronization, data from the master node always takes precedence over data from worker nodes. This ensures consistency and uniformity across the cluster.

> **Note**  
> Configuration changes applied to the file  
> `/var/wazuh-manager/etc/wazuh-manager.conf`  
> on the master node are **not automatically synchronized** to worker nodes.  
> You must manually replicate these changes and restart the nodes for them to take effect.

---

## Master node

The master node centralizes coordination and ensures that critical data remains consistent across all nodes in the cluster. Its responsibilities include:

- Receiving and managing agent registration and deletion requests
- Creating and managing shared configuration groups
- Updating custom rules, decoders, SCA policies, and CDB lists

The following data is synchronized from the master node to worker nodes:

- Agent registration information
- Shared configuration
- CDB lists
- Custom SCA policies
- Custom decoders and rules

During synchronization, any existing versions of these files on worker nodes are overwritten with the versions from the master node.

---

## Worker node

Worker nodes are responsible for:

- Redirecting agent enrollment requests to the master node
- Synchronizing shared data from the master node
- Receiving and processing events from Wazuh agents
- Sending agent status updates to the master node

If shared files are modified on a worker node, those changes are discarded during the next synchronization cycle and replaced with the master node’s version.

---

## How it works

The Wazuh server cluster is managed by the `wazuh-clusterd` daemon, which implements a master–worker architecture. All communications are initiated by worker nodes, and each worker communicates independently with the master.

Several internal threads handle different cluster operations:

- **Keep-alive thread**  
  Maintains persistent connections by sending periodic keep-alive messages from workers to the master.

- **Agent info thread**  
  Sends agent operating system details, labels, and status information. The master validates agent existence before storing updates to avoid stale data.

- **Agent groups send thread**  
  Distributes agent group assignment information to worker nodes. This data is calculated by the master when agents connect for the first time.

- **Local agent-groups thread**  
  Periodically retrieves agent group information from the database and caches it on the master to avoid redundant queries for each worker.

- **Integrity thread**  
  Synchronizes shared files from the master node to worker nodes.

- **Local integrity thread**  
  Periodically calculates file integrity using MD5 checksums and modification timestamps. This avoids recalculating integrity data for each worker connection.

All cluster logs are written to `/var/wazuh-manager/logs/cluster.log`.
