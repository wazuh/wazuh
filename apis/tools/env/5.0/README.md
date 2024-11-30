## PyServer development environment

> [!Warning]
> This is a testing environment, do not use in production.

This folder contains the development environment for the Wazuh 5.0 version. It includes the following components:

- **wazuh-manager**: Manager node.
- **wazuh-worker1**: Worker node #1.
- **wazuh-worker2**: Worker node #2.
- **wazuh-indexer**: Indexer node to persist agents information, their events, orders, etc.
- **nginx-lb**: NGINX load balancer to distribute agent connections among nodes.
- **wazuh-agent**: Agent.

> [!Note]
> The server nodes have the Wazuh Engine and the Managament and Communications API installed.

## Quickstart

Using the environment is quite simple and requires only two steps:

1. Generate the certificates used to encrypt the communication between the different nodes.
2. Start services.

### Certificates generation

To generate the certificates for the server and indexer nodes, execute:

```bash
certs/gen_certs.sh
```

You should then have the keys and certificates inside the `certs` folder

```console
wazuh@wazuh:~/wazuh/apis/tools/env/5.0$ ls -la certs/
total 12460
drwxr-xr-x 2 wazuh wazuh     4096 Nov 28 13:12 .
drwxr-xr-x 7 wazuh wazuh     4096 Nov 28 09:01 ..
-rw-r--r-- 1 wazuh wazuh      567 Nov 28 13:12 ca-config.json
-rwxr-xr-x 1 wazuh wazuh 10376657 Nov 28 13:12 cfssl
-rwxr-xr-x 1 wazuh wazuh  2277873 Nov 28 13:12 cfssljson
-rwxr-xr-x 1 wazuh wazuh     1358 Nov 28 13:12 gen_certs.sh
-rw-r--r-- 1 wazuh wazuh       16 Nov 25 15:23 .gitignore
-rw-r--r-- 1 wazuh wazuh      989 Nov 28 13:12 root-ca.csr
-rw------- 1 wazuh wazuh     1679 Nov 28 13:12 root-ca-key.pem
-rw-r--r-- 1 wazuh wazuh     1338 Nov 28 13:12 root-ca.pem
-rw-r--r-- 1 wazuh wazuh     1066 Nov 28 13:12 wazuh-indexer.csr
-rw------- 1 wazuh wazuh     1708 Nov 28 13:12 wazuh-indexer.key
-rw------- 1 wazuh wazuh     1679 Nov 28 13:12 wazuh-indexer-key.pem
-rw-r--r-- 1 wazuh wazuh     1415 Nov 28 13:12 wazuh-indexer.pem
-rw-r--r-- 1 wazuh wazuh     1066 Nov 28 13:12 wazuh-manager.csr
-rw------- 1 wazuh wazuh     1704 Nov 28 13:12 wazuh-manager.key
-rw------- 1 wazuh wazuh     1679 Nov 28 13:12 wazuh-manager-key.pem
-rw-r--r-- 1 wazuh wazuh     1415 Nov 28 13:12 wazuh-manager.pem
-rw-r--r-- 1 wazuh wazuh     1066 Nov 28 13:12 wazuh-worker1.csr
-rw------- 1 wazuh wazuh     1704 Nov 28 13:12 wazuh-worker1.key
-rw------- 1 wazuh wazuh     1675 Nov 28 13:12 wazuh-worker1-key.pem
-rw-r--r-- 1 wazuh wazuh     1415 Nov 28 13:12 wazuh-worker1.pem
-rw-r--r-- 1 wazuh wazuh     1066 Nov 28 13:12 wazuh-worker2.csr
-rw------- 1 wazuh wazuh     1704 Nov 28 13:12 wazuh-worker2.key
-rw------- 1 wazuh wazuh     1675 Nov 28 13:12 wazuh-worker2-key.pem
-rw-r--r-- 1 wazuh wazuh     1415 Nov 28 13:12 wazuh-worker2.pem
```

### Start services

To start the containers, execute

```console
docker compose up
```

> [!Note]
> This command builds the images from the compose file if they do not exist in your local system. If you want to 
> re-build an image or all images, execute `docker compose build` (use the flag `--no-cache` to build from the ground 
> up).

And that's it, you can now view the logs using `docker logs <container-name>` or log into the containers using
`docker exec -it <container-name> bash`.

## Documentation

### Ports mapping

All relevant APIs ports are mapped to the host to be able to access them without having to log into the containers.
Here are the mappings for each component:

#### Server Communications API

- 27000: Manager node
- 27001: Worker node 1
- 27002: Worker node 2

#### Server Management API

- 55000: Manager node
- 55001: Worker node 1
- 55002: Worker node 2

#### Indexer

- 9200: Indexer node
