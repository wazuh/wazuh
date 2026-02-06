## PyServer development environment

> [!Warning]
> This is a testing environment, do not use in production.

This folder contains the development environment for the Wazuh 4.x versions. It includes the following components:

- **wazuh-master**: Master node.
- **wazuh-worker1**: Worker node #1.
- **wazuh-worker2**: Worker node #2.
- **nginx-lb**: NGINX load balancer to distribute agent connections among nodes.
- **wazuh-agent**: Agent.
- **wazuh-indexer**: Indexer

### Working with docker environment
The following commands runs a cluster:
1. Run `docker compose build`
2. Run `docker compose up`

If a single docker is needed, it is possible to run:
1. Move to the dockefile location for instance:
 `cd wazuh-manager`
2. Run `docker build -t dev-wazuh-manager --target server ./wazuh-manager`
3. Define .env with the necessary environment variables
4. Run docker:
```
docker run -d \
--name wazuh-master \
--hostname wazuh-master \
-p 55000:55000 \
-v ${WAZUH_LOCAL_PATH}/framework/scripts:/var/wazuh-manager/framework/scripts \
-v ${WAZUH_LOCAL_PATH}/api/scripts:/var/wazuh-manager/api/scripts \
-v ${WAZUH_LOCAL_PATH}/framework/wazuh:/var/wazuh-manager/framework/python/lib/python${WAZUH_PYTHON_VERSION}/site-packages/wazuh \
-v ${WAZUH_LOCAL_PATH}/api/api:/var/wazuh-manager/framework/python/lib/python${WAZUH_PYTHON_VERSION}/site-packages/api \
dev-wazuh-manager \
/scripts/entrypoint.sh wazuh-master master-node master
```
If we need more agents we can use:
`docker compose up --scale wazuh-agent=<number_of_agents>`

### Troubleshooting
- Use option **-no-cache** when you have building issues.

`docker compose build --no-cache`

- To completely clean the environment (including volumes), run:
  ```bash
  docker compose down -v
  ```
