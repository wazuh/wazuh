# Description

**Current version: 20250701-0**

This is a container for the develop wazuh-engine. It is based on the `ubuntu:20.04` image and contains all the necessary dependencies to run the engine.
To connect to the container, you can use the `ssh` service. The default user is `root` and the password is `Engine123`.
On the other hand, the container also have git and `gh cli` installed, so you can clone the repository and create a pull request.

# How to use this image

The following command supposes that you are in the directory where the `Dockerfile` is located.

## Build the image and create the container

This section will guide you through the process of building the image and creating the container.
Once the container is created, you will not require to build the image again until we update the image or `wazuh-engine`.

### Build the image

First step is to build the image. You can use the following command:

``` bash
export VERSION=20250701-0
docker buildx build -t engine-container:$VERSION . --no-cache
# Tag the image as latest to use it as the default image (recommended)
docker tag engine-container:$VERSION engine-container:latest
```

This step will take a while, as it will download all the dependencies and compile the engine.

### Check the image

To check the image, you can use the `docker images` command, you should see the `engine-container` image:

```bash
╰─# docker images
REPOSITORY                     TAG          IMAGE ID       CREATED         SIZE
engine-container               20250701-0   b29a5190594a   2 minutes ago   17.2GB
engine-container               latest       b29a5190594a   2 minutes ago   17.2GB
```

## Create the container

In order to create the container, you can use the following command:

``` bash
docker create -p 4022:22 --name engine-container engine-container:latest
```

Alternatively, you can use a specific version of the image
``` bash
export VERSION=20250701-0
docker create -p 4022:22 --name engine-container engine-container:$VERSION
```
This command will create a container named `engine-container` and will map the port `4022` of the host to the port `22` of the container. A container is created in a stopped state.

To check the status of the container, you can use the following command:

``` bash
╰─# docker ps -a
CONTAINER ID   IMAGE                     COMMAND                  CREATED          STATUS    PORTS     NAMES
e7483d68d1ac   engine-container:latest   "/usr/bin/EntryPoint…"   10 seconds ago   Created             engine-container
```

## Start the container

After creating the container, you can start it, and is not necessary to build the image again until we update the image or `wazuh-engine`.

To start the container, you can use the `docker start` command:

``` bash
docker start engine-container
```

The container will be running in the background. This container is running the `sshd` service, so you can connect to it using `ssh`, see how [connect to the container](#connect-to-the-container).
To check the status of the container, you can use the following command


You can check the status of the container using the following command:

``` bash
╰─# docker ps
CONTAINER ID   IMAGE                     COMMAND                  CREATED          STATUS         PORTS                                     NAMES
e7483d68d1ac   engine-container:latest   "/usr/bin/EntryPoint…"   39 seconds ago   Up 8 seconds   0.0.0.0:4022->22/tcp, [::]:4022->22/tcp   engine-container
```


## Connect to the container

### Connect with `ssh`


To connect to the container, you can use the `ssh` command. The default user is `root` and the password is `Engine123`. The container is listening on port `4022`, so you can use the following command:

``` bash
ssh root@localhost -p 4022
```

Also you can obtain the IP address of the container using the following command:
``` bash
docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' engine-container
```

And then you can connect to the container using the IP address:
``` bash
ssh root@<IP_ADDRESS>
```


### Connect with VSCode

You can also connect to the container using VSCode. You can use the following steps:
1. Install the `Remote - SSH` extension.
2. Click on the `Remote Explorer` icon.
3. Click `Dev Containers`
4. And then click on the `engine-container` container.
