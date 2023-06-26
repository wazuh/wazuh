# Luis Chico Wazuh-Goal

This folder contains the source code and deployment files for Luis Chico Wazuh-Goal.


## Description

This repository provides a solution for the Luis Chico Wazuh-Goal. It includes a Docker Compose configuration with the following services:

- **wazuh_all_in_one**: This service builds the Wazuh manager from source and includes the Wazuh indexer and Wazuh dashboard. The entrypoint script automatically starts all the services.

- **agent**: This service runs the Wazuh agent for Linux.

- **winagent**: This service is responsible for building and generating the zipfile required by Windows to install a Wazuh agent.

- **unit_test**: This service installs the necessary dependencies for cmocka and demonstrates how to create a unit test for the EventForward function in a Wazuh client.

- **vagrant**: This directory contains the setup for running a Windows 10 VM with the agent installed using the result of the winagent service.

## Getting Started

To get started with the project, follow these steps:

1. Install Docker and Docker Compose on your machine.

2. Clone this repository to your local machine.

3. Navigate to the lc_goal directory.

4. Run the following command to start the Docker Compose environment:

'''
cd wazuh/tools/lc_goal
docker-compose -f deployment/docker-compose.yml up
'''

This will build and start the Wazuh manager, agent (linux), and other services defined in the docker-compose.yml file.

5. Once the services are up and running, you can access the Wazuh dashboard by opening a web browser and navigating to `http://10.5.0.2` (assuming the static IP 10.5.0.2/16 is assigned to the Wazuh server).

Note: You may need to wait a few moments for the services to initialize before accessing the dashboard.

## Requirements
* Docker
* Docker Compose

## Directory Structure

The directory structure of the project is as follows:
<pre>
'''
├── app
│   ├── api_agent
│   │   └── register_agent.sh
│   └── lc_cmocka_simple_test
│       ├── CMakeLists.txt
│       ├── src
│       │   ├── add.c
│       │   └── add.h
│       └── test
│           └── test_add.c
├── build
│   ├── agent
│   │   ├── build
│   │   └── Dockerfile
│   ├── agent_windows
│   │   ├── build
│   │   ├── Dockerfile
│   │   └── run
│   ├── unit_test
│   │   ├── build
│   │   ├── Dockerfile
│   │   ├── entry_point.sh
│   │   └── run
│   ├── vagrant
│   │   ├── macOS
│   │   │   └── set_macOS_ready.sh
│   │   ├── share
│   │   │   ├── get_final_state.sh
│   │   │   └── get_initial_state.sh
│   │   └── Vagrantfile
│   └── wazuh_all_in_one
│       ├── build
│       ├── Dockerfile
│       ├── entrypoint.sh
│       └── run
├── deployment
│   └── docker-compose.yml
└── README.md
'''
</pre>

