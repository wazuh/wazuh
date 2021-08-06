<!---
Copyright (C) 2015-2021, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: Google Cloud
## Index
1. [Purpose](#purpose)
2. [Sequence diagram](#sequence-diagram)

## Purpose
The Google Cloud Module is in charge of requests events to the Google Cloud API and deals with them. The module get the events from a Google Cloud subscription that is specified in the configuration file.

This module, use a python script to request the events from the Google Cloud API, give them the format required and send them to the AgentD.

## Sequence diagram
Sequence diagram shows the basic flow of Google Cloud Module. Steps are:
1. Get the parameters from the config file to setup the module.
2. Send the parameters to the script that will deal with the events of the Google Cloud API.
3. Request the events from the Google Cloud API.
4. Once the events are receive, the script give format to each of the events.
5. Send the events to the AgentD
6. If we receive less events than the maximum number of events request, it do anothe request to the Google Cloud API for more events
