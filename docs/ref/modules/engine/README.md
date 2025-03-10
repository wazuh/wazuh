# Engine

## Introduction
The engine is responsible for transforming raw data into standardized schema documents, enriching it with threat intelligence, and forwarding it to designated destinations.

## Data flow
The data flow begins when an event enters the orchestrator and continues until it is processed by the security policy. Below is a high-level flowchart illustrating this process.

<flowchart_placeholder>

```mermaid
flowchart LR

classDef EventBoxClass font-size: 15px,stroke-width:2px, color:#fff, fill:#3f51b5

%% Router Table
subgraph routerTable["Router Table"]
  direction TB

  routeC
  routeB
  routeA


  subgraph routeA["Route prod"]
   direction LR
   policyA("Security Policy")
   filterA{"Filter"}
   filterA -.-> policyA
  end

  subgraph routeB["Route QA"]
   direction LR
   policyB("Security Policy")
   filterB{"Filter"}
   filterB -.-> policyB
  end

  subgraph routeC["Route Dev"]
   direction LR
   policyC("Security Policy")
   filterC{"Filter"}
   filterC -.-> policyC
  end
end

%% Orchestrator
subgraph orchestrator["Orchestrator (Simplified)"]
  direction LR
  %% Router Table

  routeSelector("Route</br>selector")
  routerTable
end


%% Routes
eventA@{ shape: doc, label: "Incoming</br>event" }
eventA:::EventBoxClass
eventA-->routeSelector
routeSelector-.->filterA & filterB & filterC


```

To understand how the engine is structured, it's important to identify the key components involved in this process. When a new event arrives, the engine directs it to different policies for processing. The orchestrator manages these policies at runtime.

The orchestrator routes events to a policy and is composed of the following elements:
- Route: Identifies the events that must be processed by a specific Policy.
- Policy: Processes the events.
- Priority: Determines the order in which the orchestrator attempt to route events.

A policy defines the processing pipeline of the events and is composed of:
- Decoders: Normalize and extract information from the events into a common schema.
- Rules: Analyze security threats (primarily IoCs) and enrich the events.
- Outputs: Send normalized and enriched events to the indexer and other defined outputs.

Each policy can be tailored to specific use cases.

<flowchart_placeholder>


```mermaid
---
title: Security policy dataflow
---
flowchart LR

classDef EventBoxClass font-size: 15px,stroke-width:2px, color:#fff, fill:#3f51b5
classDef TreeBoxClass font-size: 15px,stroke-width:2px,stroke-dasharray: 5 5

 subgraph decoTree["Decoders"]
  direction TB

  deco01(" ")
  deco02(" ")
  deco03(" ")
  deco04(" ")
  deco05(" ")
  deco06(" ")
  deco07(" ")
  deco08(" ")

  deco01 --> deco02 & deco03 & deco04
  deco02 --> deco05
  deco03 --> deco06 & deco07
  deco04 --> deco08
 end

 subgraph ruleTree["Rules"]
  direction TB

  rule01(" ")
  rule02(" ")
  rule03(" ")
  rule04(" ")
  rule05(" ")
  rule06(" ")
  rule07(" ")
  rule08(" ")

  rule01 --> rule02 & rule03 & rule04
  rule02 --> rule05
  rule03 --> rule06 & rule07
  rule04 --> rule08
 end

 subgraph outputTree["Outputs"]
  direction TB

  output01(" ")
  output02(" ")
  output03(" ")
  output04(" ")
  output05(" ")
  output06(" ")
  output07(" ")
  output08(" ")

  output01 --> output02 & output03 & output04
  output02 --> output05
  output03 --> output06 & output07
  output04 --> output08

 end

 decoTree:::TreeBoxClass
 ruleTree:::TreeBoxClass
 outputTree:::TreeBoxClass
 eventInput:::EventBoxClass
 eventOutput:::EventBoxClass

 %% Pipeline
 eventInput@{shape: doc, label: "Event</br>Input"}==>decoTree==>ruleTree==>outputTree==>eventOutput@{shape: doc, label: "Enriched</br>Event"}



```

### Event
The purpose of the Engine is to convert unstructured or semi-structured logs into normalized and enriched events. The agent transmits logs within a JSON payload, which includes additional metadata such as OS information, log source, and other relevant details. The Engine processes these logs and generates a structured JSON event, incorporating all relevant information in accordance with the defined [schema](#).

Input event example:
```json
{
  "@timestamp": "2025-01-23T17:40:37Z",
  "agent": {
    "groups": [
      "group1",
      "group2"
    ],
    "host": {
      "architecture": "x86_64",
      "hostname": "wazuh-endpoint-linux",
      "ip": [
        "192.168.1.2"
      ],
      "os": {
        "name": "Amazon Linux 2",
        "platform": "Linux"
      }
    },
    "id": "2887e1cf-9bf2-431a-b066-a46860080f56",
    "name": "wazuh-agent-name",
    "type": "endpoint",
    "version": "5.0.0"
  },
  "event": {
    "collector": "file",
    "module": "logcollector",
    "original": "Dec 13 11:35:28 a-mac-with-esc-key GoogleSoftwareUpdateAgent[21412]: 2016-12-13 11:35:28.421 GoogleSoftwareUpdateAgent[21412/0x700007399000] [lvl=2] -[KSUpdateEngine updateAllExceptProduct:] KSUpdateEngine updating all installed products, except:'com.google.Keystone'."
  },
  "log": {
    "file": {
      "path": "/var/log/syslog.log"
    }
  },
}
```

Processed event:
```json
{
  "@timestamp": "2025-01-23T17:40:37Z",
  "agent": {
    "groups": [
      "group1",
      "group2"
    ],
    "host": {
      "architecture": "x86_64",
      "hostname": "wazuh-endpoint-linux",
      "ip": [
        "192.168.1.2"
      ],
      "os": {
        "name": "Amazon Linux 2",
        "platform": "Linux"
      }
    },
    "id": "2887e1cf-9bf2-431a-b066-a46860080f56",
    "name": "wazuh-agent-name",
    "type": "endpoint",
    "version": "5.0.0"
  },
  "event": {
    "collector": "file",
    "created": "2024-11-22T02:00:00Z",
    "kind": "event",
    "module": "logcollector",
    "original": "Dec 13 11:35:28 a-mac-with-esc-key GoogleSoftwareUpdateAgent[21412]: 2016-12-13 11:35:28.421 GoogleSoftwareUpdateAgent[21412/0x700007399000] [lvl=2] -[KSUpdateEngine updateAllExceptProduct:] KSUpdateEngine updating all installed products, except:'com.google.Keystone'.",
    "start": "2025-12-13T11:35:28.000Z"
  },
  "host": {
    "hostname": "a-mac-with-esc-key"
  },
  "log": {
    "file": {
      "path": "/var/log/syslog.log"
    }
  },
  "message": "2016-12-13 11:35:28.421 GoogleSoftwareUpdateAgent[21412/0x700007399000] [lvl=2] -[KSUpdateEngine updateAllExceptProduct:] KSUpdateEngine updating all installed products, except:'com.google.Keystone'.",
  "process": {
    "name": "GoogleSoftwareUpdateAgent",
    "pid": 21412
  },
  "related": {
    "hosts": [
      "a-mac-with-esc-key"
    ]
  },
  "tags": [
    "production-server"
  ],
  "wazuh": {
    "decoders": [
      "syslog"
    ]
  }
}
```

### Policy processing
The policy is the operational graph applied to each event, structured into decoders, rules, and outputs, each related to normalizing, enriching, and delivery respectively.

<flowchart_placeholder>

Wazuh comes with a predefined policy that enables all its components to work properly and it is structured on top of Wazuh-supported log sources.

Each source does have a particular way to format and send logs to the engine. The default policy takes care of that, allowing the users to focus on their integrations and not on the nuances of the logs transports for each source.

<flowchart_placeholder>

### Decoding process
The decoding process converts unstructured data received by the engine into schema-based JSON events.

All events enter the pipeline through the root decoder, which determines the appropriate decoder for processing. Each subsequent decoder processes the event as much as possible before passing it to the next suitable decoder. This continues until no further processing can be performed.

A closer examination of the predefined decoders reveals the following structure:

<flowchart_placeholder>

```mermaid
flowchart TD

%% Style
classDef AssetSuccessClass fill:#2196f3,stroke-width:2px,fill-opacity:0.8
classDef AssetFailClass fill:#f50057,stroke-width:2px,fill-opacity:0.8
classDef AssetNotExecutedClass fill:#90a4ae,stroke-width:2px,fill-opacity:0.8


%% First Level
decoderR("root decoder"):::AssetSuccessClass
decoderR --x decoder1
decoderR --> decoder2 --> decoder21
decoderR -.-> decoder3 -.-> decoder31

decoder1("decoder 1"):::AssetFailClass
decoder2("decoder 2"):::AssetSuccessClass

decoder1 -.-> decoder11 & decoder12
decoder2 -.-> decoder22

decoder11("decoder 1-1"):::AssetNotExecutedClass
decoder12("decoder 1-2"):::AssetNotExecutedClass
decoder21("decoder 2-1"):::AssetSuccessClass
decoder22("decoder 2-2"):::AssetNotExecutedClass
decoder3("decoder 3"):::AssetNotExecutedClass
decoder31("decoder 3-1"):::AssetNotExecutedClass
linkStyle 0 stroke:#f50057,stroke-width:2px



```

### Security enrichment process
The analysis process evaluates all event fields to identify security concerns, represented as threat indicators within the common schema. These indicators are later examined in the Wazuh Indexer for threat hunting and security issue detection.

All decoded events pass through the analysis pipeline, where the root rule determines the next appropriate rule for processing. This continues until no further rules can be applied. Unlike decoding, a rule can trigger multiple subsequent rules, each contributing to the event's analysis by adding relevant threat indicators.

A closer look at the predefined rules reveals the following structure:

<flowchart_placeholder>
```mermaid
flowchart TD

%% Style
  classDef AssetSuccessClass fill:#2196f3,stroke-width:2px,fill-opacity:0.8
  classDef AssetFailClass fill:#f50057,stroke-width:2px,fill-opacity:0.8
  classDef AssetNotExecutedClass fill:#90a4ae,stroke-width:2px,fill-opacity:0.8
  ruleR("root rule (geo)") --x rule1("rule 1")
  rule1 -.-> rule11("rule 1-1") & rule12("rule 1-2")
  ruleR --> rule2("rule 2")
  rule2 --> rule21("rule 2-1")
  rule2 --x rule22("rule 2-2")
  rule2 --> rule23("rule 2-3")
  ruleR --> rule3("rule 3")
  rule3 --> rule31("rule 3-1")

  ruleR:::AssetSuccessClass
  rule1:::AssetFailClass
  rule11:::AssetNotExecutedClass
  rule12:::AssetNotExecutedClass
  rule2:::AssetSuccessClass
  rule21:::AssetSuccessClass
  rule22:::AssetFailClass
  rule23:::AssetSuccessClass
  rule3:::AssetSuccessClass
  rule31:::AssetSuccessClass
  linkStyle 0,5 stroke:#f50057,stroke-width:2px


```

### Archiving and alerting process
Once an event has completed processing through the decoder and rule pipelines, it enters the output pipeline. Similar to previous stages, the event first passes through the root output, which determines the appropriate output(s) for further processing. Multiple outputs can be selected, enabling flexible storage and distribution policies.

The output process in Wazuh is designed to efficiently distribute alerts through broadcasting, with each output capable of filtering alerts to support customized distribution:


### Asset processing
- Adding an asset architecture diagram, parts and asset chain op execution tree
- basic explanation of assets in general


#### Decoder Asset
Some specialization of the asset as decoder

#### Filter Asset

Some specialization of the asset as filter, like for example the `filter`  cannot parser or map fields.

#### Rules Asset
Some specialization of the asset as rules, i.e. Cannot parser o map outside of schema.

#### Outputs Asset

## How it work

### Definitions

### Parsers

Explanation of how parsers work

- link to new document inside this module with all parsers

### Helper funntions

Explanation of how herlper work, format, types, etc.

- link to new document inside this module with all helpers functions

### Variables

I think we should eliminate this concept

### Schemas

what is each one used for and what is the format

#### Wazuh Schema + Custom Schema

#### Logpar override Schema

#### Others schemas


## Catalog

intro + api catalog link

### Nampeaces

### Integrations


## Event processing

Protocol, log, etc.


## Metrics

How metrics are generated and how they are used

I think we should leave this short until future definitions.

## Queues

I think we should leave this empty until future definitions.

## Time Zones

## GEOIP

## KVDB
I think we should leave this empty until future definitions.


## Tester

How testing work in orchestrator

### Sessions

### Traces and logs
