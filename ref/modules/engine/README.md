# Engine

## Introduction
The engine is responsible for transforming raw data into standardized schema documents, enriching it with threat intelligence, and forwarding it to designated destinations.

## Data flow
The data flow begins when an event enters the orchestrator and continues until it is processed by the security policy. Below is a high-level flowchart illustrating this process.


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

Wazuh comes with a predefined policy that enables all its components to work properly and it is structured on top of Wazuh-supported log sources.

Each source does have a particular way to format and send logs to the engine. The default policy takes care of that, allowing the users to focus on their integrations and not on the nuances of the logs transports for each source.

<flowchart_placeholder>  // TODO Agent or endpoint (like syslog client, aws s3) to engine dataflow

### Decoding process
The decoding process converts unstructured data received by the engine into schema-based JSON events.

All events enter the pipeline through the root decoder, which determines the appropriate decoder for processing. Each subsequent decoder processes the event as much as possible before passing it to the next suitable decoder. This continues until no further processing can be performed.

A closer examination of the predefined decoders reveals the following structure:


```mermaid
---
title: Decoder tree
---
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

The event is evaluated by a decoder to determine if it matches the conditions defined within the decoder. If the decoder rejects the event, it is passed to the next sibling decoder within the same hierarchy for evaluation. This process continues until a decoder accepts the event or no more sibling decoders are available.

When a decoder accepts an event, it may modify the event by normalizing or enriching its data. After this, the event is passed to the child decoders of the accepted decoder for further processing. Each child decoder evaluates the event using the same logic, ensuring a hierarchical and iterative approach to event processing.

This hierarchical evaluation ensures that events are processed efficiently and routed through the appropriate decoders based on their structure and content.

The following diagram illustrates the event flow on the decoder tree of default policy:

```mermaid
---
title: Event flow on decoder tree
---
flowchart LR

 classDef EventBoxClass font-size: 15px,stroke-width:2px, color:#fff, fill:#3f51b5
 classDef TreeBoxClass font-size: 15px,stroke-width:2px,stroke-dasharray: 5 5

 subgraph decoTree["First layer - Internal decoders"]
    direction TB
    deco01(" ")
    deco02(" ")
    deco03(" ")
    deco04("Integration Decoder")
    deco05(" ")
    deco06(" ")
    deco07(" ")

    deco01 --> deco02 & deco03 & deco04
    deco02 --> deco05
    deco03 --> deco06 & deco07
  end

  deco04 -..-> decoIntegration["Integration Decoder"]:::TreeBoxClass
  eventInput@{shape: doc, label: "Event</br>Input"} ==> decoTree
  decoTree:::TreeBoxClass

 subgraph userDecoTree["Integrations & User decoders"]
    direction TB
    userDeco01(" ")
    userDeco02(" ")
    userDeco03(" ")
    userDeco04(" ")
    userDeco05(" ")
    userDeco06(" ")
    userDeco07(" ")
    userDeco08(" ")

    userDeco01 --> userDeco02 & userDeco03 & userDeco04
    userDeco02 --> userDeco05
    userDeco03 --> userDeco06 & userDeco07
    userDeco04 --> userDeco08
  end



%% decoIntegration --> userDecoTree
decoIntegration --> userDeco01
userDecoTree ----> eventOutput@{shape: doc, label: "Normalized</br>event"}

userDecoTree:::TreeBoxClass
eventInput:::EventBoxClass
eventOutput:::EventBoxClass
```

In the default policy, the first layer is for internal decoders, which are responsible for normalizing events.
The second layer is for integrations and user-defined decoders, which are used to process events from specific
sources or applications.

### Security enrichment process
The analysis process evaluates all event fields to identify potential security concerns, which are represented as threat
indicators within the common schema. These indicators are later stored in the Wazuh Indexer, where they can be used for
threat hunting and detecting security issues.

All decoded events pass through the analysis pipeline, starting with the root rule. The root rule determines the next
appropriate rule for processing the event. If a rule matches, it triggers all its child rules for evaluation in a
broadcast manner. Each child rule is independently evaluated, contributing additional threat indicators to the event's
analysis. If a rule does not match, its child rules are not evaluated, ensuring efficient processing.

This hierarchical and broadcast-based evaluation allows the analysis pipeline to enrich events with relevant security
context while maintaining performance and scalability.


```mermaid
---
title: Rules tree
---
flowchart TD

%% Style
  classDef AssetSuccessClass fill:#2196f3,stroke-width:2px,fill-opacity:0.8
  classDef AssetFailClass fill:#f50057,stroke-width:2px,fill-opacity:0.8
  classDef AssetNotExecutedClass fill:#90a4ae,stroke-width:2px,fill-opacity:0.8
  ruleR("root rule") --x rule1("rule 1")
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

The following diagram illustrates the event flow on the rules tree of the default policy:

```mermaid
---
title: Event flow on rules
---
flowchart LR

classDef EventBoxClass font-size: 15px,stroke-width:2px, color:#fff, fill:#3f51b5
classDef TreeBoxClass font-size: 15px,stroke-width:2px,stroke-dasharray: 5 5

 subgraph firstLayerRulesTree["First layer: Geo enrichment"]
  direction TB

  firstLayerRules01(" ")
  firstLayerRules02(" ")
  firstLayerRules03(" ")
  firstLayerRules04(" ")
  firstLayerRules05(" ")
  firstLayerRules06(" ")
  firstLayerRules07(" ")
  firstLayerRules08(" ")

  firstLayerRules01 --> firstLayerRules02 & firstLayerRules03 & firstLayerRules04
  firstLayerRules02 --> firstLayerRules05
  firstLayerRules03 --> firstLayerRules06 & firstLayerRules07
  firstLayerRules04 --> firstLayerRules08
 end

 subgraph wazuhRulesTree["Wazuh Rules"]
  direction TB

  wazuhRules01(" ")
  wazuhRules02(" ")
  wazuhRules03(" ")
  wazuhRules04(" ")
  wazuhRules05(" ")
  wazuhRules06(" ")
  wazuhRules07(" ")
  wazuhRules08(" ")

  wazuhRules01 --> wazuhRules02 & wazuhRules03 & wazuhRules04
  wazuhRules02 --> wazuhRules05
  wazuhRules03 --> wazuhRules06 & wazuhRules07
  wazuhRules04 --> wazuhRules08
 end

 subgraph userRulesTree["User rules"]
  direction TB

  userRules01(" ")
  userRules02(" ")
  userRules03(" ")
  userRules04(" ")
  userRules05(" ")
  userRules06(" ")
  userRules07(" ")
  userRules08(" ")

  userRules01 --> userRules02 & userRules03 & userRules04
  userRules02 --> userRules05
  userRules03 --> userRules06 & userRules07
  userRules04 --> userRules08

 end

 firstLayerRulesTree:::TreeBoxClass
 wazuhRulesTree:::TreeBoxClass
 userRulesTree:::TreeBoxClass
 eventInput:::EventBoxClass
 eventOutput:::EventBoxClass

 %% Pipeline
 eventInput@{shape: doc, label: "Normalized</br>Event"}==>firstLayerRulesTree==>wazuhRulesTree & userRulesTree-.->eventOutput@{shape: doc, label: "Security</br>event"}

```

The analysis pipeline is divided into three layers:

- **First layer**: Responsible for geo-enrichment and general IoCs.
- **Wazuh Rules**: Contains the default rules provided by Wazuh.
- **User Rules**: Contains user-defined rules.

The event always starts at the first layer, where it is enriched with geo-location information and general IoCs.
Then both the Wazuh and user rules are applied to the event.


### Archiving and alerting process

Once an event has completed processing through the decoder and rule pipelines, it enters the output pipeline.
Similar to previous stages, the event first passes through the root output, which determines the appropriate output(s)
for further processing. Multiple outputs can be selected, enabling flexible storage and distribution policies.

The output process in Wazuh is designed to efficiently distribute alerts through broadcasting, with each output capable
of filtering alerts to support customized distribution:

```mermaid
---
title: Event flow on outputs
---
flowchart TD

    outputR --> output1("Indexer alert output") & output2("File alerts output")
    outputR("Broadcaster output") --x output3("File archive output")
    outputR("Broadcaster output") --x output4("Other output")

     outputR:::AssetSuccessClass
     output1:::AssetSuccessClass
     output2:::AssetSuccessClass
     output3:::AssetFailClass
     output4:::AssetSuccessClass
    classDef AssetSuccessClass fill:#3f51b5,stroke-width:2px,fill-opacity:0.5
    classDef AssetFailClass fill:#f44336,stroke-width:2px,fill-opacity:0.5
    classDef AssetNotExecutedClass fill:#9e9e9e,stroke-width:2px,fill-opacity:0.5
    linkStyle 2 stroke:#D50000,fill:none
```


### Full pipeline

The following diagram illustrates the full pipeline of the default policy, including the decoding, rule, and output
stages:

```mermaid
flowchart TD

 classDef EventBoxClass font-size: 15px,stroke-width:2px, color:#fff, fill:#3f51b5
 classDef TreeBoxClass font-size: 15px,stroke-width:2px,stroke-dasharray: 5 5
 classDef ModuleArchClass fill:#673ab7,stroke-width:2px,fill-opacity:0.5, font-size: 20px
 classDef SubModuleArchClass fill:#673ab7,stroke-width:2px,fill-opacity:0.5, font-size: 15px

%% --------------------------------------
%%           Decoding Stage
%% --------------------------------------

 subgraph decoTree["First layer - Internal decoders"]
    direction TB
    decoInputRoot(" ")
    deco02(" ")
    deco03(" ")
    integrationDecoder("Integration Decoder")
    deco05(" ")
    deco06(" ")
    deco07(" ")

    decoInputRoot --> deco02 & deco03 & integrationDecoder
    deco02 --> deco05
    deco03 --> deco06 & deco07
  end

  integrationDecoder -..-> userDecoRoot:::TreeBoxClass


 subgraph userDecoTree["Integrations & User decoders"]
    direction TB
    userDecoRoot(" ")
    userDeco02(" ")
    userDeco03(" ")
    userDeco04(" ")
    userDeco05(" ")
    userDeco06(" ")
    userDeco07(" ")
    userDeco08(" ")

    userDecoRoot --> userDeco02 & userDeco03 & userDeco04
    userDeco02 --> userDeco05
    userDeco03 --> userDeco06 & userDeco07
    userDeco04 --> userDeco08
  end

%% Stage block
subgraph decoderStage["Decoding Stage"]
    decoTree:::TreeBoxClass
    userDecoTree:::TreeBoxClass
end



%% Output decoder stage
eventNormalized@{shape: doc, label: "Normalized</br>event"}
eventNormalized:::EventBoxClass

%% Pipieline
routeSelector ==> decoInputRoot
userDecoTree ====> eventNormalized

%% --------------------------------------
%%           Rules Stage
%% --------------------------------------

subgraph firstLayerRulesTree["First layer Rules:</br>Geo enrichment</br>General IoCs"]
  direction TB

  firstLayerRules01(" ")
  firstLayerRules02(" ")
  firstLayerRules03(" ")
  firstLayerRules04(" ")
  firstLayerRules05(" ")
  firstLayerRules06(" ")
  firstLayerRules07(" ")
  firstLayerRules08(" ")

  firstLayerRules01 --> firstLayerRules02 & firstLayerRules03 & firstLayerRules04
  firstLayerRules02 --> firstLayerRules05
  firstLayerRules03 --> firstLayerRules06 & firstLayerRules07
  firstLayerRules04 --> firstLayerRules08
 end

 subgraph wazuhRulesTree["Wazuh Rules"]
  direction TB

  wazuhRules01(" ")
  wazuhRules02(" ")
  wazuhRules03(" ")
  wazuhRules04(" ")
  wazuhRules05(" ")
  wazuhRules06(" ")
  wazuhRules07(" ")
  wazuhRules08(" ")

  wazuhRules01 --> wazuhRules02 & wazuhRules03 & wazuhRules04
  wazuhRules02 --> wazuhRules05
  wazuhRules03 --> wazuhRules06 & wazuhRules07
  wazuhRules04 --> wazuhRules08
 end

 subgraph userRulesTree["User rules"]
  direction TB

  userRules01(" ")
  userRules02(" ")
  userRules03(" ")
  userRules04(" ")
  userRules05(" ")
  userRules06(" ")
  userRules07(" ")
  userRules08(" ")

  userRules01 --> userRules02 & userRules03 & userRules04
  userRules02 --> userRules05
  userRules03 --> userRules06 & userRules07
  userRules04 --> userRules08

 end



subgraph ruleStage["Rules Stage"]
 firstLayerRulesTree:::TreeBoxClass
 wazuhRulesTree:::TreeBoxClass
 userRulesTree:::TreeBoxClass
end

%% Output stage rules
securityEvent@{shape: doc, label: "Security</br>event"}
securityEvent:::EventBoxClass

%% Pipieline
eventNormalized==>firstLayerRulesTree==>wazuhRulesTree & userRulesTree-.->securityEvent

%% --------------------------------------
%%           Output Stage
%% --------------------------------------
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
 outputTree:::TreeBoxClass

%% Pipieline output
 securityEvent ==> outputTree


%% --------------------------------------
%%           Default Policy
%% --------------------------------------
subgraph defaultPolicy["Default policy"]
  decoderStage
  eventNormalized
  ruleStage
  securityEvent
  outputTree
end
defaultPolicy:::SubModuleArchClass


%% --------------------------------------
%%           Engine
%% --------------------------------------
%% Input Decodeing Stage
eventInput@{shape: doc, label: "Incoming event</br>from endpoint"}
eventInput:::EventBoxClass

subgraph engine["engine"]
  defaultPolicy
  routeSelector(["Orchestrator: Router (Route selector)"])
end
engine:::ModuleArchClass

eventInput ===> routeSelector

```



## Schema

A schema defines a structured format for data, ensuring consistency, interoperability, and efficient querying. It establishes a common set of field names, data types, and relationships that standardize log and event data across different sources.

The Engine ensures that all operations—parsing, normalization, and enrichment—aim to transform unstructured data into structured data that adheres to the schema. This structured approach enhances data integrity, improves search performance, and enables seamless correlation across multiple data sources.

- Consistency: Standardized field names prevent discrepancies when integrating data from different sources.
- Interoperability: Facilitates integration with various tools and analytics platforms.
- Efficient Querying: Optimizes indexing and search performance.
- Data Enrichment: Enables meaningful correlations by aligning logs with predefined categories (e.g., network, process, user activity).

For example, a network event log structured according to the schema might look like this:
```json
{
  "event": {
    "category": "network",
    "type": "connection",
    "action": "network_connection"
  },
  "source": {
    "ip": "192.168.1.10",
    "port": 443
  },
  "destination": {
    "ip": "10.0.0.5",
    "port": 8080
  },
  "user": {
    "name": "admin"
  }
}
```

### Configuration
The schema configuration for the engine follows a structured format where each field is defined with specific attributes. The schema consists of a JSON object with the following key elements:

- Fields Definition:
  - The fields object contains a list of field names as keys.
  - Each field has a corresponding object defining its properties.
- Field Properties:
  Each field in the schema contains two primary properties:
  - `type`: Specifies the OpenSearch field type, such as date, keyword, text, integer, etc.
  - `array`: A boolean value (true or false) indicating whether the field can store multiple values (i.e., an array) or just a single value.

```json
{
  "name": "schema/engine-schema/0",
  "fields": {
    "@timestamp": {
      "type": "date",
      "array": false
    },
    "agent.build.original": {
      "type": "keyword",
      "array": false
    },
    "agent.ephemeral_id": {
      "type": "keyword",
      "array": false
    },
    "agent.id": {
      "type": "keyword",
      "array": false
    }
  }
}
```

### Implications
- Operational Graph and Consistency Enforcement
  - The schema is used during the construction of the operational graph to ensure that all operations are valid based on the defined field types and structures.
  - Whenever possible, schema validation is performed at build time to prevent misconfigurations before execution.
  - If an operation's consistency cannot be fully validated at build time, additional runtime checks are applied to ensure adherence to the schema.
- Consistency and Normalization in Dashboards
  - The schema ensures that data displayed in dashboards follows a consistent structure.
  - This enables seamless aggregation, filtering, and visualization by maintaining a predictable and normalized data format.

## Managing the Engine's processing
Now that we've explored what the Engine does and how its processing works, we’ll introduce key elements involved in managing and defining the operational graph—specifically, routes, policies, and assets.

All management is performed through the API (refer to the API documentation for a complete list of available calls). Before defining the operational graph, all policies and assets must first be loaded into the Engine’s catalog. This ensures that all assets are validated and ready for use before they are referenced in processing.

### Namespaces
To organize assets efficiently, the Engine categorizes them into namespaces. Internally, assets are stored directly under a specific namespace, allowing for structured management and role-based segregation of policies.

The default policy asset namespaces in the Engine are:
- `system` – Core assets responsible for handling internal event processing and ensuring basic event normalization.
- `wazuh` – Default integrations developed and maintained by Wazuh.
- `user` – A default namespace for end-user-defined assets.

While these are the predefined namespaces, the Engine allows creating as many namespaces as needed, enabling flexibility in asset management.

### Assets Catalog

The Catalog is responsible for managing the Engine’s assets, organizing them under namespaces. Each asset is uniquely identified by its name, following the convention:
```
<type>/<name>/<version>
```

This naming structure ensures clear versioning and categorization of assets. The following asset types are defined:
- **decoders** – Responsible for normalizing events, transforming raw data into a structured format.
- **rules** – Handle security analysis and event enrichment, identifying threats and adding contextual information.
- **outputs** – Define storage policies for processed events, determining how and where data is stored.
- **filters** – Used for event routing, ensuring events are correctly directed to the appropriate policies.
- **integrations** – Serve as manifests for other assets, grouping related assets that support a common goal. Typically used to bundle all assets required for specific services.

All API calls to the Catalog support name-path operations, allowing users to manage specific assets or entire groups efficiently. (Refer to the API documentation for a full list of available catalog operations.)

### Policies and Routes

With all assets defined and stored in the Catalog, the next step is to define policies, specifying exactly what functionality we want to apply. A policy organizes assets hierarchically, defining how events are processed.

The API allows users to configure all decoders, rules, and outputs for a policy, along with default management settings—such as defining default asset parents for specific namespaces. (For a complete list of API calls, refer to the documentation.)

Each policy contains references to asset names, and during the building process, the Engine retrieves these assets from the Catalog. The graph is then built following the parent relationships defined in the assets, ensuring a valid structure. If the relationships are invalid or incomplete, the build process will fail, preventing misconfigurations.

Following the same Catalog-first approach, policies are stored before they are actually used. Policies are only referenced when defining routes, ensuring that all assets and relationships are pre-validated before execution.

The Orchestrator is responsible for pairing filters with policies, ensuring that specific types of events are processed by the appropriate policies. It also manages loaded policies, routing priority and some event processing configuration.

The Engine also introduces the concept of testing sessions, which are specialized policies designed for processing test events via the API. These sessions allow users to validate how their policies will behave before deploying them in production, ensuring correctness and expected functionality.

For a complete list of API calls related to routing and policy management, refer to the documentation.

#### Architecture

The Engine is composed of distinct modules, each responsible for managing a specific aspect of event processing:
- Catalog → Manages assets (decoders, rules, filters, outputs, integrations).
- Policy → Manages policies, defining how assets are organized and processed.
- Orchestrator → Manages routes, pairing filters with policies to control event processing.

All modules follow the same naming convention, ensuring that every item—whether an asset, policy, or route—can be stored and identified homogeneously by the Store module.

For more information on the Engine’s architecture and how the modules interact, refer to [architecture documentation](architecture.md).

## Assets
In the Wazuh Engine, assets represent the fundamental components of security policies and are the smallest unit within such a policy.

Each asset is organized into various stages that dictate operational procedures when processing an event. These stages provide a structured and semantically meaningful sequence of operations, enhancing the engine's capability to execute these operations efficiently based on predefined execution strategies.

Do not confuse stages with attributes, which are configuration details and metadata about the asset.


```mermaid
---
config:
  nodeSpacing: 30
  rankSpacing: 25
  flowchart:
    subGraphTitleMargin:
      top: 20
      bottom: 20
---
flowchart TB


classDef AssetsClass fill:#3f51b5,stroke-width:2px,fill-opacity:0.5, font-size: 20px, min-width:350px
classDef partsAssetsClass font-size:15px,stroke-width:2px,stroke-dasharray:10px,rx:15,ry:15, min-width:250px
classDef AttributesClass min-width: 200px

 subgraph assetSchema["Asset Schema"]
    direction TB
    attributes:::partsAssetsClass ~~~ stages:::partsAssetsClass
 end
 assetSchema:::AssetsClass

 subgraph attributes["Attributes"]
    direction LR
    attr_1(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
    attr_2(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
    attr_3(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
    attr_4(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
  end

 subgraph stages["Stages"]
    direction LR
    stage_1(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
    stage_2(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
    stage_3(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
    stage_4(["&emsp;&emsp;&emsp;&emsp;&emsp;...&emsp;&emsp;&emsp;&emsp;&emsp;"]):::AttributesClass
  end


```

### Attributes
Attributes are configuration details. Although the order of definition does not matter, we follow the convention of defining them in the order of name, metadata, and parents.
- **Name**: Identifies the asset and follows the pattern `<asset_type>/<name>/<version>`.
- **Metadata**: Contains all information about the asset. The exact subfields depend on the asset type.
- **Parents**: When applicable to the asset, this defines the order in the asset graph. The exact child selection depends on the specific asset graph type.
- **Definitions**: Defines symbols that will be replaced throughout the document in its occurrences.

### Stages
The stages define the operation chain and flow the asset performs on events. Each stage is executed in the order of definition:



```mermaid
---
config:
  nodeSpacing: 30
  rankSpacing: 25
  flowchart:
    subGraphTitleMargin:
      top: 20
      bottom: 20
---
flowchart TB

classDef partsAssetsClass font-size:15px,stroke-width:2px,stroke-dasharray:10px,rx:15,ry:15
classDef EventBoxClass font-size: 15px,stroke-width:2px, color:#fff, fill:#3f51b5
classDef stateFailClass fill:#f50057,stroke-width:2px,fill-opacity:0.5
classDef stateSuccessClass fill:#2196f3,stroke-width:2px,fill-opacity:0.8

eventInput@{ shape: doc, label: "Event input"}
eventInput:::EventBoxClass
eventInput ---> stage_1


subgraph stages["Stages"]
   direction TB
   stage_1(["Process stage 1"])
   stage_2(["Process stage 2"])
   stage_3(["Process stage ..."])
   stage_4(["Process stage n"])
   stage_1 --->|success| stage_2
   stage_2 --->|success| stage_3
   stage_3 --->|success| stage_4
end
stages:::partsAssetsClass

failedState@{ shape: dbl-circ, label: "Asset fail" }
failedState:::stateFailClass
stage_1 --->|failed|failedState
stage_2 --->|failed|failedState
stage_3 --->|failed|failedState

successState@{ shape: dbl-circ, label: "Asset success" }
successState:::stateSuccessClass
stage_4 --->|success| successState
```

When a stage is executed, it can either fail or succeed, depending on the logic of the stage and the operations performed. Each stage is sequentially executed only if the previous stage succeeds.

Stages:
- **Check/Allow**: Allows conditional operations to be made on the event. Cannot modify the event.
- **Parse**: Parses fields on the event, acting both as a condition and normalization.
- **Map**: Allows mapping and transformation operations on the event.
- **Normalize**: Defines blocks with a combination of check, parse, and map stages.
- **Output**: Allows operations to communicate outside the Engine, typically used to send events outward. Cannot modify the event.

### Asset types
The type of asset is an allowed combination of certain stages. The following table outlines the stages available for each type of asset:

| Asset Type | Allowed Stages |
|-|-|
|Decoders|check, parse, map, normalize|
|Rules|check, map, normalize_rule|
|Outputs|check, output|
|Filters|allow|

Each asset has a name and metadata, with custom metadata suited to its specific needs. Additionally, each asset can have parents.

### Operations
Operations are the fundamental units within the operation graph. Each operation can succeed or fail, forming the basis for defining the graph by combining operations based on their execution results.

Operations are always defined as:
```yaml
target_field: operation
```

Where the operation can be:
- **Literal Value**: A direct check or map operation depending on the stage it is defined. This can be any of the YAML native values (string, number, boolean, etc.).
- **Reference**: Denoted by $field_name, it performs a direct check or map operation using the referenced value.
- **Helper Function**: Denoted by helper_name(args), it performs a check or map operation depending on the called helper.

When building an asset, the process can fail if there is any operation that contains a:
- **Syntax Error**: Errors in the target_field or operation syntax.
- **Schema Validation Failure**: Errors such as mapping a boolean into a keyword field, which violates the schema validation rules.
- **Semantic Error**: Incorrect usage, such as using a conditional helper in a map stage.
These errors will be notified when trying to upload the asset to the catalog.

### Execution Graph Summary
With a basic understanding of a policy and its components, we can look at the global picture of how the operation graph is defined.
Within the policy, we have subgraphs, each corresponding to an asset type:
- Decoders
- Rules
- Outputs

<workflow_placeholder>

Every event traverses each subgraph independently, forming a chain of subgraphs.

Each graph is composed of assets defined by parent relationships. An event moves down in the graph based on the asset's logical output. If an asset operation succeeds, the event is sent to its child assets.

The traversal of each subgraph follows these rules:
- **Decoders**: If the current decoder asset succeeds, the event is sent to its first child. If it fails, the event is sent to the next sibling of the parent decoder (logical OR between children).
- **Rules**: If the current rule asset succeeds, the event is broadcast to all its child assets.
- **Outputs**: Events are broadcast to all defined output assets.

An asset is considered successful if it accepts the event, meaning all conditional stages have succeeded, regardless of the outcome of transformational stages. This ensures that events are processed through the appropriate path based on successful acceptance checks.

A stage succeeds if the logical combination of its operations succeeds. The exact combination logic is determined by the stage itself. This ensures that each stage can apply its own logic to decide whether it has successfully processed an event.

<workflow_placeholder>

### Helper functions
Implement all the high level operations available to the user when developing the ruleset. Each function defines its signature, its mode of operation and its error management. Users cannot change the behavior of a helper function, and cannot combine two functions into a single expression.

There are two intrinsic operations which do not require additional syntax:
- Comparison of values or references inside a check stage.
- Value or reference assignment inside a map stage.

All other operations are accessed through the helper functions.

The syntax for calling a helper function is `helper_name(args…)`. They can be used in both check operations and map operations. Helper functions are classified into three categories:
- **Conditionals**: Used in check operations to test complex conditions.
- **Transformational**: Used in map operations to transform data.
- **Mapping**: A subset of transformational operations scoped to modifying only the target field.

Check the [helper standard library](ref-helper-functions.md) for a complete list of available helper functions.

#### Condition Helpers
When using conditional helpers, the syntax is:
```yaml
target_field: condition_helper(args)
```

The helper will always test a condition on *target_field*. If the condition passes, the operation succeeds; otherwise, it fails.

#### Mapping Helpers
When using mapping helpers, the syntax is:
```yaml
target_field: map_helper(args)
```

The helper will always map the *target_field* if the operation succeeds. If the operation fails, the *target_field* remains unchanged.

#### Transform Helpers
When using transformational helpers, the syntax is:
```yaml
target_field: transform_helper(args)
```

The helper will transform the *target_field* if the operation succeeds. If the operation fails, the *target_field* remains unchanged.

A transformational helper may fail due to implicit conditions, such as expecting a specific type for the target field, missing a reference passed as an argument, etc.

***It is important to understand that every operation can succeed or fail, and this is the foundation for defining the operation graph.***

#### Parsing rules
When using a helper function in a map or check operation:
```yaml
target.field: helper_name(args…)
```

The arguments for `helper_name` can be references to other fields, or JSON values (string, number, boolean, array, or object). Multiple arguments should be separated by commas.

When the helper function is built, arguments are parsed in the following order:
- **Quoted argument**: `'value'` starts and ends with a single quote. `\` and `'` can be escaped.
- **Reference**: `$reference` starts with `$`, followed by alphanumerics plus `#`, `_`, `@`, and `-`, separated by dots.
- **JSON value**: An attempt is made to parse the argument as JSON (any valid JSON type).
- **Raw string**: If none of the above apply, the argument is handled as a string value, with escapes allowed for `$`, `'`, `,`, `)`, `\`, and whitespace.

Invalid escape sequences will always fail.

For example:
```yaml
target.field: helper_name('string', $reference, 123, {"key": "value"})
```

This call applies `helper_name` to the `target.field` with arguments:
- `'string'`: A string value.
- `$reference`: A reference to another field.
- `123`: A numeric value (valid JSON).
- `{"key": "value"}`: A JSON object.


>[!NOTE]
> `123` is a valid json, not only the objects are valid jsons according to the JSON standard,
> but also the numbers, strings, booleans and null values are valid JSON values.

When parsing a helper function inside a logical check expression the same rules apply adding that at least one argument
is expected for the helper, specifying the target field:
```yaml
check: helper_name($target.field, args…)
```

Added we can specify comparison helpers as operators:
```yaml
check: $target.field <op> <value>
```

Where value is parsed as a single helper argument following the same escaping rules and order.

Where op is any of the following:
- `==`
- `!=`
- `<`
- `<=`
- `>`
- `>=`

When using any operator that is not the equality operator only string or integer values are allowed.

When using the default map or filter functions for string operations, values are parsed according to standard YAML
(or JSON) types. If a value is a string and begins with the reference symbol `$`, it is treated as a potential
reference. If the reference is invalid the operation building fails.
```yaml
check:
  - target.field: <yaml_type>|<$ref>
map:
  - target.field: <yaml_type>|<$ref>
```

Below are some usage examples:

```yaml
# Example 1: Simple equality check
check: http.method == "GET"

# Example 2: Comparison with an integer value
check: $event.severity > 3

# Example 3: Using a helper function in check
check: cidr_match($source.ip, "192.168.0.0", 24)

```


### Definitions
To facilitate the reuse of constructors when building large assets—such as parsing code for events with common headers or repeated constructs like IP/port definitions—definitions can be introduced at the specification level. For example:
```yaml
definitions:
  header: <timestamp> <host.hostname> <daemon>:
  source: <source.ip>:<source.port>
  destination: <destination.ip>:<destination.port>
  a-list:
    - item1: value1
    - item2: value2
```

These definitions can then be referenced elsewhere:
```yaml
parse|field:
    - <$header> from <$source> to <$destination> deny
```

This approach enables text reuse within an asset. Definitions are applied at build time through interpolation and do not function as runtime variables, i.e., cannot be modified once declared.

>[!NOTE]
> The definitions are typed, respecting JSON/YAML data types. For example, you can define a YAML object or a
> numeric value and use it as an argument for helper functions, not just strings for parsing.

#### Restrictions
- **Naming Conflicts**: Definitions cannot have the same name as a schema field. Doing so will result in a failure to build the asset.
- **Precedence**: Definitions take precedence over custom fields. If a definition exists with the same name as a custom field, all references to the field will be replaced by the definition's value.
- **Chaining Definitions**: Definitions can use other definitions in their values as long as they are defined beforehand.
- **Context**: Definitions can only appear on the right side of operations, meaning we can't define the structure of the document with definitions or be used inside non operational stages.
- **Scope**: Definitions are scoped to the asset where they are defined. They cannot be shared across assets.

#### Use Cases
- **Parsing Complex Logs**
  - Logs with extensive or structured headers can be broken into reusable definitions for clarity and to avoid redundancy.
  - **Example**: Defining reusable components (TYPE_FIELD, MSG_FIELD) for parsing various log formats.
- **Handling Large Value Lists**
  - When working with extensive arrays (e.g., banned IPs), definitions keep the configuration readable and maintainable.
  - **Example**: Using a predefined list of banned IPs to check against source IPs in a normalize stage.
- **Small Key-Value Databases (kvdbs)**
  - When small mappings are needed but don’t justify a full kvdb, definitions provide a lightweight alternative.
  - **Example**: Mapping log levels or event IDs to structured categories, types, and outcomes for normalization.

### Variables

Variables are temporary fields scoped to the current asset that is processing an event. They are identified by prefixing their name with an underscore `_`, following the standard field naming convention and supporting any operation just like fields.
```
_field.name
```

Key characteristics:
- Scoped to the current asset – Variables exist only within the asset processing the event and do not persist beyond it.
- Runtime Modifiable – Unlike definitions, which are static, variables can be modified during event processing.

### Log Parsing
Log parsing transforms raw log entries into structured data using parser expressions. These expressions serve as an alternative to Grok, eliminating the need for explicit type declarations by leveraging predefined schema-based parsing. Instead of regular expressions, they use specialized parsers for improved accuracy and efficiency.

Key Components:
- Literals: Direct character matches with escape rules for special characters.
- Fields: Extract structured data, including:
  - Schema fields (predefined in the schema)
  - Custom fields (user-defined, defaulting to text)
  - Optional fields (ignored if missing)
  - Field choices (choosing between multiple fields)
- Wildcards: Capture patterns without mapping data to fields.
- Optional Groups: Make subexpressions optional for flexible parsing.
- Schema Parsers: Automatically applied when a field of a known type is used, ensuring compatibility with Wazuh Indexer.

Example:
This expression captures an IP or hostname into `client.ip` or `client.address` and, if present, captures a port into `server.port`:

```yaml
parse|event.original:
  - "<client.ip>?<client.address> connected to <server.ip>(?:<server.port>)"
```

For a log entry:
```
192.168.1.10 connected to 10.0.0.5:443
```

It extracts:
```json
{
  "client.ip": "192.168.1.10",
  "server.ip": "10.0.0.5",
  "server.port": "443"
}
```

Parsers are also available as helper functions for use in map and check operations. For a detailed explanation, see the Parser Stage and Parser Helper Functions sections.

### Key Value Databases
The engine allows the definition of JSON key-value databases, making them available in the assets through helper functions. These databases can be used to map large serializable data and check Indicators of Compromise (IoCs) or extensive key databases that require constant management. This approach separates the maintenance of such data from the decoder, streamlining the process and ensuring efficient data handling.

For more details on managing kvdbs, refer to the How to Manage kvdb section and the kvdb Library helper functions.

#### Use cases
**Normalizing Large Serializable Data**: Maps event IDs to predefined categorization fields using a kvdb, simplifying event classification. Example:
```yaml
normalize:
  - map:
      - event: kvdb_get_merge(windows_security_eventid_to_category_type_action, $event.code)
```

This retrieves event categories, types, and actions based on the event ID.

**Checking Indicators of Compromise (IoCs)**: Compares log entries against a kvdb of known malicious IPs to identify potential threats. Example:
```yaml
normalize:
  - check:
      - source.ip: kvdb_match(known_malicious_ips)
```

If a match is found, security-related data is mapped to the event.

### Dates and Timestamps
Assets are capable of handling dates in various formats and time zones. This flexibility is achieved through configurable
parsers (refer to the [date parser documentation](ref-parser.html#date-parser) for more details).

Once a date is parsed, the Engine normalizes it to UTC. This ensures that all timestamps are stored and processed
homogeneously, maintaining consistency across event processing and dashboard visualization.

### Geolocation
Assets are capable of enriching events with geolocation information, enhancing event data with location-based context.
This is achieved by using [Maxmind - GeoLite databases](https://www.maxmind.com/), which provide location data based on
IP addresses. For more details, see the [geo location](ref-helper-functions.md#geoip) helper documentation.

The GeoLite databases are configured through the API, allowing you to specify the relevant databases to be used for
geolocation enrichment. For more information on how to configure these databases, refer to the API documentation.

### Decoders

Decoders are the first layer of assets that pass through the event when it is processed by a security policy. They are responsible for normalizing the event, transforming it into a structured event.

All events enter the pipeline through the root decoder, which selects the appropriate decoder to process the event. Each subsequent decoder processes the event as much as it can and then passes it to the next suitable decoder. This continues until no more decoders can process the event. A decoder can only select one next decoder from the available ones.


```mermaid
---
title: Decoder schema
---
kanban
  Decoder[Decoder schema]
    assetMetadata["metadata"]@{ priority: 'Very Low'}
    assetParents["parents"]
    assetChecks["checks"]
    decoParsers["parser"]
    decoNormalize["normalize"]
```

- **Metadata**: Each decoder has metadata that provides information about the decoder, such as the supported products,
  versions, and formats. This metadata does not affect the processing stages. 
    The metadata fields are:
    - `description` (string): A brief description of the decoder.
    - TODO: Add more fields when the metadata is defined.

- **Parents**: Defines the order in the decoder graph, establishing the parent-child relationship between decoders.
  A decoder can have multiple parents, when an event is successfully processed in a decoder, it will evaluate the
  children, one by one, until it finds a decoder that successfully processes the event.

> [!IMPORTANT]
> There is no order of priority when evaluating the children, and it cannot be assumed that a sibling decoder will be evaluated before another one.

- **Checks**: The checks stage is a preliminary stage in the asset processing sequence, designed to assess whether an
  event meets specific conditions without modifying the event itself.
  More information on the checks stage can be found in the [Check section](#checkallow).


### Rules

Rules are the second layer of assets that process events in a security policy. They are responsible for analyzing the
normalized event, when the decoding stage is finished, to add context, security indicators, and threat intelligence.
Unlike decoders,  the rule cannot modify the decoded event, but it can add new certain fields to enrich the event, this
prevents the rules from being used to decode events.



```mermaid
---
title: Rule schema
---
kanban
  Rule[Rule schema]
    assetMetadata["metadata"]@{ priority: 'Very Low'}
    assetParents["parents"]
    assetChecks["checks"]
    ruleNormalize["rule_enrichment"]
```

- **Metadata**: Each rule has metadata that provides information about the rule, such as the supported products,
  versions, and formats. This metadata does not affect the processing stages.
    The metadata fields are:
    - `description` (string): A brief description of the rule.
    - TODO: Add more fields when the metadata is defined.

- **Parents**: Defines the order in the rule graph, establishing the parent-child relationship between rules, a rule can
  have multiple parents, when an event is successfully processed in a rule (rule matches), it will evaluate all the
  children. Unlike decoders, and all children will be evaluated.

- **Checks**: The checks stage is a preliminary stage in the asset processing sequence, designed to assess whether an
  event meets specific conditions. On the rules, the checks stage is used to evaluate the conditions that the event must
  meet to be considered a security event. More information on the checks stage can be found in the [Check section](#checkallow).

- **Rule Enrichment**: The rule enrichment stage is used to add context, security indicators, and threat intelligence to
  the normalized event. This stage is used to add new fields to the event, but it cannot modify the normalized event, it
  like the `map` stage, but with the restriction that it cannot modify the normalized event, only rule fields can be added.

### Outputs

Outputs are the last layer of assets that process events in a security policy. They are responsible for storing the
security events in a storage system, sending them to a wazuh-indexer, a file, or sending them to a third-party system.


```mermaid
---
title: Output schema
---
kanban
  Output[Output schema]
    assetMetadata["metadata"]@{ priority: 'Very Low'}
    assetParents["parents"]
    assetChecks["checks"]
    OutputNormalize["output stage"]
```

- **Metadata**: Each output has metadata that provides information about the output, such as the destination, version,
  and format. This metadata does not affect the processing stages.
  The metadata fields are:
    - `description`: A brief description of the output.
    - TODO: Add more fields when the metadata is defined.

- **Parents**: Defines the order in the output graph, establishing the parent-child relationship between outputs.
  An output can have multiple parents, when an event is successfully processed in an output, it will evaluate all the
  children. Usually, the outputs are the last assets in the policy, so they do not have children.

- **Checks**: The checks stage is a stage in the output asset used to evaluate the conditions that the event must meet to
  be sent to the output. More information on the checks stage can be found in the [Check section](#checkallow).

### Filters

The filters are assets with a single stage, the check stage, used to evaluate the conditions without modifying the event.

The filters are used to:

1. Route events to the correct policy in the orchestrator (Most common use case).
2. Filter a event between parent assets and child assets.


```mermaid
---
title: Filter schema
---
kanban
  Output[Output schema]
    assetMetadata["metadata"]@{ priority: 'Very Low'}
    %% assetParents["parents"]
    assetChecks["allow"]
```

- **Metadata**: Each filter has metadata that provides information about the filter, such as the proposed use case, version,
  and format. This metadata does not affect the processing stages.
  The metadata fields are:
    - `description`: A brief description of the filter.
    - TODO: Add more fields when the metadata is defined.

- **Allow**: The allow stage is a stage in the filter asset used to evaluate the conditions that the event must meet to
  pass the filter. More information on the checks stage can be found in the [Check/allow section](#checkallow).

  <placeholder_graph_filter>

> [!NOTE]
> When filter assets are used in the orchestrator, the don't have parents, they are a check stage that is evaluated before
> the event is sent to the policy.

## Stages

### Check/Allow
The check stage is a preliminary stage in the asset processing sequence, designed to assess whether an event meets specific conditions without modifying the event itself. Filters events based on predefined criteria, ensuring that only relevant events trigger the subsequent stages like parse or normalize.

There are two ways to define conditions in a stage check: through a **condition list** or a **conditional expression** string.

#### Condition list
In a condition list, each condition is described with a pair `property:value`. Here, `property` is the name of any field, and `value` is the condition that the field must meet.

The event is filtered through all listed conditions, and only events that satisfy all conditions in order are processed further.

Depending on the value, the condition to test is:
- **JSON value**: Tests that the field contains a specific value.
- **Field reference**: Checks that the event contains the field denoted by the reference, and both fields have the same value. A reference is formatted as `$field.name`.
- **Helper function**: Executes a conditional operation on the field, specified by `helper_name(args…)`.

Example checklist:
```yaml
check:
  - event.format: text
  - user.name: $root_user
  - event.original: exists()
  - event.id: 1234
```

All conditions must be met for the event to pass through the check stage. If any condition fails, the event is not processed further.

> [!NOTE]
> `event.id: 1234` is not the same as `event.id: "1234"` because the first one is a number and the second one is a string.

#### Conditional expression
For scenarios requiring complex conditions, especially in rules, a conditional expression allows for more nuanced logic. This string uses a subset of first-order logic language, including logical connectives and support for grouping through parentheses.

Logical Connectives:
- Negation (`NOT`)
- Conjunction (`AND`)
- Disjunction (`OR`)

These connectives facilitate writing conditions between terms where a term can be:
- Value comparison: Formatted as `<$field><op><value>`.
- Helper function: Expressed as `<helper_name>(<field>, args...)`, except for the “exists” helper, which can be denoted by the field name alone.

Supported Operators:
- Comparison operators `!=` and `==` are applicable to all data types.
- Operators `<=`, `<`, `>=`, `>` are supported for numbers and strings (lexicographically).

Examples of conditional expressions:
```yaml
check: $event.category=="registry" AND $event.type=="change" AND ($registry.path=="/some/path" OR $registry.path=="/some/other/path")
```

```yaml
check: int_less($http.response.status_code, 400)
```

```yaml
check: $wazuh.origin == /var/log/apache2/access.log OR $wazuh.origin == /var/log/httpd/access_log
```

### Parse
Executes a series of parsing expressions that transform the event's original message into clearly defined data fields. The parsing operations are processed in sequence, with each operation attempted until one succeeds. If an operation succeeds, subsequent operations in the list are skipped.

If all operations fail, the execution of the stage is marked as failed, the processing of the event could continue with the next substage only if it is within a normalize.

For a complete list of parsers check the [Parsers](ref-parser.md) reference.

#### Parser expression
Parser expressions facilitate the transformation of log entries into structured objects, offering an alternative to Grok by eliminating the need for explicit type declarations as these are predefined in the schema. Instead of regular expressions, these expressions utilize tailored parsers, enhancing precision.

The parser expressions are composed of various tokens or expressions, where these expressions can be any one of the following:
- **Literals**, Direct characters that match input text exactly. with certain reserved characters that require escaping (used in other tokens), with the character `\` , precisely: `<>?\(`

  E.g.: The following expression will match exactly that in the log line
`[Fri Sep 09 10:42:29.902022 2011] [core:error]`
- **Fields**, are expressions of the form  `<[?]field_name[/param1…]>`, where we can identify 4 different types of field expressions:
  - **Schema fields**: Directly correspond to fields defined in the schema, with the engine automatically applying the appropriate parser and can have parameters depending on the parser.

     E.g.: `<source.ip>` will match any IPv4 or IPv6 and map it to the field `source.ip`.
  - **Custom fields**: Are those that are not in the schema, in contrast to schema fields, custom fields use the text parser unless specified otherwise by the parameters. These are intended for temporary/auxiliary use.

    Custom fields are indexed as text by default in open search, depending on the configuration open search may try to detect and index as other types.

    E.g.: `<custom_field/long>` will match any number and map it to the field `custom_field`.
  - **Optional fields**: we indicate that a field parse expression is optional writing the interrogation symbol `?` at the beginning of the expression. If the parsing fails it will continue with the next expressions.

    E.g.: `<field1>|<?field2>|<field3>` will match anything between `|` symbols three times, and the second may be empty or not.
  - **Field choice**: Expresses a choice between two field expressions, meaning one of the fields must match. We write two field expressions splitted by the interrogation symbol `?`. As the first choice we can only use parsers that do not require end token, if we use one that does the expression will fail to compile because the end tokens are not sent to the parser.

    E.g.: `<source.ip>?<~/literal/->` will match an IP and map it to source ip or a hyphen, skipping it.

    Note: `?` only needs to be scaped when it appears right after a field expression: `<source.ip>\?...`
- `Wildcards`, follows the same syntax and behaves the same as a custom field but has no name and does not map to any field. It is used to parse some pattern without extracting. Can be a optional or in a field choice also.

  E.g.:`<~/byte>` will parse a byte value and continue.

  E.g.:`Error Code: <~/long> Description: <message>` Here, `<~/long>` uses a wildcard to parse an integer error code that isn’t mapped to any field, essentially ignoring it while capturing the subsequent error description into message.
- **Optional groups**, make a logpar subexpression optional. The optional expression is denoted with `(?sub_expression)`. Used to make some more complex patterns optional where a simple optional field won’t suffice. It can contains any valid logpar expression with the exception of another optional group. An optional group can not contains another group, and two optional groups may not appear in a row.

  E.g.:`[<source.ip>(?:<source.port>)]` will match any ip address optionally followed by a port separated by double dots, and being between brackets.

**Examples**:

This expression will capture an IP address or hostname into `client.ip` or `client.address`, and optionally capture a port into `server.port` if it is present.
```yaml
<client.ip>?<client.address> connected to <server.ip>(?:<server.port>)
```

Apache error parser:
```yaml
# [Mon Dec 26 16:15:55.103522 2016] [mpm_prefork:notice] [pid 11379] AH00163: Apache/2.4.23 (Unix) configured -- resuming normal operations
# [Mon Dec 26 16:15:55.103786 2016] [core:notice] [pid 11379] AH00094: Command line: '/usr/local/Cellar/httpd24/2.4.23_2/bin/httpd'
# [Wed Oct 20 19:20:59.121211 2021] [rewrite:trace3] [pid 121591:tid 140413273032448] mod_rewrite.c(470): [client 10.121.192.8:38350] 10.121.192.8 - - [dev.elastic.co/sid#55a374e851c8][rid#7fb438083ac0/initial] applying pattern '^/import/?(.*)$' to uri '/'
# [Wed Oct 20 19:20:59.121211 2021] [rewrite:trace3] [pid 121591:tid 140413273032448] mod_rewrite.c(470): [client milo.dom.com:513] 10.121.192.8 - - [dev.elastic.co/sid#55a374e851c8][rid#7fb438083ac0/initial] applying pattern '^/import/?(.*)$' to uri '/'
# [Mon Dec 26 16:22:08 2016] [error] [client 192.168.33.1] File does not exist: /var/www/favicon.ico
# [Fri Sep 09 10:42:29.902022 2011] [core:error] [pid 35708:tid 4328636416] [client 89.160.20.112] File does not exist: /usr/local/apache2/htdocs/favicon.ico
# [Thu Jun 27 06:58:09.169510 2019] [include:warn] [pid 15934] [client 67.43.156.12:12345] AH01374: mod_include: Options +Includes (or IncludesNoExec) wasn't set, INCLUDES filter removed: /test.html
# [Mon Dec 26 16:17:53 2016] [notice] Apache/2.2.22 (Ubuntu) configured -- resuming normal operations
# [Mon Dec 26 16:22:00 2016] [error] [client 192.168.33.1] File does not exist: /var/www/favicon.ico, referer: http://192.168.33.72/
# [Mon Dec 26 16:22:08 2016] [error] [client 192.168.33.1] File does not exist: /var/www/favicon.ico
parse|event.original:
    - "[<@timestamp/Mon Dec 26 16:22:00 2016>] [<log.level>] [client <source.address>(?:<source.port>)] <message>"

    - "[<@timestamp/%a %b %d %T %Y/en_US.UTF-8>] [<~apache.error.module>:<log.level>] [pid <process.pid>(?:tid <process.thread.id>)] [client <source.address>(?:<source.port>)] <message>"

    - "[<@timestamp/%a %b %d %T %Y/en_US.UTF-8>] [<~apache.error.module>:<log.level>] [pid <process.pid>(?:tid <process.thread.id>)] <message>"
```

#### Schema fields and parsers
Fields within the schema are bound to specific parsers that ensure the data matches the expected format. For example, date fields may require a specific time format, which is denoted using parameters following the field name in the format `<field_name/param_0/param_n>`. This allows for flexible data validation against predefined types or custom formats specified by additional parameters.

For standard fields defined in the schema, each field type has an associated parser. For instance, a field of type long (like `event.severity`) will utilize a numeric parser.

Custom fields not defined in the schema default to using the text parser, which continues parsing until a specified delimiter or the end of the log entry. Fields at the end of a parser expression are interpreted as catch-all, capturing all remaining text in the log entry. This approach facilitates partial parsing where full matching is not required, ensuring flexibility in log analysis.

For example,  the case of `<tmp_field>c` this will parse everything until character `c` is found. It is possible to specify the parser name as the first argument, for example `<tmp_field/ip>c` will use the ip parser instead of the text parser. It is also possible to pass parameters to the parser, for example `<tmp_field/date/RFC822>c` parses the timestamp using the RFC822 format.

#### End tokens and field expressions
Some parsers need an anchor token to stop parsing, i.e. the text parser used by default in all custom fields will parse any character until the end token is found. The end token is the literal following the field expression, or if the field expression is at the end it will parse the remaining string.

E.g.:`<header>:<message>` will parse and capture any text up to a double dots in the header field, and the remaining of the log will be captured in the message field.

This implicates that two field expressions must be splited by a literal unless the first one does not need an end token, while `<custom/long><~>` is valid, as the long parsers does not need end token, `<text><~>` will be invalid.

In choice expressions the end token is the same for both field expressions, it is the literal right after the second field expression. E.g, `<custom_ip>?<~>|` will be valid, as both parsers require an end token, in this case the literal `|`. This implies the same as before, if one of the choices needs an end token, it must be followed by a literal.

In optional group expressions, i.e. when a field is followed by an optional group, there are multiple end tokens. The literal at the beginning of the optional group and the literal right after the group, meaning if a field needs an end token and is followed by an optional group, the group must start with a literal and a literal must appear right after the group.

E.g.: `<custom_text>(?|<opt/long>):`, in this case the text parser will try to search for a `|`, so the optional group can be parsed, and if the optional group fails, then the text parser will use the symbol `:` as end token.


### Map
Executes each operation of the list in order until the last operation. If any operation fails, it continues with the next one.

If all operations fail the stage is not marked as failed and continues to the next stage.

**Type Validation**:
- When mapping a custom field (not defined in the schema), it can store any value without additional type checks.
- When mapping a field that belongs to the schema, a validation is performed based on the field’s type (e.g.,
  `source.ip` → IP, `event.start` → timestamp).
  - If a fixed value is provided at build time and its type is invalid, the asset build fails immediately.
  - If the value is dynamically obtained, for example from a helper or another schema field, and it eventually fails
    type validation, it will fail at runtime. The field is then left unmapped to maintain the event’s integrity.

Example:

```yaml
- map:
    - event.kind: event
    - event.dataset: apache.access
    - event.category: +array_append/web
    - event.module: apache
    - service.type: apache
    - event.outcome: success
```


### Normalize/Enrichment
The normalize stage is where the event undergoes transformations and adjustments after passing through the check and parse stages successfully. Composed of a list of sub-stages that are executed in the specified order. These sub-stages can include operations such as check, map, and parse.
- **Check**: Applies conditional checks within the normalize context to determine if subsequent mappings or parsing should be executed.
- **Parse**: Further decomposes and extracts fields from the event data if required.
- **Map**: Transforms and assigns new values to fields in the event based on predefined rules.

Each set of sub-stages is processed sequentially. If a check and parse within a normalization block is successful, the corresponding map is executed, replicating the check, parse, and normalize stages of the asset.

Example:
```yaml
normalize:
 - map:
	- wazuh.decoders: array_append(windows-sysmon)
	- event.dataset: sysmon
	- event.kind: event

 # Only maps network.procol if event.code is 22
 - check: $event.code == '22'
   map:
	- network.protocol: dns

 # Only maps resources if the check and parse stages succeeded
 - check: $event.outcome == failure
   parse|message:
     - "[<error.code/int>]<details>"
   map:
     - resources: split($details, ",")
```

### Output
The Output Stage allows you to specify and configure the different outputs, defining the final destinations for events before they leave the Engine.
```yaml
outputs:
  - output_name: configuration
```

For more details on the available output types and configurations, refer to [output documentation](ref-output.md).

## Parsers

### Schema parsers
These parsers are used automatically when a field of its type is used in a logpar expression.

For example, if you use the field `<event.start>` which is of type `date`, it will be parsed automatically by the date parser.

These parsers will generate fields which are type-compatible with Wazuh Indexer.

| Type        | Parser       | Description                                                                                          |
|-------------|--------------|------------------------------------------------------------------------------------------------------|
| null        | -            | A null field can’t be indexed or searched. When a field is set to null, OpenSearch behaves as if that field has no values. |
| boolean     | bool         | OpenSearch accepts true and false as boolean values. An empty string is equal to false.               |
| float       | float        | Codified as decimal representation in string format. A single-precision 32-bit IEEE 754 floating point number, restricted to finite values. |
| scaled_float| scaled_float | Codified as decimal representation in string format. The scaling factor is defined in the schema.    |
| double      | double       | Codified as decimal representation in string format. A double-precision 64-bit IEEE 754 floating point number, restricted to finite values. |
| long        | long         | Codified as decimal representation in string format. A signed 64-bit integer with a minimum value of `-2^63` and a maximum value of `2^63-1`. |
| byte        | byte         | Codified as a decimal representation in string format. A signed 8-bit integer with a minimum value of `-128` and a maximum value of `127`. |
| object      | -            | -                                                                                                    |
| array       | -            | -                                                                                                    |
| nested      | -            | -                                                                                                    |
| text        | text         | A string sequence of characters that represent full-text values.                                     |
| keyword     | text         | A string sequence of characters that represent full-text values.                                     |
| ip          | ip           | A string with IPv4 or IPv6 address.                                                                  |
| date        | date         | Date codified as string. All dates are converted to a unified date in UTC timezone.                  |
| geo_point   | -            | -                                                                                                    |
| binary      | binary       | A codified base64 string.                                                                            |

Aditionally we define some types for the purpose to use specific parsers, normally used to parse objects or structured types from an input text. This is the case for `url` field for example.

| Type        | Parser     | Description                                                                                           |
|-------------|------------|-------------------------------------------------------------------------------------------------------|
| url         | uri        | Parses URI text and generates the URL object with all the parsed parts.                               |
| useragent   | useragent  | Parses a user agent string. It does not build the user agent object; this can be done with the OpenSearch plugin. |


## Debugging

By default, the Engine's log information is recorded in journald when launching the wazuh-manager service.

### Filtering Logs by Executable Name
You can retrieve logs specifically for the Engine using journald’s _COMM field:

```bash
journalctl _COMM=wazuh-engine
```

For real-time monitoring of errors:
```bash
journalctl -f _COMM=wazuh-engine
```

### Filtering Logs by Severity
To refine logs based on severity levels you can combine grep:
```bash
journalctl _COMM=wazuh-engine | grep info

Dec 18 14:59:22 WazPc env[12974]: 2024-12-18 14:59:22.663 12974:12974 info: Logging initialized.
Dec 18 14:59:22 WazPc env[12974]: 2024-12-18 14:59:22.668 12974:12974 fileDriver.cpp:231 at readCol(): debug: FileDriver readCol name: 'namespaces/system/decoder/core-hostinfo'.
Dec 18 14:59:22 WazPc env[12974]: 2024-12-18 14:59:22.669 12974:12974 main.cpp:166 at main(): info: Store initialized.
Dec 18 14:59:22 WazPc env[12974]: 2024-12-18 14:59:22.669 12974:12974 main.cpp:172 at main(): info: RBAC initialized.
```

Available severity levels:
- **trace** – Provides highly detailed debugging information, useful for deep troubleshooting.
- **debug** – Contains diagnostic messages intended for developers to track execution flow.
- **info** – General operational logs that indicate normal Engine activity.
- **warning** – Highlights potential issues that do not impact functionality but may require attention.
- **error** – Reports issues that may cause incorrect behavior but do not stop the Engine.
- **critical** – Indicates severe failures that may result in the Engine stopping or becoming unstable.

### Traces
Traces allow you to inspect the operational graph behavior, providing insights into how events are processed within the Engine. By using the tester endpoint (refer to the API documentation for details), you can specify several options to debug event processing effectively.

Available trace options:
- **Namespaces** – Filters traces to show only the assets under a specified namespace.
- **Graph History** – Displays all assets that processed a given event, allowing a complete view of its journey.
- **Traces** – Provides a detailed history of all operations performed by each asset (or a specified set of assets).

Here is a test example showing the graph history:
```
traces:
[🔴] decoder/zeek-x509/0 -> failed
[🔴] decoder/zeek-weird/0 -> failed
[🔴] decoder/zeek-traceroute/0 -> failed
[🔴] decoder/zeek-stats/0 -> failed
[🔴] decoder/zeek-software/0 -> failed
[🔴] decoder/zeek-socks/0 -> failed
[🔴] decoder/zeek-snmp/0 -> failed
[🔴] decoder/zeek-smb_mapping/0 -> failed
[🔴] decoder/zeek-smb_files/0 -> failed
[🔴] decoder/apache-error/0 -> failed
[🔴] decoder/zeek-smb_cmd/0 -> failed
[🔴] decoder/zeek-ssl/0 -> failed
[🔴] decoder/snort-json/0 -> failed
[🔴] decoder/squid-access/0 -> failed
[🔴] decoder/zeek-known_certs/0 -> failed
[🔴] decoder/suricata/0 -> failed
[🔴] decoder/zeek-irc/0 -> failed
[🔴] decoder/microsoft-exchange-server-smtp/0 -> failed
[🔴] decoder/snort-plaintext/0 -> failed
[🔴] decoder/pfsense-firewall/0 -> failed
[🔴] decoder/pfsense-dhcp/0 -> failed
[🔴] decoder/apache-access/0 -> failed
[🔴] decoder/snort-plaintext-csv/0 -> failed
[🔴] decoder/zeek-sip/0 -> failed
[🔴] decoder/pfsense-unbound/0 -> failed
[🔴] decoder/iis/0 -> failed
[🔴] decoder/zeek-signature/0 -> failed
[🔴] decoder/modsecurity-nginx/0 -> failed
[🔴] decoder/microsoft-dhcpv6/0 -> failed
[🔴] decoder/zeek-conn/0 -> failed
[🔴] decoder/zeek-modbus/0 -> failed
[🔴] decoder/microsoft-exchange-server-imap4-pop3/0 -> failed
[🔴] decoder/pfsense-php-fpm/0 -> failed
[🔴] decoder/microsoft-exchange-server-messagetracking/0 -> failed
[🔴] decoder/microsoft-exchange-server-httpproxy/0 -> failed
[🔴] decoder/zeek-kerberos/0 -> failed
[🔴] decoder/modsecurity-apache/0 -> failed
[🔴] decoder/microsoft-dhcp/0 -> failed
[🔴] decoder/zeek-pe/0 -> failed
[🔴] decoder/windows-event/0 -> failed
[🔴] decoder/zeek-capture_loss/0 -> failed
[🔴] decoder/zeek-dhcp/0 -> failed
[🔴] decoder/zeek-dnp3/0 -> failed
[🔴] decoder/zeek-dns/0 -> failed
[🔴] decoder/zeek-smtp/0 -> failed
[🔴] decoder/zeek-http/0 -> failed
[🔴] decoder/zeek-rfb/0 -> failed
[🔴] decoder/zeek-files/0 -> failed
[🔴] decoder/zeek-ftp/0 -> failed
[🔴] decoder/zeek-ssh/0 -> failed
[🔴] decoder/zeek-ocsp/0 -> failed
[🔴] decoder/zeek-dce_rpc/0 -> failed
[🔴] decoder/zeek-intel/0 -> failed
[🔴] decoder/zeek-syslog/0 -> failed
[🔴] decoder/zeek-known_hosts/0 -> failed
[🔴] decoder/zeek-dpd/0 -> failed
[🔴] decoder/zeek-known_services/0 -> failed
[🔴] decoder/zeek-mysql/0 -> failed
[🔴] decoder/zeek-ntlm/0 -> failed
[🔴] decoder/zeek-tunnel/0 -> failed
[🔴] decoder/zeek-notice/0 -> failed
[🔴] decoder/zeek-ntp/0 -> failed
[🔴] decoder/zeek-radius/0 -> failed
[🟢] decoder/syslog/0 -> success
[🔴] decoder/sysmon-linux/0 -> failed
[🔴] decoder/system-auth/0 -> failed
[🔴] decoder/snort-plaintext-syslog/0 -> failed
[🔴] decoder/wazuh-dashboard/0 -> failed
```

Showing full traces:
```
traces:
[🟢] decoder/syslog/0 -> success
  ↳ [/event/original: <event.start/Jun 14 15:16:01> <host.hostname> <TAG/alphanumeric/->[<process.pid>]:<~/ignore/ ><message>] -> Failure: Parse operation failed: Parser <event.start/Jun 14 15:16:01> failed at: 2018-08-14T14:30:02.203151+02:00 linux-sqrz systemd[4179]: Stopped target Basic System.
  ↳ [/event/original: <event.start/Jun 14 15:16:01> <host.hostname> <TAG/alphanumeric/->:<~/ignore/ ><message>] -> Failure: Parse operation failed: Parser <event.start/Jun 14 15:16:01> failed at: 2018-08-14T14:30:02.203151+02:00 linux-sqrz systemd[4179]: Stopped target Basic System.
  ↳ [/event/original: <event.start/2018-08-14T14:30:02.203151+02:00> <host.hostname> <TAG/alphanumeric/->[<process.pid>]: <message>] -> Success
  ↳ event.kind: map("event") -> Success
  ↳ wazuh.decoders: array_append("syslog") -> Success
  ↳ related.hosts: array_append($host.hostname) -> Success
  ↳ process.name: rename($TAG) -> Success
  ↳ host.ip: array_append($tmp.host_ip) -> Failure: 'tmp.host_ip' not found
```

## F.A.Q
- A explanation of the time zone and how it works in the engine.
- A explanation of diferent timestamp fields and how they are used.
