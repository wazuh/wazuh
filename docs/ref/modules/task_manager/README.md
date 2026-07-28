# Task Manager Module

The Task Manager module orchestrates and executes tasks on Wazuh agents from the manager.

**Daemon:** Part of `wazuh-modulesd`

**Platform:** Linux, Windows, macOS

**Type:** Manager-only

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

---

## Overview

The Task Manager is a manager-side module that:
- Coordinates task execution on remote agents
- Manages task lifecycle (creation, distribution, execution, completion)
- Tracks task status and results
- Provides task scheduling and prioritization
- Handles task timeout and retry logic

Common tasks include:
- Agent upgrades
- Configuration updates
- Remote command execution
- File distribution
- Security scans

---

## Key Features

### Task Orchestration
- **Centralized control:** Manage tasks from a single manager
- **Multi-agent targeting:** Execute tasks on multiple agents simultaneously
- **Task queuing:** Queue tasks when agents are offline
- **Result collection:** Aggregate task results from agents

### Reliability
- **Timeout handling:** Automatically fail tasks that exceed time limits
- **Retry logic:** Configurable retry attempts for failed tasks
- **Status tracking:** Monitor task progress in real-time
- **Error handling:** Graceful failure with detailed error messages

### Performance
- **Concurrent execution:** Run multiple tasks in parallel
- **Resource management:** Limit concurrent tasks to avoid overload
- **Priority queuing:** Higher-priority tasks execute first

---

## Architecture

### Task Flow

1. **Task creation:** API or internal module creates task request
2. **Task queuing:** Task Manager queues task for target agents
3. **Task distribution:** Manager sends task to connected agents
4. **Task execution:** Agents execute task and report status
5. **Result collection:** Manager collects and stores results
6. **Completion:** Task marked as complete or failed

### Component Interaction

```
┌─────────────────────┐
│   Wazuh API / CLI   │
│                     │
└──────────┬──────────┘
           │ Create Task
           ▼
┌─────────────────────┐
│   Task Manager      │
│   (Manager)         │
│  - Queue tasks      │
│  - Track status     │
│  - Handle timeouts  │
└──────────┬──────────┘
           │ Distribute
           ▼
┌─────────────────────┐
│   Task Executor     │
│   (Agent)           │
│  - Execute task     │
│  - Report status    │
└─────────────────────┘
```

---

## Configuration

For complete configuration options, see:
- [Task Manager Configuration Reference](configuration.md)

Quick configuration example:

```xml
<task-manager>
  <enabled>yes</enabled>
  <max_tasks>100</max_tasks>
  <task_timeout>300</task_timeout>
  <cleanup_time>86400</cleanup_time>
</task-manager>
```

---

## Task Types

### Agent Upgrade Tasks

Upgrade one or more agents to a new version.

**Created by:** Agent upgrade module
**Target:** Specific agents or groups
**Duration:** Variable (depends on package size and agent count)

### Custom Command Tasks

Execute custom commands or scripts on agents.

**Created by:** API or wodle-command
**Target:** Specific agents
**Duration:** Defined by command timeout

### Configuration Update Tasks

Push configuration changes to agents.

**Created by:** Centralized configuration module
**Target:** Agents in specific groups
**Duration:** Short (seconds)

---

## Task Management

### Via API

Create a task:
```bash
curl -k -X POST "https://manager:55000/tasks" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"command":"upgrade","agent":"001","version":"4.10.0"}'
```

List tasks:
```bash
curl -k -X GET "https://manager:55000/tasks" \
  -H "Authorization: Bearer $TOKEN"
```

Get task status:
```bash
curl -k -X GET "https://manager:55000/tasks/123" \
  -H "Authorization: Bearer $TOKEN"
```

### Via Database

Task information is stored in the Wazuh database:

```sql
-- View active tasks
SELECT * FROM tasks WHERE status = 'In progress';

-- View task history
SELECT * FROM tasks ORDER BY create_time DESC LIMIT 10;
```

---

## Monitoring

### Task Status Values

- **Pending:** Task queued, waiting for agent
- **In progress:** Task executing on agent
- **Done:** Task completed successfully
- **Failed:** Task failed or timed out
- **Timeout:** Task exceeded maximum execution time
- **Cancelled:** Task cancelled by user

### Check Task Manager Status

```bash
# Check module is running
/var/wazuh-manager/bin/wazuh-modulesd --test

# View task manager logs
tail -f /var/wazuh-manager/logs/ossec.log | grep task-manager
```

---

## Troubleshooting

### Tasks Not Executing

Check configuration:
```bash
/var/wazuh-manager/bin/wazuh-logtest-config
```

Check task manager is enabled:
```bash
grep -A5 "task-manager" /var/wazuh-manager/etc/wazuh-manager.conf
```

Verify agents are connected:
```bash
/var/wazuh-manager/bin/wazuh-control status
/var/wazuh-manager/bin/agent_control -l
```

### Tasks Timing Out

Increase timeout in configuration:
```xml
<task-manager>
  <task_timeout>600</task_timeout>  <!-- Increase to 10 minutes -->
</task-manager>
```

Check agent logs for execution errors:
```bash
# On agent
tail -f /var/ossec/logs/ossec.log
```

### High Task Queue

Increase max concurrent tasks:
```xml
<task-manager>
  <max_tasks>200</max_tasks>  <!-- Increase from default -->
</task-manager>
```

Or reduce task creation rate from API/modules.

---

## Performance Considerations

### Resource Usage

- Each task consumes memory for state tracking
- Concurrent task limit prevents resource exhaustion
- Cleanup interval affects database size

### Tuning

For high-volume environments:
```xml
<task-manager>
  <enabled>yes</enabled>
  <max_tasks>500</max_tasks>           <!-- More concurrent tasks -->
  <task_timeout>600</task_timeout>     <!-- Longer timeout for complex tasks -->
  <cleanup_time>43200</cleanup_time>   <!-- Cleanup every 12 hours -->
</task-manager>
```

For low-volume environments:
```xml
<task-manager>
  <enabled>yes</enabled>
  <max_tasks>50</max_tasks>            <!-- Fewer concurrent tasks -->
  <task_timeout>300</task_timeout>     <!-- Shorter timeout -->
  <cleanup_time>86400</cleanup_time>   <!-- Cleanup daily -->
</task-manager>
```

---

## See Also

- [Task Manager Configuration Reference](configuration.md) - Complete configuration options
- [Agent Upgrade](../agent_upgrade/index.html) - Agent upgrade tasks
- [Wazuh API](../../api/index.html) - Task management via API
- [Agent Management](../agent-management/index.html) - Agent lifecycle management
