# Introduction

The **FIM (File Integrity Monitoring)** module has been enhanced with a reliable synchronization mechanism that ensures file and registry changes are persisted and synchronized with the manager even during network interruptions or agent restarts.

The module implements a **dual event system** that provides both real-time alerts and reliable state synchronization. It leverages the **Agent Sync Protocol** to persist differences in a local SQLite database and synchronizes them periodically with the manager through a session-based protocol.

FIM persistence supports **stateful synchronization** for complete file/registry metadata including checksums, while maintaining **stateless real-time alerts** for immediate threat detection.
