# Logs rotation architecture
## Index
1. [Purpose](#purpose)
2. [Sequence diagram](#sequence-diagram)

## Purpose
Logs rotation feature was created to rotate the internal logs on daily basis or when they reach a configured max size. Logs rotation runs as part of monitord module and it's responsible of compressing and signing the old logs as well.

## Sequence diagram
Sequence diagram shows the basic flow of logs rotation feature hosted in monitord module. Each time the current day change is detected monitord module performs logs rotation, signing and compression based on the current configuration. Steps are:
1- rotate logs.
2- sign rotated logs.
2- compress rotated logs.
Monitord checks every 1 seconds the size of the logs and decides if they need to be rotated based on the max size configured. In this case, logs are only rotated but not singed neither compressed.
