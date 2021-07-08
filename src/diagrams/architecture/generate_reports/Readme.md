# Generate reports architecture
## Index
1. [Purpose](#purpose)
2. [Sequence diagram](#sequence-diagram)

## Purpose
Generate reports feature (Reportd) was created to generate and send reports via email based on several configurations.

## Sequence diagram
Sequence diagram shows the basic flow of generate reports feature hosted in monitord module. Each time the current day change is detected monitord module spawns a process per configured report to generate and send reports through email. Steps are:
1- create a new child process using fork.
2- the process will generate and send the report through email.
3- repeat step 1 to 2 for each configured report.
4- wait until all the child processes terminates.
5- if a process is taking to long to finish, sleep and try again later.
6- if the wait retries reached 10 or all the processes terminated, return.

