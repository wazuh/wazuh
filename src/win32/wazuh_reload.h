#ifndef WAZUH_RELOAD_H
#define WAZUH_RELOAD_H

void start_reload_control_thread(const char *agent_path);
void handle_reload_command(const char *agent_path);
int handle_reload_child(const char *pipe_name);

#define RELOAD_PIPE_CONTROL "\\\\.\\pipe\\wazuh-agent-control"
#define RELOAD_PIPE_SOCKET  "\\\\.\\pipe\\wazuh-agent-socket"

#endif