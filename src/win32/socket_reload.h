#ifndef SOCKET_RELOAD_H
#define SOCKET_RELOAD_H

int wazuh_agent_reload(const char *agent_path);
int wazuh_agent_reload_child(void);

#endif