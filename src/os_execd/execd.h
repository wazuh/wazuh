#ifndef _EXECD_H

#define _EXECD_H

#define EXECQUEUE	"queue/alerts/execq"

/* Mail msg structure */
typedef struct _ExecdMsg
{
	int type;
    int name_size;
    int args_size;
    char *name;
    char **args;
}ExecdMsg;

/* Mail config structure */
typedef struct _execd_config
	{
	char **name;
	char **cmd;
	}execd_config;


/* Send and receive the exec message on the unix queue */
int OS_RecvExecQ(int socket, ExecdMsg *execd_msg);
int OS_SendExecQ(int socket, ExecdMsg *execd_msg);
void OS_FreeExecdMsg(ExecdMsg *msg);
#endif
