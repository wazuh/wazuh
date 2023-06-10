#ifndef LINER_CMD_H
#define LINER_CMD_H

#include <stdbool.h>
#include "stream.h"
#include "cli.h"
#include "hints.h"
#include "color.h"
#include "ansi.h"

typedef struct command_t command_t;
typedef struct cmdStatus_t cmdStatus_t;

void cmdInit(void);

void cmdLoad(char *cmd, char * hint, hintStyle_t style, void (*fn)(cmdStatus_t *status));

cmdStatus_t *cmdFind(cliSession_t *cs, char *cmd);
bool cmdExecute(cmdStatus_t *cmd);
void cmdEnd(cmdStatus_t *status);

/* Command output functions */
int cmdPrintf(cmdStatus_t *s, char *fmt, ...);
void cmdString(cmdStatus_t *s, char *str);

/* Command input functions*/
int cmdDataAvailable(cmdStatus_t *s);
int cmdGetChar(cmdStatus_t *s, char *c);

/* Command state*/
void cmdSetState(cmdStatus_t *status, int state);
int cmdGetState(cmdStatus_t *status);

/* Command custom data */
void cmdSetCustomData(cmdStatus_t *s, void *data);
void * cmdGetCustomData(cmdStatus_t *s);

void cmdExit(cmdStatus_t *s);

#endif //LINER_CMD_H
