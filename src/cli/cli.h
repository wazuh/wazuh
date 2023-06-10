#ifndef CLI_H
#define CLI_H
#include "stream.h"
#include "string_list.h"
#include "hints.h"

typedef struct cliSession_t cliSession_t;

cliSession_t *cliInit(stream_t *s);
void cliTask(cliSession_t *s);
void cliSetAutocompleteCallback(void (*cb)(stringList_t *l, char *buf));
void cliSetHintsCallback(hint_t * (*cb)(char *str));
void cliExit(cliSession_t *s);

void cliString(cliSession_t *s, char *str);
int cliPrintf(cliSession_t *s, char *fmt, ...);
int cliVPrintf(cliSession_t *s, char *fmt, va_list arg);

int cliDataAvailable(cliSession_t *s);
int cliGetChar(cliSession_t *cs, char *c);

#endif //CLI_H
