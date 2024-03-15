#ifndef CLI_H
#define CLI_H
#include <stdarg.h>
#include "stream.h"
#include "string_list.h"
#include "hints.h"

typedef struct cliSession_t cliSession_t;

/*
    CLI's managment interface
*/
/*
    Module initialization
*/
void cliInit(void);

/* Creates a new CLI session and associates a stream to it */
cliSession_t * cliNewSession(stream_t *stream);

/* CLI's main task. It must be periodically execute */
void cliTask(cliSession_t *cliSession);
/* Sets autocomplete callback function.
   It receives a function pointer to a function that will return the autocomplete list
   generated from the received key
*/
void cliSetAutocompleteCallback(void (*callback)(stringList_t *autocompleteList, char *key));
/* Sets hints callback.
   It receives a function pointer to a function that will return the corresponding hint object
   obtained for the received key
*/
void cliSetHintsCallback(hint_t * (*callback)(char *str));

/* Setc CLI prompt */
void cliSetPrompt(cliSession_t *cliSession, char *prompt);

/* It must be called to force CLI's exit */
void cliExit(cliSession_t *cliSession);

/* Returns CLI session stream handler */
stream_t * cliStreamGet(cliSession_t *cliSession);

/* Return user authentication level */
int cliUserLevelGet(cliSession_t *cliSession);

/*
    CLI Input/Output interface
*/

/* Sends str string to CLI session */
void cliString(cliSession_t *cliSession, char *str);

/* Variadic CLI's printf */
int cliVPrintf(cliSession_t *cliSession, char *fmt, va_list arg);

/* Returns data pending count at CLI's input buffer */
int cliDataAvailable(cliSession_t *cliSession);

/* It returns next available char at CLI's input buffer */
int cliGetChar(cliSession_t *cliSession, char *out);

#endif //CLI_H
