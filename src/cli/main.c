#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "liner.h"
#include "stream-tcp.h"
#include "cli.h"
#include "agents.h"
#include "shared.h"
#include "dummy_commands.h"
#include "control.h"

char shost[512];

int main(int argc, char **argv) {
    static stream_t *stream;
    static cliSession_t *cliSession;

    /* Set the name */
    OS_SetName(ARGV0);
#ifndef WIN32
    char * home_path = w_homedir(argv[0]);

    /* Change working directory */
    if (chdir(home_path) == -1) {
        printf("Error home path");
    }
    if (gethostname(shost, sizeof(shost) - 1) < 0) {
        strncpy(shost, "localhost", sizeof(shost) - 1);
        shost[sizeof(shost) - 1] = '\0';
    }

    os_free(home_path);
#endif

    cliInit();
    dummyCommandsInit();

    agentsInit();
    controlInit();

/* 
    TODO: It should be only a streamTCPInit call,
    where a thread is created for stremTCPTask.
    Then, streamTCPTask should create as many
    threads as connections received (and dispose
    threads when connections closes)
*/
    stream = streamTcpInit();
    cliSession = cliNewSession(stream);
    cliTask(cliSession);

    /* Main loop is just an idle loop 
       At most it could be waiting for a kill
       signal to neatly finish all threads
    */
    while(1){
        sleep(1);
    }

    return 0;
}
