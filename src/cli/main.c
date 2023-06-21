#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "liner.h"
#include "stream-tcp.h"
#include "cmd.h"
#include "cli.h"
#include "agents.h"
#include "shared.h"

char shost[512];

hint_t greenHint = {
        .text = "I am a bold green hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorGreen,
                .back = colorBlack,
                .bold = 1
        }
};
hint_t green1Hint = {
        .text = "I am a green hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorGreen,
                .back = colorBlack,
                .bold = 0
        }
};
hint_t yellowHint = {
        .text = "I am a bold yellow hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorYellow,
                .back = colorBlack,
                .bold = 1
        }
};
hint_t yellow1Hint = {
        .text = "I am a yellow hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorYellow,
                .back = colorBlack,
                .bold = 0
        }
};
hint_t blueHint = {
        .text = "I am a bold blue hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorBlue,
                .back = colorBlack,
                .bold = 1
        }
};
hint_t blue1Hint = {
        .text = "I am a blue hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorBlue,
                .back = colorBlack,
                .bold = 0
        }
};
hint_t redHint = {
        .text = "I am a bold red hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorRed,
                .back = colorBlack,
                .bold = 1
        }
};
hint_t red1Hint = {
        .text = "I am a red hint",
        .style = {
                .header = " <- [",
                .trailer = "]",
                .fore = colorRed,
                .back = colorBlack,
                .bold = 0
        }
};

hintStyle_t defaultHintStyle = {
    .header = " <- [",
    .trailer = "]",
    .fore = colorMagenta,
    .back = colorBlack,
    .bold = 0
};

static void greenCmd(cmdStatus_t *s){
    cmdPrintf(s, "Green!\r\n");
}
static void green1Cmd(cmdStatus_t *s){
    cmdPrintf(s, "Green1!\r\n");
}
static void redCmd(cmdStatus_t *s){
    cmdPrintf(s, "Red!\r\n");
}
static void red1Cmd(cmdStatus_t *s){
    cmdPrintf(s, "Red1!\r\n");
}
static void blueCmd(cmdStatus_t *s){
    cmdPrintf(s, "Blue!\r\n");
}
static void blue1Cmd(cmdStatus_t *s){
    cmdPrintf(s, "Blue1!\r\n");
}
static void yellowCmd(cmdStatus_t *s){
    cmdPrintf(s, "Yellow!\r\n");
}
static void yellow1Cmd(cmdStatus_t *s){
    cmdPrintf(s, "Yellow1!\r\n");
}

static void clearCmd(cmdStatus_t *s){
    cmdPrintf(s, ansiEraseScreen());

    cmdEnd(s);
}
static void continueCmd(cmdStatus_t *s){
    cmdPrintf(s, "continue executed!\n");
    cmdEnd(s);
}
static void dirCmd(cmdStatus_t *s){
    cmdPrintf(s, "dir executed!\n");
    cmdEnd(s);
}
static void lsCmd(cmdStatus_t *s){
    cmdPrintf(s, "ls executed!\n");
    cmdEnd(s);
}
static void stopCmd(cmdStatus_t *s){
    cmdPrintf(s, "stop executed!\n");
    cmdEnd(s);
}

static void complexCmd(cmdStatus_t *s){
    int st = cmdGetState(s);
    switch(st){
        case 0:
            cmdPrintf(s, "This ");
            break;
        case 1:
            cmdPrintf(s, "is ");
            break;
        case 2:
            cmdPrintf(s, "a ");
            break;
        case 3:
            cmdPrintf(s, "complex ");
            break;
        case 4:
            cmdPrintf(s, "command.\r\n");
            cmdEnd(s);
            break;
    }
    cmdSetState(s, st+1);
}

int list_agents(int cmdlist);

int main(int argc, char **argv) {
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
    static int exit = 0;
    static stream_t *s;
    static cliSession_t *cs;
    char *line;

    s = streamTcpInit();
    cmdInit();
    cmdLoad("green", greenHint.text, greenHint.style, greenCmd);
    cmdLoad("1green", green1Hint.text, green1Hint.style, green1Cmd);
    cmdLoad("yellow", yellowHint.text, yellowHint.style, yellowCmd);
    cmdLoad("1yellow", yellow1Hint.text, yellow1Hint.style, yellow1Cmd);
    cmdLoad("blue", blueHint.text, blueHint.style, blueCmd);
    cmdLoad("1blue", blue1Hint.text, blue1Hint.style, blue1Cmd);
    cmdLoad("red", redHint.text, redHint.style, redCmd);
    cmdLoad("1red", red1Hint.text, red1Hint.style, red1Cmd);

    cmdLoad("clear"   , "Clears screen"    , defaultHintStyle,clearCmd   );
    cmdLoad("continue", "continues process", defaultHintStyle,continueCmd);
    cmdLoad("complex" , "complex command"  , defaultHintStyle,complexCmd);
    cmdLoad("dir"     , "Lists directory"  , defaultHintStyle,dirCmd     );
    cmdLoad("ls"      , "Unix like listing", defaultHintStyle,lsCmd      );
    cmdLoad("stop"    , "Stops process"    , defaultHintStyle,stopCmd    );

    agentsInit();
    controlInit();

    cs = cliInit(s);

    cliTask(cs);

    return 0;
}
