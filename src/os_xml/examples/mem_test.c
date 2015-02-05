#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "os_xml.h"


int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s file\n", argv[0]);
        return (-1);
    }

    while (1) {
        OS_XML xml;
        xml_node **node;
        int i = 0;

        usleep(10);
        printf(".");
        fflush(stdout);

        if (OS_ReadXML(argv[1], &xml) < 0) {
            printf("Error reading XML(%u): %s\n", xml.err_line, xml.err);
            return (1);
        }

        node = OS_GetElementsbyNode(&xml, NULL);
        if (node == NULL) {
            printf("error reading xml\n");
            return (1);
        }

        while (node[i]) {
            xml_node **cnode = NULL;
            int j = 0;
            cnode = OS_GetElementsbyNode(&xml, node[i]);
            if (cnode == NULL) {
                i++;
                continue;
            }
            while (cnode[j]) {
                /* */
                j++;
            }

            OS_ClearNode(cnode);
            i++;
        }

        OS_ClearNode(node);

        node = NULL;

        OS_ClearXML(&xml);
    }
    return (0);
}

