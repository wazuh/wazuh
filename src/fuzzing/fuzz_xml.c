/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "os_xml/os_xml.h"
#include "os_xml/os_xml_internal.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp)
        return 0;
    fwrite(data, size, 1, fp);
    fclose(fp);

    OS_XML xml;
    if (OS_ReadXML(filename, &xml) < 0) {
        OS_ClearXML(&xml);
        unlink(filename);
        return 0;
    }
    XML_NODE node = NULL;
    node = OS_GetElementsbyNode(&xml, NULL);
    if (node == NULL) {
        OS_ClearXML(&xml);
        return 0;
    }

    int i = 0;
    while (node[i]) {
        int j = 0;
        XML_NODE cnode;
        cnode = OS_GetElementsbyNode(&xml, node[i]);
        if (cnode == NULL) {
            i++;
            continue;
        }

        while (cnode[j]) {
            if (cnode[j]->attributes && cnode[j]->values) {
                int k = 0;
                while (cnode[j]->attributes[k]) {
                    k++;
                }
            }
            j++;
        }

        OS_ClearNode(cnode);
        i++;
    }

    OS_ClearNode(node);
    OS_ClearXML(&xml);
    unlink(filename);
    return 0;
}
