#include <stdio.h>
#include "common.h"

cJSON * getObjectFromArrayByKey(cJSON *array, char *key){
    cJSON *object = NULL, *item = NULL;
    int array_size, i;
    
    if(!array || !cJSON_IsArray(array)){
        return NULL;
    }

    array_size = cJSON_GetArraySize(array);
    for(i = 0; i < array_size; i++){
        object = cJSON_GetArrayItem(array, i);
        item = cJSON_GetObjectItemCaseSensitive(object, key);
        if(item && cJSON_IsString(item)){
            return item;
        }
    }
    return NULL;
}

char *execute(const char *cmd){
    char buffer[100024] = {0};
    int len;
    FILE *p;
    char *r;
    
    p = popen(cmd, "r");

    if(!p)
        return NULL;
    
    if(fgets(buffer, sizeof(buffer), p) == NULL){
        pclose(p);
        return NULL;
    }
    len = strlen(buffer);
    r = calloc(1, len + 1);
    strcpy(r, buffer);
    printf("r: %s\r\n", r);
    return r;
}
