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
