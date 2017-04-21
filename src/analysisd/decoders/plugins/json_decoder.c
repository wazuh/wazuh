/*
* Copyright (C) 2017 Wazuh Inc.
* April 18, 2017.
*
* This program is a free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

#include "../plugin_decoders.h"

#include "shared.h"
#include "eventinfo.h"
#include "../../config.h"
#include "../../external/cJSON/cJSON.h"

static void fillData(Eventinfo *lf, char *key, char *value){

  if (strcmp(key, "srcip") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       srcip: '%s'", value);
    }
#endif
    lf->srcip = strdup(value);
    return;
  }
  if (strcmp(key, "dstip") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       dstip: '%s'", value);
    }
#endif
    lf->dstip = strdup(value);
    return;
  }
  if (strcmp(key, "dstport") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       dstport: '%s'", value);
    }
#endif
    lf->dstport = strdup(value);
    return;
  }
  if (strcmp(key, "srcport") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       srcport: '%s'", value);
    }
#endif
    lf->srcport = strdup(value);
    return;
  }
  if (strcmp(key, "protocol") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       protocol: '%s'", value);
    }
#endif
    lf->protocol = strdup(value);
    return;
  }
  if (strcmp(key, "action") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       action: '%s'", value);
    }
#endif
    lf->action = strdup(value);
    return;
  }
  if (strcmp(key, "srcuser") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       srcuser: '%s'", value);
    }
#endif
    lf->srcuser = strdup(value);
    return;
  }
  if (strcmp(key, "dstuser") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       dstuser: '%s'", value);
    }
#endif
    lf->dstuser = strdup(value);
    return;
  }
  if (strcmp(key, "id") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       id: '%s'", value);
    }
#endif
    lf->id = strdup(value);
    return;
  }
  if (strcmp(key, "status") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       status: '%s'", value);
    }
#endif
    lf->status = strdup(value);
    return;
  }
  if (strcmp(key, "command") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       command: '%s'", value);
    }
#endif
    lf->command = strdup(value);
    return;
  }
  if (strcmp(key, "url") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       url: '%s'", value);
    }
#endif
    lf->url = strdup(value);
    return;
  }
  if (strcmp(key, "data") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       data: '%s'", value);
    }
#endif
    lf->data = strdup(value);
    return;
  }
  if (strcmp(key, "systemname") == 0){
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       systemname: '%s'", value);
    }
#endif
    lf->systemname = strdup(value);
    return;
  }
  // Dynamic fields
  if (lf->nfields >= Config.decoder_order_size) {
		merror(ARGV0 ": ERROR: too many fields for JSON decoder.");
		return;
	}
#ifdef TESTRULE
  if (!alert_only) {
      print_out("       %s: '%s'", key, value);
  }
#endif
	lf->fields[lf->nfields].key = strdup(key);
	lf->fields[lf->nfields].value = strdup(value);
	lf->nfields++;
}

static void readJSON (cJSON *logJSON, char *parent, Eventinfo *lf){
  cJSON *next, *array;
  char *key = NULL;
  char *value = NULL;
  size_t  n;

  while(logJSON){
    next = logJSON->next;
    if (logJSON->string){
      if(parent){
        n = strlen(parent);
        key = malloc(n+strlen(logJSON->string)+2);
        strcpy(key, parent);
        key[n++] = '.';
        strcpy(key + n, logJSON->string);
      }
      else{
        key = strdup(logJSON->string);
      }
    }
    switch((logJSON->type)&255){

      case cJSON_String:
        fillData(lf, key, logJSON->valuestring);
        break;

      case cJSON_Number:
        if ((double)logJSON->valueint == logJSON->valuedouble){
          char value_char[16];
          snprintf(value_char, 16, "%i", logJSON->valueint);
          fillData(lf, key, value_char);
        }
        else{
          char value_char[16];
          snprintf(value_char, 16, "%f", logJSON->valuedouble);
          fillData(lf, key, value_char);
        }
        break;

      case cJSON_Array:
        array = logJSON->child;
        value = calloc(256,sizeof(char));
        while (array){
          if (array->type == cJSON_String){
            strcat(value, array->valuestring);
          }
          else if (array->type == cJSON_Number){
            if ((double)array->valueint == array->valuedouble){
              char value_char[16];
              snprintf(value_char, 16, "%i", array->valueint);
              strcat(value, value_char);
            }
            else{
              char value_char[16];
              snprintf(value_char, 16, "%f", array->valuedouble);
              strcat(value, value_char);
            }
          }
          strcat(value, ",");
          array = array->next;
        }
        fillData(lf, key, value);
        cJSON_Delete(array);
        free(value);
        break;

      case cJSON_NULL:
        fillData(lf, key, "NULL");
        break;

      case cJSON_True:
        fillData(lf, key, "true");
        break;

      case cJSON_False:
        fillData(lf, key, "false");
        break;

      case cJSON_Object:
        readJSON (logJSON->child, key, lf);
        break;

    } // switch
    logJSON = next;
    free(key);
  } // while
  cJSON_Delete(next);
}


void *JSON_Decoder_Init()
{
  debug1("%s: Initializing JSON decoder.", ARGV0);
  return (NULL);
}

void *JSON_Decoder_Exec(Eventinfo *lf)
{
  cJSON *logJSON;
  logJSON = cJSON_Parse(lf->log);
  if (!logJSON)
    merror("%s: ERROR: JSON parsing. %s", ARGV0, cJSON_GetErrorPtr());
  else
  {
    readJSON (logJSON, NULL, lf);
    cJSON_Delete(logJSON);
  }

  return (NULL);
}
