/*
 * Wazuh Module for routing messages.
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #include "wm_inventory_sync.h"
 #include "config/indexer-config.h"
 #include "external/cJSON/cJSON.h"
 #include "sym_load.h"
 #include "inventory_sync/include/inventory_sync.h"
 
 #ifndef HOST_NAME_MAX
 #define HOST_NAME_MAX 255
 #endif
 
 static void* wm_inventory_sync_main(wm_inventory_sync_t* data);
 static void wm_inventory_sync_destroy(wm_inventory_sync_t* data);
 static void wm_inventory_sync_stop(wm_inventory_sync_t* data);
 cJSON* wm_inventory_sync_dump(wm_inventory_sync_t* data);
 
 void* inventory_sync_module = NULL;
 inventory_sync_start_func inventory_sync_start_ptr = NULL;
 inventory_sync_stop_func inventory_sync_stop_ptr = NULL;
 
 const wm_context WM_INVENTORY_SYNC_CONTEXT = {
     .name = "inventory_sync",
     .start = (wm_routine)wm_inventory_sync_main,
     .destroy = (void (*)(void*))wm_inventory_sync_destroy,
     .dump = (cJSON * (*)(const void*)) wm_inventory_sync_dump,
     .sync = NULL,
     .stop = (void (*)(void*))wm_inventory_sync_stop,
     .query = NULL,
 };
 
 static void wm_inventory_sync_log_config(cJSON* config_json)
 {
     if (config_json)
     {
         char* config_str = cJSON_PrintUnformatted(config_json);
         if (config_str)
         {
             mtdebug1(WM_INVENTORY_SYNC_LOGTAG, "%s", config_str);
             cJSON_free(config_str);
         }
     }
 }
 
 void* wm_inventory_sync_main(__attribute__((unused))wm_inventory_sync_t* data)
 {
     mtinfo(WM_INVENTORY_SYNC_LOGTAG, "Starting inventory_sync module.");
     if (inventory_sync_module = so_get_module_handle("inventory_sync"), inventory_sync_module)
     {
        inventory_sync_start_ptr = so_get_function_sym(inventory_sync_module, "inventory_sync_start");
        inventory_sync_stop_ptr = so_get_function_sym(inventory_sync_module, "inventory_sync_stop");
 
         if (inventory_sync_start_ptr)
         {
             cJSON* config_json = cJSON_CreateObject();
 
             if (indexer_config == NULL)
             {
                 cJSON_AddItemToObject(config_json, "indexer", cJSON_CreateObject());
             }
             else
             {
                 cJSON_AddItemToObject(config_json, "indexer", cJSON_Duplicate(indexer_config, TRUE));
             }
 
             /* Add cluster name to vulnerability detection configurations
              * If the cluster is enabled, the cluster name is the cluster name read from the configuration file.
              * If the cluster is disabled, the cluster name is the hostname, known as the manager name.
              */
             const bool cluster_status = get_cluster_status();
             cJSON_AddBoolToObject(config_json, "clusterEnabled", cluster_status);
 
             if (cluster_status)
             {
                 char* cluster_name = get_cluster_name();
                 cJSON_AddStringToObject(config_json, "clusterName", cluster_name);
                 os_free(cluster_name);
 
                 char* manager_node_name = get_node_name();
                 cJSON_AddStringToObject(config_json, "clusterNodeName", manager_node_name);
                 os_free(manager_node_name);
             }
             else
             {
                 char hostname[HOST_NAME_MAX + 1];
                 if (gethostname(hostname, HOST_NAME_MAX) == 0)
                 {
                     cJSON_AddStringToObject(config_json, "clusterName", hostname);
                 }
                 else
                 {
                     cJSON_AddStringToObject(config_json, "clusterName", "undefined");
                 }
 
                 cJSON_AddStringToObject(config_json, "clusterNodeName", "undefined");
             }
 
             wm_inventory_sync_log_config(config_json);
             inventory_sync_start_ptr(mtLoggingFunctionsWrapper, config_json);
             cJSON_Delete(config_json);
         }
         else
         {
             mtwarn(WM_INVENTORY_SYNC_LOGTAG, "Unable to start inventory_sync module.");
             return NULL;
         }
     }
     else
     {
         mtwarn(WM_INVENTORY_SYNC_LOGTAG, "Unable to load inventory_sync module.");
         return NULL;
     }
 
     return NULL;
 }
 
 void wm_inventory_sync_destroy(wm_inventory_sync_t* data)
 {
     free(data);
 }
 
 void wm_inventory_sync_stop(__attribute__((unused)) wm_inventory_sync_t* data)
 {
     mtinfo(WM_INVENTORY_SYNC_LOGTAG, "Stopping inventory_sync module.");
     if (inventory_sync_stop_ptr)
     {
         inventory_sync_stop_ptr();
     }
     else
     {
         mtwarn(WM_INVENTORY_SYNC_LOGTAG, "Unable to stop inventory_sync module.");
     }
 }
 
 wmodule* wm_inventory_sync_read()
 {
     wmodule* module;
 
     os_calloc(1, sizeof(wmodule), module);
     module->context = &WM_INVENTORY_SYNC_CONTEXT;
     module->tag = strdup(module->context->name);
     mtinfo(WM_INVENTORY_SYNC_LOGTAG, "Loaded Inventory sync module.");
     return module;
 }
 
 cJSON* wm_inventory_sync_dump(__attribute__((unused)) wm_inventory_sync_t* data)
 {
     cJSON* root = cJSON_CreateObject();
 
     return root;
 }
 