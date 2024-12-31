/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "wdb_state_wrappers.h"

cJSON* __wrap_wdb_create_state_json() {
    return mock_type(cJSON *);
}

// Total counters

void __wrap_w_inc_queries_total() {
    function_called();
}

// Global counters

void __wrap_w_inc_global() {
    function_called();
}

void __wrap_w_inc_global_open_time(){
    function_called();
}

void __wrap_w_inc_global_sql(){
    function_called();
}

void __wrap_w_inc_global_sql_time(){
    function_called();
}

void __wrap_w_inc_global_backup() {
    function_called();
}

void __wrap_w_inc_global_backup_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_vacuum() {
    function_called();
}

void __wrap_w_inc_global_vacuum_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_get_fragmentation() {
    function_called();
}

void __wrap_w_inc_global_get_fragmentation_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

// Global agent counters

void __wrap_w_inc_global_agent_insert_agent() {
    function_called();
}

void __wrap_w_inc_global_agent_insert_agent_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_update_agent_data(){
    function_called();
}

void __wrap_w_inc_global_agent_update_agent_data_time(__attribute__((unused))struct timeval diff){
    function_called();
}

void __wrap_w_inc_global_agent_update_agent_name() {
    function_called();
}

void __wrap_w_inc_global_agent_update_agent_name_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_update_keepalive() {
    function_called();
}

void __wrap_w_inc_global_agent_update_keepalive_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_update_connection_status() {
    function_called();
}

void __wrap_w_inc_global_agent_update_connection_status_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_update_status_code() {
    function_called();
}

void __wrap_w_inc_global_agent_update_status_code_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_reset_agents_connection() {
    function_called();
}

void __wrap_w_inc_global_agent_reset_agents_connection_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_delete_agent() {
    function_called();
}

void __wrap_w_inc_global_agent_delete_agent_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_select_agent_name() {
    function_called();
}

void __wrap_w_inc_global_agent_select_agent_name_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_select_agent_group() {
    function_called();
}

void __wrap_w_inc_global_agent_select_agent_group_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_find_agent() {
    function_called();
}

void __wrap_w_inc_global_agent_find_agent_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_get_agent_info() {
    function_called();
}

void __wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node() {
    function_called();
}

void __wrap_w_inc_global_agent_get_agent_info_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_get_all_agents() {
    function_called();
}

void __wrap_w_inc_global_agent_get_all_agents_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_get_agents_by_connection_status() {
    function_called();
}

void __wrap_w_inc_global_agent_get_agents_by_connection_status_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_disconnect_agents() {
    function_called();
}

void __wrap_w_inc_global_agent_disconnect_agents_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_sync_agent_info_get() {
    function_called();
}

void __wrap_w_inc_global_agent_sync_agent_info_get_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_sync_agent_info_set() {
    function_called();
}

void __wrap_w_inc_global_agent_sync_agent_info_set_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_sync_agent_groups_get() {
    function_called();
}

void __wrap_w_inc_global_agent_sync_agent_groups_get_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_set_agent_groups() {
    function_called();
}

void __wrap_w_inc_global_agent_set_agent_groups_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_get_groups_integrity() {
    function_called();
}

void __wrap_w_inc_global_agent_get_groups_integrity_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_get_distinct_groups() {
    function_called();
}

void __wrap_w_inc_global_agent_get_distinct_groups_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_agent_recalculate_agent_group_hashes() {
    function_called();
}

void __wrap_w_inc_global_agent_recalculate_agent_group_hashes_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

// Global group counters

void __wrap_w_inc_global_group_insert_agent_group() {
    function_called();
}

void __wrap_w_inc_global_group_insert_agent_group_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_group_delete_group() {
    function_called();
}

void __wrap_w_inc_global_group_delete_group_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_group_select_groups() {
    function_called();
}

void __wrap_w_inc_global_group_select_groups_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_group_find_group() {
    function_called();
}

void __wrap_w_inc_global_group_find_group_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

// Global belongs counters

void __wrap_w_inc_global_belongs_select_group_belong() {
    function_called();
}

void __wrap_w_inc_global_belongs_select_group_belong_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

void __wrap_w_inc_global_belongs_get_group_agent() {
    function_called();
}

void __wrap_w_inc_global_belongs_get_group_agent_time(__attribute__((unused))struct timeval diff) {
    function_called();
}

// Global labels counters

void __wrap_w_inc_global_labels_get_labels() {
    function_called();
}

void __wrap_w_inc_global_labels_get_labels_time(__attribute__((unused))struct timeval diff) {
    function_called();
}
