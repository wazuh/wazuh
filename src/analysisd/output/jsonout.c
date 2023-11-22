/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "jsonout.h"
#include "alerts/getloglocation.h"
#include "format/to_json.h"

void jsonout_output_event(const Eventinfo *lf, KafkaProducerConfig* tmp_kafka_producer)
{
    //_jflog
    char *json_alert = Eventinfo_to_jsonstr(lf, false, NULL);
    if (strstr(json_alert,"gcp")) {
        mdebug2("Sending gcp event: %s", json_alert);
    }
    mdebug2("jsonout_output_event->json_alert,len:%d, msg:%s",strlen(json_alert), json_alert);
    kafka_productor_send_msg(json_alert, strlen(json_alert), tmp_kafka_producer);
    free(json_alert);
    return;
}
void jsonout_output_archive(const Eventinfo *lf, KafkaProducerConfig* tmp_kafka_producer)
{
    //_ejflog
    char *json_alert;
    if (strcmp(lf->location, "ossec-keepalive") && !strstr(lf->location, "->ossec-keepalive")) {
        json_alert = Eventinfo_to_jsonstr(lf, true, NULL);
        fprintf(_ejflog, "%s\n", json_alert);
        mdebug2("jsonout_output_archive->json_alert,len:%d, msg:%s", strlen(json_alert), json_alert);
        kafka_productor_send_msg(json_alert, strlen(json_alert), tmp_kafka_producer);
        free(json_alert);
    }
}

void jsonout_output_archive_flush(){
    fflush(_ejflog);
}

void jsonout_output_event_flush(){
    fflush(_jflog);
}
