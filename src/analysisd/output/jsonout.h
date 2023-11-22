/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef JSONOUT_H
#define JSONOUT_H

#include "eventinfo.h"
#include "../kafka_func.h"

void jsonout_output_event(const Eventinfo *lf, KafkaProducerConfig* tmp_kafka_producer);
void jsonout_output_archive(const Eventinfo *lf, KafkaProducerConfig* tmp_kafka_producer);
void jsonout_output_archive_flush();
void jsonout_output_event_flush();

#endif /* JSONOUT_H */
