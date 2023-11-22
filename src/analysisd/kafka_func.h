#ifndef KAFKA_FUNC_H
#define KAFKA_FUNC_H
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <shared.h>
#include "librdkafka/rdkafka.h"

typedef struct _KafkaCustomerConfig {
    rd_kafka_t *rk;
    rd_kafka_topic_partition_list_t *topics;
    char *brokers;
    char *group;
    char *topic;
} KafkaCustomerConfig;

typedef struct _KafkaProducerConfig {
    rd_kafka_t *rk;
    rd_kafka_topic_t *rkt;
    char *brokers;
    char *topic;
} KafkaProducerConfig;

bool kafka_productor_init(KafkaProducerConfig* tmp_kafka_producer);

bool kafka_productor_send_msg(char *buf, int len, KafkaProducerConfig* tmp_kafka_producer);

void kafka_productor_destroy(KafkaProducerConfig* tmp_kafka_producer);

bool kafka_consumer_init(KafkaCustomerConfig* tmp_kafka_customer);

int  kafka_consumer_get_msg (KafkaCustomerConfig* tmp_kafka_customer, char** buffer);

void kafka_consumer_destroy(KafkaCustomerConfig* tmp_kafka_customer);

#endif