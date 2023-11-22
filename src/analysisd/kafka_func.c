#include "kafka_func.h"

bool kafka_productor_init(KafkaProducerConfig* tmp_kafka_producer)
{
    minfo("kafka_productor_init start!");
    rd_kafka_conf_t *conf;
    char errstr[512];
    conf = rd_kafka_conf_new();
    if (rd_kafka_conf_set(conf, "bootstrap.servers", tmp_kafka_producer->brokers, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK){
        minfo("rd_kafka_conf_set:%s", errstr);
        return false;
    }
    tmp_kafka_producer->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!tmp_kafka_producer->rk){
        minfo("%% Failed to create new producer:%s", errstr);
        return false;
    }

    tmp_kafka_producer->rkt = rd_kafka_topic_new(tmp_kafka_producer->rk, tmp_kafka_producer->topic, NULL);
    if (!tmp_kafka_producer->rkt){
        minfo("%% Failed to create topic object: %s", rd_kafka_err2str(rd_kafka_last_error()));
        rd_kafka_destroy(tmp_kafka_producer->rk);
        tmp_kafka_producer->rk = NULL;
        return false;
    }
    minfo("kafka_productor_init end!");
    return true;
}

bool kafka_productor_send_msg(char *buf, int len, KafkaProducerConfig* tmp_kafka_producer)
{
    mdebug2("kafka_productor_send_msg start!");
    if (!tmp_kafka_producer->rk || !tmp_kafka_producer->rkt) {
        minfo("rk or rkt is NULL");
        return false;
    }

    if (len == 0) {
        rd_kafka_poll(tmp_kafka_producer->rk, 0);
        return false;
    }
    bool bRetry = false;
    do{
        if (rd_kafka_produce(tmp_kafka_producer->rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY, buf, len, NULL, 0, NULL) == -1){
            mdebug2("%% Failed to produce to topic %s: %s", rd_kafka_topic_name(tmp_kafka_producer->rkt),
                rd_kafka_err2str(rd_kafka_last_error()));
            if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL){
                rd_kafka_poll(tmp_kafka_producer->rk, 1000);
                bRetry = true;
            }
        }
        else{
            mdebug2("%% Enqueued message (%d bytes) for topic %s", len, rd_kafka_topic_name(tmp_kafka_producer->rkt));
        }
    } while (bRetry);
    rd_kafka_poll(tmp_kafka_producer->rk, 0);
    mdebug2("kafka_productor_send_msg end!");
    return true;
}

void kafka_productor_destroy(KafkaProducerConfig* tmp_kafka_producer)//rd_kafka_t **producer_rk, rd_kafka_topic_t **producer_rkt)
{
    minfo("%% Flushing final message..");
    if (tmp_kafka_producer->rk) {
        rd_kafka_flush(tmp_kafka_producer->rk, 10 * 1000);
    }
    if (tmp_kafka_producer->rkt) {
        rd_kafka_topic_destroy(tmp_kafka_producer->rkt);
        tmp_kafka_producer->rkt = NULL;
    }
    if (tmp_kafka_producer->rk) {
        rd_kafka_destroy(tmp_kafka_producer->rk);
        tmp_kafka_producer->rk = NULL;
    }
}

/*
init all configuration of kafka
*/
bool kafka_consumer_init(KafkaCustomerConfig* tmp_kafka_customer)
{
    minfo("kafka_consumer_init start!");
    rd_kafka_conf_t *conf;
    rd_kafka_topic_conf_t *topic_conf;
    rd_kafka_resp_err_t err;
    char errstr[512];

    /* Kafka configuration */
    conf = rd_kafka_conf_new();

    //topic configuration
    topic_conf = rd_kafka_topic_conf_new();

    /* Consumer groups require a group id */
    if (!tmp_kafka_customer->group)
        tmp_kafka_customer->group = "rdkafka_consumer_example";
    if (rd_kafka_conf_set(conf, "group.id", tmp_kafka_customer->group,
        errstr, sizeof(errstr)) !=
        RD_KAFKA_CONF_OK) {
        minfo("%% %s\n", errstr);
        return false;
    }

    /* Set default topic config for pattern-matched topics. */
    rd_kafka_conf_set_default_topic_conf(conf, topic_conf);

    tmp_kafka_customer->rk = rd_kafka_new(RD_KAFKA_CONSUMER, conf, errstr, sizeof(errstr));
    if (!tmp_kafka_customer->rk){
        minfo("%% Failed to create new consumer:%s", errstr);
        return false;
    }

    if (rd_kafka_brokers_add(tmp_kafka_customer->rk, tmp_kafka_customer->brokers) == 0){
        minfo("%% No valid brokers specified");
        return false;
    }

    rd_kafka_poll_set_consumer(tmp_kafka_customer->rk);

    tmp_kafka_customer->topics = rd_kafka_topic_partition_list_new(1);

    rd_kafka_topic_partition_list_add(tmp_kafka_customer->topics, tmp_kafka_customer->topic, -1);

    if ((err = rd_kafka_subscribe(tmp_kafka_customer->rk, tmp_kafka_customer->topics))){
        minfo("%% Failed to start consuming topics: %s", rd_kafka_err2str(err));
        return false;
    }
    minfo("kafka_consumer_init end!");
    return true;
}

int kafka_consumer_get_msg(KafkaCustomerConfig* tmp_kafka_customer, char** buffer)
{
    rd_kafka_message_t *rkmessage;
    int ret_len = 0;
    rkmessage = rd_kafka_consumer_poll(tmp_kafka_customer->rk, -1);
    if (!rkmessage){
        return 0;
    }

    if (rkmessage->err) {
        minfo("rkmessage error!");
        return 0;
    }

    ret_len = (int)rkmessage->len;
    if(ret_len > 0) {
        minfo("msg:%s", (char *)rkmessage->payload);
        *buffer = strdup((char *)rkmessage->payload);
    }
    rd_kafka_message_destroy(rkmessage);
    return ret_len;
}

void kafka_consumer_destroy(KafkaCustomerConfig* tmp_kafka_customer)
{
    if (tmp_kafka_customer->rk) {
        rd_kafka_resp_err_t err = rd_kafka_consumer_close(tmp_kafka_customer->rk);
        if (err){
            minfo("%% Failed to close consumer: %s", rd_kafka_err2str(err));
        }
        else{
            minfo("%% Consumer closed");
        }
    }
    if (tmp_kafka_customer->topics) {
        rd_kafka_topic_partition_list_destroy(tmp_kafka_customer->topics);
        tmp_kafka_customer->topics = NULL;
    }
    if (tmp_kafka_customer->rk) {
        //destroy kafka handle
        rd_kafka_destroy(tmp_kafka_customer->rk);
        tmp_kafka_customer->rk = NULL;
    }
    int count = 5;
    while (count-- > 0 && rd_kafka_wait_destroyed(1000) == -1){
        mdebug2("Waiting for librdkafka to decommission");
    }
}
