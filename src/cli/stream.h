#ifndef STREAM_STREAM_H
#define STREAM_STREAM_H

typedef struct stream_t{
    void (*task        )(void *custom);
    int (*isOnline     )(void *custom);
    int (*dataAvailable)(void *custom);
    int (*getChar      )(void *custom, char *c);
    int (*sendChar     )(void *custom, char  c);
    int (*write        )(void *custom, char *buf, int len);
    int (*clearInput   )(void *custom);
    int (*flushOutput  )(void *custom);
    void *custom;
}stream_t;

#endif //STREAM_STREAM_H
