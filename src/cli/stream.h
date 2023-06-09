#ifndef STREAM_STREAM_H
#define STREAM_STREAM_H

typedef struct stream_t{
    void (*task)(void);
    int (*isOnline)(void);
    int (*dataAvailable)(void);
    int (*getChar)(char *c);
    int (*sendChar)(char c);
    int (*write)(char *buf, int len);
    int (*clearInput)(void);
    int (*flushOutput)(void);
}stream_t;

#endif //STREAM_STREAM_H
