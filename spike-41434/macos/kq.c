// kqueue EVFILT_PROC NOTE_EXIT|NOTE_EXITSTATUS on a pid. Usage: kq <pid> (non-child) or kq (forks a child that exits 9).
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>

int main(int argc, char **argv) {
    pid_t pid = argc > 1 ? atoi(argv[1]) : fork();
    if (!pid) {
        usleep(200000);
        _exit(9);
    }
    int kq = kqueue();
    struct kevent ev;
    EV_SET(&ev, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT | NOTE_EXITSTATUS, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
        perror("kevent register");
        return 1;
    }
    kevent(kq, NULL, 0, &ev, 1, NULL);
    printf("%s pid=%d NOTE_EXITSTATUS=%s data=%ld exit_code=%ld\n", argc > 1 ? "non-child" : "child", pid,
           ev.fflags & NOTE_EXITSTATUS ? "yes" : "no", (long)ev.data, (long)(ev.data >> 8) & 0xff);
}
