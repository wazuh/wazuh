
#include "wdb.h"

int doRollback(rollback_data_t *rollback_data) {
    int result = OS_INVALID;
        int result2;
    struct timeval begin;
    struct timeval end;
    struct timeval diff;

    if (rollback_data != NULL && rollback_data->wdb != NULL) {
        w_inc_global_rollback();
        gettimeofday(&begin, 0);
        if (wdb_rollback2(rollback_data->wdb) < 0) {
            mdebug1("Global DB Cannot rollback transaction");
            snprintf(rollback_data->output, OS_MAXSTR + 1, "err Cannot rollback transaction");
        } else {
            snprintf(rollback_data->output, OS_MAXSTR + 1, "ok");
            result = OS_SUCCESS;
        }

        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_global_rollback_time(diff);
    }
    return result;
}