/* Exercise the production configuration reader and daily compression path. */
#include "shared.h"
#include "monitord/monitord.h"
#include <sys/resource.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    OS_SetName("compression-test");
    if (chdir(argv[1]) < 0) return 3;
    MonitordConfig(argv[2], &mond, 1, 0);
    if (argc > 3 && !strcmp(argv[3], "failure")) {
        struct rlimit limit = { 64, 64 };
        signal(SIGXFSZ, SIG_IGN);
        if (setrlimit(RLIMIT_FSIZE, &limit) < 0) return 4;
        return OS_CompressLogZstd("failure.log") == -1 ? 0 : 5;
    }
    if (argc > 3 && !strcmp(argv[3], "single")) {
        return OS_CompressLogZstd("single.log") == -1 ? 0 : 6;
    }
    manage_files(15, 10, 2026);
    cJSON *options = getMonitorGlobalOptions();
    char *json = cJSON_PrintUnformatted(options);
    puts(json);
    free(json);
    cJSON_Delete(options);
    return 0;
}
