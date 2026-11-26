/* Benchmark the actual manager compressors; do not substitute command-line codecs. */
#include "shared.h"
#include "monitord/monitord.h"
#include "../external/zlib/zlib.h"
#include "../external/zstd/lib/zstd.h"
#include <sys/resource.h>

static double seconds(const struct timeval *value) {
    return value->tv_sec + value->tv_usec / 1000000.0;
}

/* Unlike getrusage's inherited pre-exec peak, VmHWM measures this exec image. */
static long peak_rss(long fallback) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return fallback;
    char line[256];
    long value = fallback;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "VmHWM: %ld kB", &value) == 1) break;
    }
    fclose(status);
    return value;
}

/* Readback is a separate library-level benchmark, not a manager feature. */
static int decompress_log(const char *source, const char *destination, int zstd) {
    char input[65536], output[65536];
    FILE *target = fopen(destination, "wb");
    if (!target) return -1;
    int result = 0;
    if (!zstd) {
        gzFile file = gzopen(source, "rb");
        if (!file) { fclose(target); return -1; }
        int count;
        while ((count = gzread(file, output, sizeof(output))) > 0) {
            if (fwrite(output, 1, count, target) != (size_t)count) { result = -1; break; }
        }
        int status = gzclose(file);
        if (count < 0 || status != Z_OK) result = -1;
    } else {
        FILE *file = fopen(source, "rb");
        ZSTD_DCtx *context = ZSTD_createDCtx();
        if (!file || !context) {
            if (file) fclose(file);
            ZSTD_freeDCtx(context);
            fclose(target);
            return -1;
        }
        size_t count, remaining = 1;
        while ((count = fread(input, 1, sizeof(input), file)) > 0 && result == 0) {
            ZSTD_inBuffer in = {input, count, 0};
            ZSTD_outBuffer out;
            do {
                out = (ZSTD_outBuffer){output, sizeof(output), 0};
                remaining = ZSTD_decompressStream(context, &out, &in);
                if (ZSTD_isError(remaining) || fwrite(output, 1, out.pos, target) != out.pos) {
                    result = -1;
                    break;
                }
                if (remaining == 0 && in.pos == in.size) break;
            } while (in.pos < in.size || out.pos == out.size);
        }
        if (ferror(file) || remaining != 0) result = -1;
        fclose(file);
        ZSTD_freeDCtx(context);
    }
    if (fclose(target) != 0) result = -1;
    return result;
}

int main(int argc, char **argv) {
    if (argc < 5) return 2;
    OS_SetName("compression-benchmark");
    if (chdir(argv[1]) != 0) return 3;
    MonitordConfig(argv[2], &mond, 1, 0);
    const int zstd = mond.global.compression_method == W_LOG_COMPRESSION_ZSTD;
    struct timespec begin, end;
    struct rusage before, after;
    int result = 0;
    getrusage(RUSAGE_SELF, &before);
    clock_gettime(CLOCK_MONOTONIC, &begin);
    if (strcmp(argv[3], "baseline") == 0) {
        /* Configuration/library startup floor, without compression work. */
    } else if (strcmp(argv[3], "compress") == 0) {
        if (zstd) result = OS_CompressLogZstd(argv[4]);
        else OS_CompressLog(argv[4]);
    } else if (strcmp(argv[3], "decompress") == 0 && argc == 6) {
        result = decompress_log(argv[4], argv[5], zstd);
    } else if (strcmp(argv[3], "daily") == 0) {
        manage_files(15, 10, 2026);
    } else {
        result = -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    getrusage(RUSAGE_SELF, &after);
    printf("{\"algorithm\":\"%s\",\"operation\":\"%s\",\"wall_s\":%.9f,"
           "\"user_s\":%.9f,\"system_s\":%.9f,\"max_rss_kib\":%ld,"
           "\"zlib_version\":\"%s\",\"zstd_version\":\"%s\",\"result\":%d}\n",
           zstd ? "zstd" : "gzip", argv[3],
           end.tv_sec - begin.tv_sec + (end.tv_nsec - begin.tv_nsec) / 1000000000.0,
           seconds(&after.ru_utime) - seconds(&before.ru_utime),
           seconds(&after.ru_stime) - seconds(&before.ru_stime), peak_rss(after.ru_maxrss),
           zlibVersion(), ZSTD_versionString(), result);
    return result == 0 ? 0 : 4;
}
