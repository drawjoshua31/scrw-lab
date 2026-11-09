/*
 * poc_pac_probe.c - instrumented, bisectable harness for a crash-only bug.
 *
 * This file contains no vulnerability. It is the scaffolding around yours:
 * it parameterises the trigger, writes a breadcrumb that survives the panic,
 * and enforces the one-variable-per-boot discipline that makes a crash-only
 * bug analysable at all.
 *
 * Why this shape:
 *
 *   A kernel that panics gives you exactly one data point per boot. If you
 *   change three things between boots you learn nothing, because you cannot
 *   attribute the outcome. So the harness takes a full parameter set, records
 *   it before it does anything dangerous, runs exactly one attempt, and
 *   records that it survived. The next boot's parameters differ in one field.
 *
 *   The marker is the other half. Spray a unique 64-bit value; if it shows up
 *   in the panic's registers, you control the faulting value, which is the
 *   difference between "a crash" and "a primitive in progress". panicdump
 *   --marker finds it for you.
 *
 * Build (device): see scripts/build_device.sh. Requires a signing identity.
 *
 * Usage:
 *   poc_pac_probe --log /var/mobile/pac-probe.log --stage 3 --count 512 \
 *                 --size 0x400 --threads 4 --delay-us 250 \
 *                 --marker 0x53524357deadbeef
 *
 *   poc_pac_probe --plan        # print the bisect matrix, run nothing
 *   poc_pac_probe --self-check  # verify the breadcrumb log works
 *
 * Run it from an app you control (Developer Mode is on, per your log). Each
 * invocation is one attempt. Reboot after a panic, change one field, repeat.
 */

#include "breadcrumb.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct trigger_params {
    int stage;
    unsigned count;
    unsigned size;
    unsigned threads;
    unsigned delay_us;
    uint64_t marker;
    uint64_t seed;
} trigger_params_t;

/*
 * Your bug goes here, in another file, compiled into the same binary:
 *
 *   int avet_trigger(const trigger_params_t *p);
 *
 * It must do exactly one attempt and return 0 if the process is still alive.
 * Do not loop internally: the harness owns the loop, the logging and the
 * recovery. If the trigger needs to allocate, spray, or race, that belongs
 * inside the trigger, parameterised by the struct.
 */
int avet_trigger(const trigger_params_t *p);

__attribute__((weak)) int avet_trigger(const trigger_params_t *p)
{
    (void)p;
    return -1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [options]\n"
            "  --log <path>      breadcrumb log (default /var/mobile/pac-probe.log)\n"
            "  --stage <n>       trigger stage\n"
            "  --count <n>       object/spray count\n"
            "  --size <n>        object size (accepts 0x)\n"
            "  --threads <n>     racing threads\n"
            "  --delay-us <n>    delay between operations\n"
            "  --marker <hex>    unique value to spray (default 0x53524357deadbeef)\n"
            "  --seed <n>        PRNG seed, so a run is reproducible\n"
            "  --plan            print the bisect matrix and exit\n"
            "  --self-check      verify breadcrumb durability and exit\n",
            argv0);
}

static int self_check(const char *log_path)
{
    bc_log_t *log = bc_open(log_path);
    int i;

    if (!log) {
        fprintf(stderr, "self-check: cannot open %s\n", log_path);
        return 1;
    }
    for (i = 0; i < 3; i++) {
        if (bc_mark(log, "self-check %d", i) != 0) {
            fprintf(stderr, "self-check: write/fsync failed\n");
            bc_close(log);
            return 1;
        }
    }
    bc_close(log);
    printf("self-check: wrote 3 marks to %s\n", log_path);
    printf("now reboot the device and confirm the marks are still there.\n");
    printf("if they are not, the log is not durable and the harness is useless.\n");
    return 0;
}

static void print_plan(const trigger_params_t *base)
{
    /* A coarse one-factor-at-a-time sweep. Run one line per boot. */
    static const unsigned counts[] = {64, 256, 1024};
    static const unsigned sizes[] = {0x40, 0x100, 0x400};
    static const unsigned delays[] = {0, 100, 1000};
    size_t i;

    printf("bisect plan (one line per boot; change nothing else):\n");
    printf("  stage  count  size   delay  marker\n");
    for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        printf("%-6d %-6u 0x%03x  %-6u 0x%016llx\n", base->stage, counts[i], base->size, base->delay_us, (unsigned long long)base->marker);
    }
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        printf("%-6d %-6u 0x%03x  %-6u 0x%016llx\n", base->stage, base->count, sizes[i], base->delay_us, (unsigned long long)base->marker);
    }
    for (i = 0; i < sizeof(delays) / sizeof(delays[0]); i++) {
        printf("%-6d %-6u 0x%03x  %-6u 0x%016llx\n", base->stage, base->count, base->size, delays[i], (unsigned long long)base->marker);
    }
    printf("\nafter each run, pull the panic artifact and run:\n");
    printf("  panicdump --marker 0x%016llx --symbols <syms> <artifact>\n",
           (unsigned long long)base->marker);
    printf("record the caller offset. A stable offset is a stable site.\n");
}

int main(int argc, char **argv)
{
    trigger_params_t p;
    const char *log_path = "/var/mobile/pac-probe.log";
    int plan = 0;
    int check = 0;
    int i;
    int rc;
    bc_log_t *log;

    memset(&p, 0, sizeof(p));
    p.stage = 1;
    p.count = 256;
    p.size = 0x100;
    p.threads = 1;
    p.delay_us = 100;
    p.marker = 0x53524357deadbeefULL;
    p.seed = 1;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(a, "--stage") == 0 && i + 1 < argc) {
            p.stage = atoi(argv[++i]);
        } else if (strcmp(a, "--count") == 0 && i + 1 < argc) {
            p.count = (unsigned)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(a, "--size") == 0 && i + 1 < argc) {
            p.size = (unsigned)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(a, "--threads") == 0 && i + 1 < argc) {
            p.threads = (unsigned)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(a, "--delay-us") == 0 && i + 1 < argc) {
            p.delay_us = (unsigned)strtoul(argv[++i], NULL, 0);
        } else if (strcmp(a, "--marker") == 0 && i + 1 < argc) {
            p.marker = strtoull(argv[++i], NULL, 16);
        } else if (strcmp(a, "--seed") == 0 && i + 1 < argc) {
            p.seed = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(a, "--plan") == 0) {
            plan = 1;
        } else if (strcmp(a, "--self-check") == 0) {
            check = 1;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown option: %s\n", a);
            usage(argv[0]);
            return 1;
        }
    }

    if (check) {
        return self_check(log_path);
    }
    if (plan) {
        print_plan(&p);
        return 0;
    }

    log = bc_open(log_path);
    if (!log) {
        fprintf(stderr, "cannot open breadcrumb log %s\n", log_path);
        return 1;
    }

    /*
     * Every mark is fsynced. If the device comes back with a panic, the last
     * line in this file is the stage that died.
     */
    bc_mark(log, "=== run start marker=0x%016llx seed=%llu", (unsigned long long)p.marker, (unsigned long long)p.seed);
    bc_mark(log, "params stage=%d count=%u size=0x%x threads=%u delay_us=%u", p.stage, p.count, p.size, p.threads, p.delay_us);
    bc_mark(log, "about to call trigger");

    fflush(stdout);
    rc = avet_trigger(&p);

    bc_mark(log, "trigger returned %d (survived)", rc);
    bc_mark(log, "=== run end");

    printf("trigger rc=%d\n", rc);
    if (rc == -1) {
        printf("\navet_trigger() is the weak fallback: nothing ran.\n" "Implement it against your bug, then rebuild.\n");
    }
    bc_close(log);
    return 0;
}
