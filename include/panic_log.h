/*
 * panic_log.h - tolerant parser for Apple panic logs (.ips and plain text).
 *
 * Real artifacts vary. A 27.x log may omit "build" and "socId" from the body,
 * put the SPTM version inline in panicString, and print the backtrace as
 * "lr:/fp:" pairs. The parser records what it finds and leaves the rest empty,
 * because a missing field is itself a clue.
 *
 * Addresses need care. A log carries three separate slides:
 *   KernelCache slide: the fileset slide
 *   Kernel slide: stext - kch + KernelCache slide
 *   Kernel text exec slide TEXT_EXEC - kch + KernelCache slide
 * The last two are header-relative, not plain segment slides. Subtracting one
 * from a runtime address lands on a static kernelcache header, not on the
 * segment's own static base. There is no single slide that maps every frame, so
 * this module exposes the candidates and the report scores them.
 */

#ifndef PANIC_LOG_H
#define PANIC_LOG_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define PL_MAX_FRAMES 96
#define PL_TEXT_MAX 4096
#define PL_MAX_SLIDES 3

/* Bits for panic_log_t.aux_mask. */
enum {
    PL_AUX_FP = 1u << 0,
    PL_AUX_LR = 1u << 1,
    PL_AUX_SP = 1u << 2,
    PL_AUX_PC = 1u << 3,
    PL_AUX_CPSR = 1u << 4,
    PL_AUX_FAR = 1u << 5,
    PL_AUX_ESR = 1u << 6
};

typedef struct panic_log {
    /* Identity */
    char build[96];
    char product[32];
    char soc_id[24];
    char soc_revision[16];
    char kernel_version[256];
    char fileset_uuid[40];
    char sptm_uuid[40];
    char incident[64];
    char crash_reporter_key[80];
    char date[48];
    char bug_type[16];
    int developer_mode;
    int has_developer_mode;

    /* Panic line */
    char panic_string[PL_TEXT_MAX];
    char panic_head[320];
    char panic_reason[192];
    char caller_hex[24];
    uint64_t caller;
    int has_caller;
    int cpu;
    int has_cpu;
    int has_pac_failure;
    char pac_key[8];   /* "DA", "IA", "DB", ... */
    char pac_reg[8];   /* "x16" */

    /* Context */
    char panicked_task[320];
    char panicked_thread[320];
    char panicked_pid[24];
    char panicked_tid[40];
    char panicked_kext[96];
    char sptm_version[64];
    uint64_t sptm_load_address;
    int has_sptm_load_address;

    /* Slides. Only some are present in any given artifact. */
    uint64_t kernelcache_slide;
    uint64_t kernelcache_base;
    uint64_t kernel_slide;
    uint64_t kernel_text_base;
    uint64_t text_exec_slide;
    uint64_t text_exec_base;
    int has_kernelcache_slide;
    int has_kernelcache_base;
    int has_kernel_slide;
    int has_kernel_text_base;
    int has_text_exec_slide;
    int has_text_exec_base;

    /* Registers: regs[0..28] are x0..x28. */
    uint64_t regs[29];
    uint32_t reg_mask;
    uint64_t fp, lr, sp, pc, cpsr, far, esr;
    uint32_t aux_mask;

    /* Stackshot */
    uint64_t frames[PL_MAX_FRAMES];
    size_t nframes;
    int stackshot_succeeded;
    long long stackshot_bytes;
    long long stackshot_uncompressed;
    int note_missing_stackshot;
    int note_resampled_truncated;
    int note_zero_pids;
    int note_exclaves_stackshot;
    char notes[768];

    int recognised;
} panic_log_t;

/*
 * Returns 1 on success, 0 if the input was empty or unreadable. A partial
 * parse is still a success: check the has_* and note_* fields.
 */
int panic_log_parse_file(const char *path, panic_log_t *out, char *err, size_t err_cap);
int panic_log_parse_text(const char *text, panic_log_t *out, char *err, size_t err_cap);

/* Names for reg index 0..28 and aux index 29..35. Writes into buf. */
const char *panic_reg_name(int index, char *buf, size_t cap);

/*
 * Distinct slides present in the log, in the order KernelCache, Kernel, text
 * exec. Returns how many were written, at most PL_MAX_SLIDES. The caller
 * decides which one is right for an address.
 */
size_t panic_log_slides(const panic_log_t *p, uint64_t *out, size_t cap);
#endif /* PANIC_LOG_H */
