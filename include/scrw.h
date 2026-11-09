/*
 * scrw.h - System Core Read/Write (SCRW) primitive interface.
 *
 * "System Core" is Apple's term for XNU plus its kernel extensions; SCRW is
 * an arbitrary read/write primitive over that address space. This header is
 * deliberately backend-agnostic: the transport (physmap walk, corrupted
 * kernel object, tfp0 analogue, RPC to a higher-privilege component) lives
 * behind scrw_backend.h so that analysis code never depends on how the
 * primitive is obtained.
 *
 * Design rules enforced here:
 *   1. Fail closed. Writes are refused until explicitly armed, and reads can
 *      be restricted to a window allowlist so a half-working primitive can be
 *      exercised without immediately panicking the device.
 *   2. Every access is bounds- and overflow-checked before it reaches the
 *      backend. A 64-bit wrap in a research primitive is a panic.
 *   3. Errors are values, not crashes. Backend faults are reported, counted
 *      and (optionally) retried; they are never silently swallowed.
 *
 * Accuracy matters more than reach: a primitive that returns wrong bytes is
 * worse than one that returns SCRW_E_FAULT.
 */

#ifndef SCRW_H
#define SCRW_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define SCRW_ABI_VERSION 1u

/*
 * Token required by scrw_arm_writes(). Arming is intentionally awkward: it
 * should be impossible to enable writes by accident from a code path that was
 * only ever meant to read.
 */
#define SCRW_ARM_MAGIC 0x53435257C0DE0001ULL
#define SCRW_MAX_WINDOWS 8

typedef enum scrw_err {
    SCRW_OK = 0,
    SCRW_E_INVAL = 1, /* bad argument from the caller */
    SCRW_E_NOTIMPL = 2, /* backend does not implement this operation */
    SCRW_E_NOMEM = 3,
    SCRW_E_FAULT = 4, /* target rejected the access (would panic) */
    SCRW_E_RANGE = 5, /* blocked by the window allowlist */
    SCRW_E_NOT_ARMED = 6, /* write attempted before scrw_arm_writes() */
    SCRW_E_BACKEND = 7, /* backend misconfigured or absent */
    SCRW_E_STATE = 8, /* wrong state, or a self-test failed */
    SCRW_E_OVERFLOW = 9, /* addr + len wrapped */
    SCRW_E_UNMAPPED = 10 /* kvtophys: no translation for this KVA */
} scrw_err_t;

typedef struct scrw_window {
    uint64_t base;
    uint64_t size;
} scrw_window_t;

typedef struct scrw_caps {
    uint32_t abi_version;
    const char *backend_name;
    uint64_t kernel_slide;
    uint64_t kernel_text_base;
    uint64_t kernel_text_size;
    int can_read;
    int can_write;
    int can_kvtophys;
    int can_kcall;
} scrw_caps_t;

typedef struct scrw_config {
    /*
     * Default 1. Research primitives are usually developed read-only for a
     * long time; writes should be a deliberate, late step.
     */
    int require_arm_for_writes;

    /*
     * Default 0. Set to 1 to confine all access to `windows`. This turns a
     * wobbly primitive into something you can fuzz without touching
     * arbitrary kernel memory.
     */
    int enforce_windows;

    /* Retries on SCRW_E_FAULT per chunk. Keep at 0 while developing: a fault
     * usually means the address is unmapped, and retrying rarely helps. */
    unsigned fault_retries;

    /* Maximum bytes per backend call. 0 means "no split". Useful for backends
     * that are RPC-bound and cannot service large transfers. */
    uint32_t max_io;
    scrw_window_t windows[SCRW_MAX_WINDOWS];
    size_t window_count;
} scrw_config_t;

typedef struct scrw_stats {
    uint64_t reads;
    uint64_t writes;
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t faults;
    uint64_t guard_rejects;
    uint64_t backend_errors;
} scrw_stats_t;

/* One self-test assertion: read u32 at addr, compare against expect under mask. */
typedef struct scrw_check {
    uint64_t addr;
    uint32_t expect;
    uint32_t mask;
    const char *what;
} scrw_check_t;

typedef struct scrw_ctx scrw_ctx_t;

/* Defined in scrw_backend.h. Forward-declared so this header stays standalone. */
struct scrw_backend;
void scrw_config_default(scrw_config_t *cfg);
scrw_err_t scrw_open(scrw_ctx_t **out, const struct scrw_backend *backend, void *backend_ctx, const scrw_config_t *cfg);
void scrw_close(scrw_ctx_t *ctx);
scrw_err_t scrw_caps_get(scrw_ctx_t *ctx, scrw_caps_t *out);
scrw_err_t scrw_stats_get(scrw_ctx_t *ctx, scrw_stats_t *out);

/* Arms writes. Returns SCRW_E_BACKEND if the backend cannot write at all. */
scrw_err_t scrw_arm_writes(scrw_ctx_t *ctx, uint64_t token);
int scrw_writes_armed(scrw_ctx_t *ctx);

/* Adds an allowlist window. Only meaningful with enforce_windows. */
scrw_err_t scrw_add_window(scrw_ctx_t *ctx, uint64_t base, uint64_t size);
scrw_err_t scrw_cread(scrw_ctx_t *ctx, uint64_t addr, void *buf, size_t len, size_t *out_done);
scrw_err_t scrw_cwrite(scrw_ctx_t *ctx, uint64_t addr, const void *buf, size_t len, size_t *out_done);
scrw_err_t scrw_cread_u64(scrw_ctx_t *ctx, uint64_t addr, uint64_t *out);
scrw_err_t scrw_cread_u32(scrw_ctx_t *ctx, uint64_t addr, uint32_t *out);
scrw_err_t scrw_cwrite_u64(scrw_ctx_t *ctx, uint64_t addr, uint64_t val);
scrw_err_t scrw_cwrite_u32(scrw_ctx_t *ctx, uint64_t addr, uint32_t val);

/* Reads a NUL-terminated string. Truncates rather than failing on long input. */
scrw_err_t scrw_cread_cstr(scrw_ctx_t *ctx, uint64_t addr, char *out, size_t cap);

/*
 * Runs a list of assertions (e.g. Mach-O magic at kernel_text_base) and
 * renders a report. Returns SCRW_OK only if every check passed. Run this
 * before trusting any read: a primitive that is silently off by one page or
 * has the wrong slide will produce plausible-looking garbage.
 */
scrw_err_t scrw_selftest(scrw_ctx_t *ctx, const scrw_check_t *checks, size_t n, char *report, size_t report_cap);

const char *scrw_strerror(scrw_err_t err);
const char *scrw_backend_name(const scrw_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SCRW_H */
