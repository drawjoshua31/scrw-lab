/*
 * scrw_backend.h - transport vtable for the SCRW layer.
 *
 * A backend is the *how*: it turns (address, length) into bytes. Everything
 * above it (scrw.c) is the *policy*: bounds checks, arming, allowlists,
 * statistics. Keeping the two apart is what lets the project survive a change
 * of primitive without rewriting the analysis tools.
 *
 * Contract for implementers:
 *   - read()/write() must be *exact or fail*: fill all len bytes or return an
 *     error. Partial success is not allowed; the caller splits large requests
 *     itself via cfg.max_io.
 *   - Return SCRW_E_FAULT, never abort(), when the target address is not
 *     accessible. In kernel space the failure mode is a panic, so the caller
 *     is responsible for probing safely; the backend must still report it.
 *   - read()/write() may be called concurrently only if you document it.
 *     The default assumption is single-threaded.
 */

#ifndef SCRW_BACKEND_H
#define SCRW_BACKEND_H
#include "scrw.h"

struct scrw_backend {
    uint32_t abi_version;
    const char *name;

    /*
     * Called once from scrw_open(). Fill in caps (slide, text base/size and
     * which operations are actually available). Returning an error aborts the
     * open, which is what you want if the bug failed to trigger.
     */
    scrw_err_t (*open)(void *ctx, scrw_caps_t *caps);
    scrw_err_t (*read)(void *ctx, uint64_t addr, void *buf, size_t len);
    scrw_err_t (*write)(void *ctx, uint64_t addr, const void *buf, size_t len);
    /* Optional. Convert a kernel VA to a physical address. */
    scrw_err_t (*kvtophys)(void *ctx, uint64_t kva, uint64_t *pa);
    /* Optional. Called from scrw_close() before the context is freed. */
    void (*close)(void *ctx);
};

typedef struct scrw_backend scrw_backend_t;

/*
 * Device backend skeleton: src/scrw_stub.c. Every operation returns
 * SCRW_E_NOTIMPL until you fill it in. Start here.
 */
const scrw_backend_t *scrw_stub_backend(void);

/*
 * Host backend for tests: a fake kernel backed by a plain memory buffer with
 * a configurable base address. Lets you exercise the policy layer, the tools
 * and the panic-report pipeline with no device attached.
 */
typedef struct scrw_loopback_ctx scrw_loopback_ctx_t;

scrw_loopback_ctx_t *scrw_loopback_create(void *mem, uint64_t base, size_t size);
void scrw_loopback_destroy(scrw_loopback_ctx_t *ctx);
const scrw_backend_t *scrw_loopback_backend(void);

#endif /* SCRW_BACKEND_H */
