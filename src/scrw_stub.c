/*
 * scrw_stub.c - the backend you fill in.
 * The stub below compiles everywhere and returns SCRW_E_NOTIMPL, so the rest
 * of the project builds and its tests pass on a machine with no device.
 */

#include "scrw_backend.h"
#include <string.h>

typedef struct stub_state {
    uint64_t kernel_slide;
    uint64_t kernel_text_base;
    uint64_t kernel_text_size;
    /* Put your primitive's handles here: fds, ports, shared memory, etc. */
} stub_state;

static scrw_err_t stub_open(void *vctx, scrw_caps_t *caps)
{
    stub_state *st = (stub_state *)vctx;

    if (!caps) {
        return SCRW_E_INVAL;
    }
    if (!st) {
        /*
         * No state configured. Still open successfully, but advertise nothing:
         * a stub that cannot read must not claim it can. This is what lets the
         * host build exercise the policy layer with no device and no bug.
         */
        caps->kernel_slide = 0;
        caps->kernel_text_base = 0;
        caps->kernel_text_size = 0;
        caps->can_read = 0;
        caps->can_write = 0;
        caps->can_kvtophys = 0;
        caps->can_kcall = 0;
        return SCRW_OK;
    }

    /*
     * TODO(phase 5): prove the slide before advertising it.
     *
     *   uint32_t magic = 0;
     *   if (raw_kread32(st, st->kernel_text_base, &magic) != SCRW_OK)
     *       return SCRW_E_BACKEND;
     *   if (magic != 0xfeedfacf)
     *       return SCRW_E_BACKEND;
     */

    caps->kernel_slide = st->kernel_slide;
    caps->kernel_text_base = st->kernel_text_base;
    caps->kernel_text_size = st->kernel_text_size;

    /* Flip these on as you implement them. */
    caps->can_read = 0;
    caps->can_write = 0;
    caps->can_kvtophys = 0;
    caps->can_kcall = 0;
    return SCRW_OK;
}

static scrw_err_t stub_read(void *vctx, uint64_t addr, void *buf, size_t len)
{
    stub_state *st = (stub_state *)vctx;

    (void)st;
    (void)addr;
    (void)buf;
    (void)len;

    /*
     * TODO(phase 5): implement the read path.
     *
     * Rules:
     *   - exact or error, never partial
     *   - SCRW_E_FAULT for an address the primitive cannot reach
     *   - no printf/allocations here: this runs in hot paths and possibly in
     *     a signal-adjacent context
     */
    return SCRW_E_NOTIMPL;
}

static scrw_err_t stub_write(void *vctx, uint64_t addr, const void *buf, size_t len)
{
    stub_state *st = (stub_state *)vctx;

    (void)st;
    (void)addr;
    (void)buf;
    (void)len;

    /* TODO(phase 5): implement, then set caps.can_write = 1 in open(). */
    return SCRW_E_NOTIMPL;
}

static const scrw_backend_t g_stub = {
    SCRW_ABI_VERSION,
    "stub",
    stub_open,
    stub_read,
    stub_write,
    NULL,
    NULL
};

const scrw_backend_t *scrw_stub_backend(void)
{
    return &g_stub;
}

/*
 * Typical wiring in a device tool:
 *
 *   stub_state st = { .kernel_slide = slide, .kernel_text_base = base, .kernel_text_size = size };
 *   scrw_ctx_t *ctx = NULL;
 *   if (scrw_open(&ctx, scrw_stub_backend(), &st, NULL) != SCRW_OK) { ... }
 *
 * ...and then everything above the vtable works unchanged.
 */
