/*
 * scrw_loopback.c - in-memory backend so the policy layer can be tested
 * without a device.
 *
 * The window is a plain malloc'd buffer placed at a fake kernel base. Out of
 * range reads/writes return SCRW_E_FAULT, which is what a real primitive
 * should do for an unmapped address. This backend never panics, which makes it
 * safe for CI and for developing the analysis tools before the exploit works.
 */

#include "scrw_backend.h"
#include <stdlib.h>
#include <string.h>

struct scrw_loopback_ctx {
    unsigned char *mem;
    uint64_t base;
    size_t size;
};

scrw_loopback_ctx_t *scrw_loopback_create(void *mem, uint64_t base, size_t size)
{
    scrw_loopback_ctx_t *ctx;

    if (!mem || size == 0) {
        return NULL;
    }
    ctx = (scrw_loopback_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    ctx->mem = (unsigned char *)mem;
    ctx->base = base;
    ctx->size = size;
    return ctx;
}

void scrw_loopback_destroy(scrw_loopback_ctx_t *ctx)
{
    free(ctx);
}

static int in_window(const scrw_loopback_ctx_t *l, uint64_t addr, size_t len, size_t *off_out)
{
    uint64_t off;

    if (addr < l->base) {
        return 0;
    }
    off = addr - l->base;
    if (off > (uint64_t)l->size) {
        return 0;
    }
    if (len > l->size - (size_t)off) {
        return 0;
    }
    *off_out = (size_t)off;
    return 1;
}

static scrw_err_t lb_open(void *vctx, scrw_caps_t *caps)
{
    scrw_loopback_ctx_t *l = (scrw_loopback_ctx_t *)vctx;

    if (!l || !caps) {
        return SCRW_E_INVAL;
    }
    caps->kernel_slide = 0;
    caps->kernel_text_base = l->base;
    caps->kernel_text_size = (uint64_t)l->size;
    caps->can_read = 1;
    caps->can_write = 1;
    caps->can_kvtophys = 0;
    caps->can_kcall = 0;
    return SCRW_OK;
}

static scrw_err_t lb_read(void *vctx, uint64_t addr, void *buf, size_t len)
{
    scrw_loopback_ctx_t *l = (scrw_loopback_ctx_t *)vctx;
    size_t off = 0;

    if (!l || (!buf && len)) {
        return SCRW_E_INVAL;
    }
    if (!in_window(l, addr, len, &off)) {
        return SCRW_E_FAULT;
    }
    memcpy(buf, l->mem + off, len);
    return SCRW_OK;
}

static scrw_err_t lb_write(void *vctx, uint64_t addr, const void *buf, size_t len)
{
    scrw_loopback_ctx_t *l = (scrw_loopback_ctx_t *)vctx;
    size_t off = 0;

    if (!l || (!buf && len)) {
        return SCRW_E_INVAL;
    }
    if (!in_window(l, addr, len, &off)) {
        return SCRW_E_FAULT;
    }
    memcpy(l->mem + off, buf, len);
    return SCRW_OK;
}

static const scrw_backend_t g_loopback = {
    SCRW_ABI_VERSION,
    "loopback",
    lb_open,
    lb_read,
    lb_write,
    NULL,
    NULL
};

const scrw_backend_t *scrw_loopback_backend(void)
{
    return &g_loopback;
}
