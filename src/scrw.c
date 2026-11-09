/*
 * scrw.c - policy layer for the SCRW primitive.
 *
 * Responsibilities: argument validation, overflow checks, the window
 * allowlist, write arming, chunking, statistics, and self-tests. The transport
 * is entirely in the backend.
 */

#include "scrw.h"
#include "scrw_backend.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct scrw_ctx {
    scrw_backend_t be;
    void *be_ctx;
    scrw_config_t cfg;
    scrw_caps_t caps;
    scrw_stats_t stats;
    int armed;
};

void scrw_config_default(scrw_config_t *cfg)
{
    if (!cfg) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->require_arm_for_writes = 1;
    cfg->enforce_windows = 0;
    cfg->fault_retries = 0;
    cfg->max_io = 0;
    cfg->window_count = 0;
}

static int window_contains(const scrw_window_t *w, uint64_t addr, uint64_t end)
{
    uint64_t wend;

    if (w->size == 0) {
        return 0;
    }
    if (w->base > UINT64_MAX - w->size) {
        return 0;
    }
    wend = w->base + w->size;
    /* [addr, end) inside [base, wend) */
    return addr >= w->base && end <= wend;
}

static int guard_allows(const scrw_ctx_t *c, uint64_t addr, uint64_t end)
{
    size_t i;

    if (!c->cfg.enforce_windows) {
        return 1;
    }
    if (c->cfg.window_count == 0) {
        /* Fail closed: enforcement with no windows permits nothing. */
        return 0;
    }
    for (i = 0; i < c->cfg.window_count; i++) {
        if (window_contains(&c->cfg.windows[i], addr, end)) {
            return 1;
        }
    }
    return 0;
}

static int append(char *buf, size_t cap, size_t *used, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (!buf || cap == 0 || *used >= cap) {
        return 0;
    }
    va_start(ap, fmt);
    n = vsnprintf(buf + *used, cap - *used, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return 0;
    }
    if ((size_t)n >= cap - *used) {
        *used = cap - 1;
        return 0;
    }
    *used += (size_t)n;
    return 1;
}

scrw_err_t scrw_open(scrw_ctx_t **out, const scrw_backend_t *backend, void *backend_ctx, const scrw_config_t *cfg)
{
    scrw_ctx_t *c;
    scrw_err_t e;

    if (!out) {
        return SCRW_E_INVAL;
    }
    *out = NULL;
    if (!backend) {
        return SCRW_E_INVAL;
    }
    if (backend->abi_version != SCRW_ABI_VERSION) {
        return SCRW_E_BACKEND;
    }
    if (!backend->open || !backend->read) {
        return SCRW_E_BACKEND;
    }
    c = (scrw_ctx_t *)calloc(1, sizeof(*c));
    if (!c) {
        return SCRW_E_NOMEM;
    }
    c->be = *backend;
    c->be_ctx = backend_ctx;
    if (cfg) {
        c->cfg = *cfg;
    } else {
        scrw_config_default(&c->cfg);
    }
    if (c->cfg.window_count > SCRW_MAX_WINDOWS) {
        free(c);
        return SCRW_E_INVAL;
    }

    c->caps.abi_version = SCRW_ABI_VERSION;
    c->caps.backend_name = c->be.name ? c->be.name : "(unnamed)";

    e = c->be.open(c->be_ctx, &c->caps);
    if (e != SCRW_OK) {
        free(c);
        return e;
    }
    *out = c;
    return SCRW_OK;
}

void scrw_close(scrw_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    if (ctx->be.close) {
        ctx->be.close(ctx->be_ctx);
    }
    free(ctx);
}

scrw_err_t scrw_caps_get(scrw_ctx_t *ctx, scrw_caps_t *out)
{
    if (!ctx || !out) {
        return SCRW_E_INVAL;
    }
    *out = ctx->caps;
    return SCRW_OK;
}

scrw_err_t scrw_stats_get(scrw_ctx_t *ctx, scrw_stats_t *out)
{
    if (!ctx || !out) {
        return SCRW_E_INVAL;
    }
    *out = ctx->stats;
    return SCRW_OK;
}

scrw_err_t scrw_arm_writes(scrw_ctx_t *ctx, uint64_t token)
{
    if (!ctx) {
        return SCRW_E_INVAL;
    }
    if (token != SCRW_ARM_MAGIC) {
        return SCRW_E_INVAL;
    }
    if (!ctx->caps.can_write || !ctx->be.write) {
        return SCRW_E_BACKEND;
    }
    ctx->armed = 1;
    return SCRW_OK;
}

int scrw_writes_armed(scrw_ctx_t *ctx)
{
    return ctx && ctx->armed;
}

scrw_err_t scrw_add_window(scrw_ctx_t *ctx, uint64_t base, uint64_t size)
{
    if (!ctx) {
        return SCRW_E_INVAL;
    }
    if (ctx->cfg.window_count >= SCRW_MAX_WINDOWS) {
        return SCRW_E_INVAL;
    }
    if (size == 0 || base > UINT64_MAX - size) {
        return SCRW_E_INVAL;
    }
    ctx->cfg.windows[ctx->cfg.window_count].base = base;
    ctx->cfg.windows[ctx->cfg.window_count].size = size;
    ctx->cfg.window_count++;
    return SCRW_OK;
}

scrw_err_t scrw_cread(scrw_ctx_t *ctx, uint64_t addr, void *buf, size_t len, size_t *out_done)
{
    size_t done = 0;
    scrw_err_t e = SCRW_OK;

    if (out_done) {
        *out_done = 0;
    }
    if (!ctx) {
        return SCRW_E_INVAL;
    }
    if (!buf && len) {
        return SCRW_E_INVAL;
    }
    if (len == 0) {
        return SCRW_OK;
    }
    if (addr > UINT64_MAX - (uint64_t)len) {
        return SCRW_E_OVERFLOW;
    }
    if (!guard_allows(ctx, addr, addr + (uint64_t)len)) {
        ctx->stats.guard_rejects++;
        return SCRW_E_RANGE;
    }

    while (done < len) {
        size_t chunk = len - done;
        unsigned attempt;

        if (ctx->cfg.max_io && chunk > (size_t)ctx->cfg.max_io) {
            chunk = (size_t)ctx->cfg.max_io;
        }
        for (attempt = 0; attempt <= ctx->cfg.fault_retries; attempt++) {
            e = ctx->be.read(ctx->be_ctx, addr + (uint64_t)done, (unsigned char *)buf + done, chunk);
            if (e != SCRW_E_FAULT) {
                break;
            }
            ctx->stats.faults++;
        }
        if (e != SCRW_OK) {
            break;
        }
        done += chunk;
    }

    ctx->stats.reads++;
    ctx->stats.bytes_read += done;
    if (e != SCRW_OK && e != SCRW_E_FAULT) {
        ctx->stats.backend_errors++;
    }
    if (out_done) {
        *out_done = done;
    }
    return e;
}

scrw_err_t scrw_cwrite(scrw_ctx_t *ctx, uint64_t addr, const void *buf, size_t len, size_t *out_done)
{
    size_t done = 0;
    scrw_err_t e = SCRW_OK;

    if (out_done) {
        *out_done = 0;
    }
    if (!ctx) {
        return SCRW_E_INVAL;
    }
    if (!buf && len) {
        return SCRW_E_INVAL;
    }
    if (len == 0) {
        return SCRW_OK;
    }
    if (ctx->cfg.require_arm_for_writes && !ctx->armed) {
        return SCRW_E_NOT_ARMED;
    }
    if (!ctx->be.write) {
        return SCRW_E_NOTIMPL;
    }
    if (addr > UINT64_MAX - (uint64_t)len) {
        return SCRW_E_OVERFLOW;
    }
    if (!guard_allows(ctx, addr, addr + (uint64_t)len)) {
        ctx->stats.guard_rejects++;
        return SCRW_E_RANGE;
    }

    while (done < len) {
        size_t chunk = len - done;
        unsigned attempt;

        if (ctx->cfg.max_io && chunk > (size_t)ctx->cfg.max_io) {
            chunk = (size_t)ctx->cfg.max_io;
        }
        for (attempt = 0; attempt <= ctx->cfg.fault_retries; attempt++) {
            e = ctx->be.write(ctx->be_ctx, addr + (uint64_t)done, (const unsigned char *)buf + done, chunk);
            if (e != SCRW_E_FAULT) {
                break;
            }
            ctx->stats.faults++;
        }
        if (e != SCRW_OK) {
            break;
        }
        done += chunk;
    }

    ctx->stats.writes++;
    ctx->stats.bytes_written += done;
    if (e != SCRW_OK && e != SCRW_E_FAULT) {
        ctx->stats.backend_errors++;
    }
    if (out_done) {
        *out_done = done;
    }
    return e;
}

scrw_err_t scrw_cread_u64(scrw_ctx_t *ctx, uint64_t addr, uint64_t *out)
{
    size_t done = 0;
    scrw_err_t e;

    if (!out) {
        return SCRW_E_INVAL;
    }
    e = scrw_cread(ctx, addr, out, sizeof(*out), &done);
    return (e == SCRW_OK && done == sizeof(*out)) ? SCRW_OK : (e == SCRW_OK ? SCRW_E_FAULT : e);
}

scrw_err_t scrw_cread_u32(scrw_ctx_t *ctx, uint64_t addr, uint32_t *out)
{
    size_t done = 0;
    scrw_err_t e;

    if (!out) {
        return SCRW_E_INVAL;
    }
    e = scrw_cread(ctx, addr, out, sizeof(*out), &done);
    return (e == SCRW_OK && done == sizeof(*out)) ? SCRW_OK : (e == SCRW_OK ? SCRW_E_FAULT : e);
}

scrw_err_t scrw_cwrite_u64(scrw_ctx_t *ctx, uint64_t addr, uint64_t val)
{
    return scrw_cwrite(ctx, addr, &val, sizeof(val), NULL);
}

scrw_err_t scrw_cwrite_u32(scrw_ctx_t *ctx, uint64_t addr, uint32_t val)
{
    return scrw_cwrite(ctx, addr, &val, sizeof(val), NULL);
}

scrw_err_t scrw_cread_cstr(scrw_ctx_t *ctx, uint64_t addr, char *out, size_t cap)
{
    size_t off = 0;

    if (!out || cap == 0) {
        return SCRW_E_INVAL;
    }
    out[0] = '\0';

    while (off + 1 < cap) {
        unsigned char tmp[64];
        size_t want = cap - 1 - off;
        size_t got = 0;
        size_t i;
        scrw_err_t e;

        if (want > sizeof(tmp)) {
            want = sizeof(tmp);
        }
        e = scrw_cread(ctx, addr + (uint64_t)off, tmp, want, &got);
        if (e != SCRW_OK) {
            out[off] = '\0';
            return e;
        }
        for (i = 0; i < got; i++) {
            out[off++] = (char)tmp[i];
            if (tmp[i] == 0) {
                return SCRW_OK;
            }
        }
        if (got == 0) {
            break;
        }
    }
    out[off] = '\0';
    return SCRW_OK;
}

scrw_err_t scrw_selftest(scrw_ctx_t *ctx, const scrw_check_t *checks, size_t n, char *report, size_t report_cap)
{
    size_t i;
    size_t used = 0;
    int failed = 0;

    if (report && report_cap) {
        report[0] = '\0';
    }
    if (!ctx || (n && !checks)) {
        return SCRW_E_INVAL;
    }

    for (i = 0; i < n; i++) {
        uint32_t v = 0;
        scrw_err_t e = scrw_cread_u32(ctx, checks[i].addr, &v);
        int ok = (e == SCRW_OK) && ((v & checks[i].mask) == (checks[i].expect & checks[i].mask));

        if (!ok) {
            failed++;
        }
        append(report, report_cap, &used, "[%s] %-24s addr=0x%016llx got=0x%08x want=0x%08x mask=0x%08x%s%s\n", ok ? "ok" : "FAIL", checks[i].what ? checks[i].what : "?", (unsigned long long)checks[i].addr, v, checks[i].expect, checks[i].mask, e != SCRW_OK ? " err=" : "", e != SCRW_OK ? scrw_strerror(e) : "");
    }
    append(report, report_cap, &used, "selftest: %zu checks, %d failed\n", n, failed);
    return failed ? SCRW_E_STATE : SCRW_OK;
}

const char *scrw_strerror(scrw_err_t err)
{
    switch (err) {
    case SCRW_OK:
        return "ok";
    case SCRW_E_INVAL:
        return "invalid argument";
    case SCRW_E_NOTIMPL:
        return "not implemented";
    case SCRW_E_NOMEM:
        return "out of memory";
    case SCRW_E_FAULT:
        return "target fault (access would panic)";
    case SCRW_E_RANGE:
        return "blocked by window allowlist";
    case SCRW_E_NOT_ARMED:
        return "writes not armed";
    case SCRW_E_BACKEND:
        return "backend error";
    case SCRW_E_STATE:
        return "bad state";
    case SCRW_E_OVERFLOW:
        return "address range overflow";
    case SCRW_E_UNMAPPED:
        return "kernel VA has no translation";
    default:
        return "unknown";
    }
}

const char *scrw_backend_name(const scrw_ctx_t *ctx)
{
    return (ctx && ctx->caps.backend_name) ? ctx->caps.backend_name : "(none)";
}
