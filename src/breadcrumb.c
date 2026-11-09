/*
 * breadcrumb.c - panic-survivable write-ahead log.
 *
 * One fsync per mark. That is the whole point: a mark that is still in the
 * page cache when the kernel dies is worthless, because the reset that follows
 * a panic discards it.
 */

#include "breadcrumb.h"
#if defined(_WIN32)
#include <stdarg.h>
#include <stdio.h>

bc_log_t *bc_open(const char *path)
{
    (void)path;
    return NULL;
}

int bc_mark(bc_log_t *log, const char *fmt, ...)
{
    (void)log;
    (void)fmt;
    return -1;
}

int bc_hexdump(bc_log_t *log, const char *label, const void *buf, size_t len)
{
    (void)log;
    (void)label;
    (void)buf;
    (void)len;
    return -1;
}

void bc_close(bc_log_t *log)
{
    (void)log;
}

#else

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct bc_log {
    int fd;
    char path[256];
};

bc_log_t *bc_open(const char *path)
{
    bc_log_t *log;
    int fd;

    if (!path) {
        return NULL;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return NULL;
    }
    log = (bc_log_t *)calloc(1, sizeof(*log));
    if (!log) {
        close(fd);
        return NULL;
    }
    log->fd = fd;
    snprintf(log->path, sizeof(log->path), "%s", path);
    return log;
}

static int write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            /* A zero-byte write on a non-empty buffer makes no progress. */
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static void stamp(char *buf, size_t cap)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        snprintf(buf, cap, "?");
        return;
    }
    snprintf(buf, cap, "%lld.%03ld", (long long)ts.tv_sec, (long)(ts.tv_nsec / 1000000));
}

int bc_mark(bc_log_t *log, const char *fmt, ...)
{
    char line[512];
    char ts[48];
    va_list ap;
    int n;
    size_t used;

    if (!log || log->fd < 0 || !fmt) {
        return -1;
    }
    stamp(ts, sizeof(ts));
    n = snprintf(line, sizeof(line), "%s ", ts);
    if (n < 0 || (size_t)n >= sizeof(line)) {
        return -1;
    }
    used = (size_t)n;

    va_start(ap, fmt);
    n = vsnprintf(line + used, sizeof(line) - used, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return -1;
    }
    used += (size_t)n;
    if (used > sizeof(line) - 2) {
        used = sizeof(line) - 2;
    }
    line[used++] = '\n';

    if (write_all(log->fd, line, used) != 0) {
        return -1;
    }
    /* The durability that makes this useful across a panic. */
    if (fsync(log->fd) != 0) {
        return -1;
    }
    return 0;
}

int bc_hexdump(bc_log_t *log, const char *label, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    char line[160];
    size_t i;

    if (!log || log->fd < 0) {
        return -1;
    }
    if (bc_mark(log, "%s: %zu bytes", label ? label : "dump", len) != 0) {
        return -1;
    }
    for (i = 0; i < len; i += 16) {
        size_t j;
        size_t used = 0;
        int n = snprintf(line, sizeof(line), "  %04zx  ", i);
        if (n < 0) {
            return -1;
        }
        used = (size_t)n;
        for (j = 0; j < 16 && i + j < len; j++) {
            n = snprintf(line + used, sizeof(line) - used, "%02x ", p[i + j]);
            if (n < 0) {
                return -1;
            }
            used += (size_t)n;
        }
        while (used + 1 < sizeof(line) && used < 62) {
            line[used++] = ' ';
        }
        for (j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = p[i + j];
            n = snprintf(line + used, sizeof(line) - used, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
            if (n < 0) {
                return -1;
            }
            used += (size_t)n;
        }
        line[used++] = '\n';
        if (write_all(log->fd, line, used) != 0) {
            return -1;
        }
    }
    if (fsync(log->fd) != 0) {
        return -1;
    }
    return 0;
}

void bc_close(bc_log_t *log)
{
    if (!log) {
        return;
    }
    if (log->fd >= 0) {
        fsync(log->fd);
        close(log->fd);
    }
    free(log);
}

#endif /* _WIN32 */
