/*
 * breadcrumb.h - write-ahead log for experiments that can panic the device.
 *
 * A kernel panic destroys every buffer in the crashing process. If the last
 * thing you printed went to stdout, you lose it. The only reliable trail is
 * one that reached the filesystem before the fault: each mark is write() plus
 * fsync() on an O_APPEND descriptor, so it survives an immediate reset.
 *
 * Cost is one fsync per mark: use it at stage boundaries, not per iteration.
 * If the device does not come back, the last line in the file names the stage
 * that killed it.
 *
 * POSIX only. Not part of the host build.
 */

#ifndef BREADCRUMB_H
#define BREADCRUMB_H
#include <stddef.h>

typedef struct bc_log bc_log_t;
/* Returns NULL if the path cannot be opened. */
bc_log_t *bc_open(const char *path);
/* Appends one timestamped line and fsyncs. Returns 0 on success. */
int bc_mark(bc_log_t *log, const char *fmt, ...);
/* Appends a hexdump of buf, fsyncing once at the end. */
int bc_hexdump(bc_log_t *log, const char *label, const void *buf, size_t len);
void bc_close(bc_log_t *log);
#endif /* BREADCRUMB_H */
