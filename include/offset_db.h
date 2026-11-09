/*
 * offset_db.h - build-keyed constants, and a kernel symbol table.
 *
 * Two rules that save days of debugging:
 *   1. Offsets are per build, and the build string is part of the key. Loading
 *      a 27.0 table on a 27.1 device must fail loudly, not silently return a
 *      plausible number.
 *   2. A missing symbol is an error, not a zero. offset_db_require() makes the
 *      failure explicit at the call site.
 */

#ifndef OFFSET_DB_H
#define OFFSET_DB_H

#include <stddef.h>
#include <stdint.h>

/* ---------------- build-keyed constants ---------------- */

typedef struct offset_entry {
    char key[64];
    uint64_t value;
} offset_entry_t;

typedef struct offset_db {
    char build[96];
    offset_entry_t *entries;
    size_t count;
    size_t cap;
} offset_db_t;

/*
 * Loads one [build] section. If want_build is NULL the first section wins.
 * Returns 1 on success, 0 on failure (err is filled in).
 */
int offset_db_load(offset_db_t *db, const char *path, const char *want_build, char *err, size_t err_cap);
int offset_db_get(const offset_db_t *db, const char *key, uint64_t *out);

/* Returns 0 and clears *ok when the key is absent. */
uint64_t offset_db_require(const offset_db_t *db, const char *key, int *ok);
void offset_db_free(offset_db_t *db);

/* ---------------- symbol table ---------------- */

typedef struct sym {
    uint64_t addr;
    char name[96];
} sym_t;

typedef struct symtab {
    sym_t *syms;
    size_t count;
    size_t cap;
    int sorted_by_addr;
    int sorted_by_name;
} symtab_t;

/*
 * Accepts "0xfffffff00b123456 _symbol", "_symbol 0xfffffff00b123456", and the
 * plain "fffffff00b123456 _symbol" form. Header lines and anything without a
 * parseable address are skipped.
 */
int symtab_load(symtab_t *st, const char *path, char *err, size_t err_cap);
void symtab_sort_by_addr(symtab_t *st);
void symtab_sort_by_name(symtab_t *st);

/* Greatest symbol with addr <= target. Requires sorted_by_addr. */
const sym_t *symtab_lookup_addr(const symtab_t *st, uint64_t addr);
/* Exact name match. Requires sorted_by_name. */
const sym_t *symtab_lookup_name(const symtab_t *st, const char *name);

void symtab_free(symtab_t *st);

/*
 * Compares two name-sorted tables. modal is the most common
 * (new.addr - old.addr) among names present in both, matched is how many names
 * are common, modal_count how many share the modal delta, and distinct how many
 * different deltas occur. Returns 0 when there are no common names or when
 * either table is not name-sorted.
 */
typedef struct symtab_delta_stats {
    long long modal;
    size_t matched;
    size_t modal_count;
    size_t distinct;
} symtab_delta_stats_t;

int symtab_delta_stats(const symtab_t *old_tab, const symtab_t *new_tab, symtab_delta_stats_t *out);

#endif /* OFFSET_DB_H */
