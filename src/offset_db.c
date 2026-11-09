/*
 * offset_db.c - build-keyed constants and kernel symbol tables.
 */

#include "offset_db.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static char *trim(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return s;
}

static int is_hex_token(const char *s)
{
    size_t n = 0;

    if (!s) {
        return 0;
    }
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return 1;
    }
    for (; *s; s++) {
        if (!isxdigit((unsigned char)*s)) {
            return 0;
        }
        n++;
    }
    return n >= 8;
}

/* ------------------------------------------------------------------ */
/* offset database                                                     */
/* ------------------------------------------------------------------ */
static int db_push(offset_db_t *db, const char *key, uint64_t value)
{
    if (db->count == db->cap) {
        size_t ncap = db->cap ? db->cap * 2 : 32;
        offset_entry_t *n = (offset_entry_t *)realloc(db->entries, ncap * sizeof(*n));
        if (!n) {
            return 0;
        }
        db->entries = n;
        db->cap = ncap;
    }
    snprintf(db->entries[db->count].key, sizeof(db->entries[db->count].key), "%s", key);
    db->entries[db->count].value = value;
    db->count++;
    return 1;
}

int offset_db_load(offset_db_t *db, const char *path, const char *want_build, char *err, size_t err_cap)
{
    FILE *f;
    char line[512];
    char section[96];
    int have_section = 0;
    int taken_section = 0;

    if (err && err_cap) {
        err[0] = '\0';
    }
    if (!db || !path) {
        return 0;
    }
    memset(db, 0, sizeof(*db));

    f = fopen(path, "r");
    if (!f) {
        if (err && err_cap) {
            snprintf(err, err_cap, "cannot open %s", path);
        }
        return 0;
    }

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        char *eq;

        if (*s == '\0' || *s == '#' || *s == ';') {
            continue;
        }
        if (*s == '[') {
            char *close = strchr(s, ']');
            if (!close) {
                continue;
            }
            *close = '\0';
            snprintf(section, sizeof(section), "%s", trim(s + 1));
            have_section = 1;
            continue;
        }
        eq = strchr(s, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        {
            char *key = trim(s);
            char *val = trim(eq + 1);
            char *end = NULL;
            unsigned long long v;

            if (!have_section) {
                continue;
            }
            if (want_build && strcmp(section, want_build) != 0) {
                continue;
            }
            if (!want_build && taken_section &&
                strcmp(section, db->build) != 0) {
                /* Only the first section is used when no build is requested. */
                continue;
            }
            if (!taken_section) {
                snprintf(db->build, sizeof(db->build), "%s", section);
                taken_section = 1;
            }
            v = strtoull(val, &end, 0);
            if (end == val) {
                continue;
            }
            if (!db_push(db, key, (uint64_t)v)) {
                fclose(f);
                offset_db_free(db);
                if (err && err_cap) {
                    snprintf(err, err_cap, "out of memory");
                }
                return 0;
            }
        }
    }
    fclose(f);

    if (!taken_section || db->count == 0) {
        if (err && err_cap) {
            snprintf(err, err_cap, "no entries%s%s", want_build ? " for build " : "", want_build ? want_build : "");
        }
        offset_db_free(db);
        return 0;
    }
    return 1;
}

int offset_db_get(const offset_db_t *db, const char *key, uint64_t *out)
{
    size_t i;

    if (!db || !key || !out) {
        return 0;
    }
    for (i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].key, key) == 0) {
            *out = db->entries[i].value;
            return 1;
        }
    }
    return 0;
}

uint64_t offset_db_require(const offset_db_t *db, const char *key, int *ok)
{
    uint64_t v = 0;

    if (ok) {
        *ok = offset_db_get(db, key, &v);
    }
    return v;
}

void offset_db_free(offset_db_t *db)
{
    if (!db) {
        return;
    }
    free(db->entries);
    db->entries = NULL;
    db->count = 0;
    db->cap = 0;
}

/* ------------------------------------------------------------------ */
/* symbol table                                                        */
/* ------------------------------------------------------------------ */

static int sym_push(symtab_t *st, const char *name, uint64_t addr)
{
    if (st->count == st->cap) {
        size_t ncap = st->cap ? st->cap * 2 : 256;
        sym_t *n = (sym_t *)realloc(st->syms, ncap * sizeof(*n));
        if (!n) {
            return 0;
        }
        st->syms = n;
        st->cap = ncap;
    }
    st->syms[st->count].addr = addr;
    snprintf(st->syms[st->count].name, sizeof(st->syms[st->count].name), "%s", name);
    st->count++;
    return 1;
}

int symtab_load(symtab_t *st, const char *path, char *err, size_t err_cap)
{
    FILE *f;
    char line[512];

    if (err && err_cap) {
        err[0] = '\0';
    }
    if (!st || !path) {
        return 0;
    }
    memset(st, 0, sizeof(*st));

    f = fopen(path, "r");
    if (!f) {
        if (err && err_cap) {
            snprintf(err, err_cap, "cannot open %s", path);
        }
        return 0;
    }
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        char *tok1;
        char *tok2;
        char *sp;

        if (*s == '\0' || *s == '#' || *s == ';') {
            continue;
        }
        sp = strpbrk(s, " \t");
        if (!sp) {
            continue;
        }
        *sp = '\0';
        tok1 = s;
        tok2 = trim(sp + 1);
        if (!*tok2) {
            continue;
        }
        {
            uint64_t addr = 0;
            const char *name = NULL;

            if (is_hex_token(tok1)) {
                addr = (uint64_t)strtoull(tok1, NULL, 16);
                name = tok2;
            } else if (is_hex_token(tok2)) {
                addr = (uint64_t)strtoull(tok2, NULL, 16);
                name = tok1;
            } else {
                continue;
            }
            /* names with spaces: keep only the first token */
            {
                char nm[96];
                size_t n = 0;
                const char *p = name;
                while (*p && !isspace((unsigned char)*p) && n + 1 < sizeof(nm)) {
                    nm[n++] = *p++;
                }
                nm[n] = '\0';
                if (!sym_push(st, nm, addr)) {
                    fclose(f);
                    symtab_free(st);
                    if (err && err_cap) {
                        snprintf(err, err_cap, "out of memory");
                    }
                    return 0;
                }
            }
        }
    }
    fclose(f);

    if (st->count == 0) {
        if (err && err_cap) {
            snprintf(err, err_cap, "no symbols parsed");
        }
        return 0;
    }
    symtab_sort_by_addr(st);
    return 1;
}

static int cmp_addr(const void *a, const void *b)
{
    const sym_t *x = (const sym_t *)a;
    const sym_t *y = (const sym_t *)b;

    if (x->addr < y->addr) {
        return -1;
    }
    if (x->addr > y->addr) {
        return 1;
    }
    return 0;
}

static int cmp_name(const void *a, const void *b)
{
    const sym_t *x = (const sym_t *)a;
    const sym_t *y = (const sym_t *)b;

    return strcmp(x->name, y->name);
}

void symtab_sort_by_addr(symtab_t *st)
{
    if (!st || st->count < 2) {
        if (st) {
            st->sorted_by_addr = 1;
            st->sorted_by_name = 0;
        }
        return;
    }
    qsort(st->syms, st->count, sizeof(sym_t), cmp_addr);
    st->sorted_by_addr = 1;
    st->sorted_by_name = 0;
}

void symtab_sort_by_name(symtab_t *st)
{
    if (!st || st->count < 2) {
        if (st) {
            st->sorted_by_name = 1;
            st->sorted_by_addr = 0;
        }
        return;
    }
    qsort(st->syms, st->count, sizeof(sym_t), cmp_name);
    st->sorted_by_name = 1;
    st->sorted_by_addr = 0;
}

const sym_t *symtab_lookup_addr(const symtab_t *st, uint64_t addr)
{
    size_t lo;
    size_t hi;

    if (!st || !st->sorted_by_addr || st->count == 0) {
        return NULL;
    }
    if (addr < st->syms[0].addr) {
        return NULL;
    }
    lo = 0;
    hi = st->count;
    while (lo + 1 < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (st->syms[mid].addr <= addr) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    return &st->syms[lo];
}

const sym_t *symtab_lookup_name(const symtab_t *st, const char *name)
{
    size_t lo = 0;
    size_t hi;

    if (!st || !st->sorted_by_name || !name || st->count == 0) {
        return NULL;
    }
    hi = st->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(st->syms[mid].name, name);
        if (c == 0) {
            return &st->syms[mid];
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return NULL;
}

void symtab_free(symtab_t *st)
{
    if (!st) {
        return;
    }
    free(st->syms);
    st->syms = NULL;
    st->count = 0;
    st->cap = 0;
}

static int cmp_delta_value(const void *a, const void *b)
{
    long long x = *(const long long *)a;
    long long y = *(const long long *)b;

    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

int symtab_delta_stats(const symtab_t *old_tab, const symtab_t *new_tab, symtab_delta_stats_t *out)
{
    long long *deltas;
    size_t n = 0;
    size_t i;
    size_t run = 0;
    size_t best_run = 0;
    size_t best_len = 0;
    size_t distinct = 1;

    if (!old_tab || !new_tab || !out) {
        return 0;
    }
    if (!old_tab->sorted_by_name || !new_tab->sorted_by_name) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    if (old_tab->count == 0) {
        return 0;
    }
    deltas = (long long *)malloc(old_tab->count * sizeof(*deltas));
    if (!deltas) {
        return 0;
    }
    for (i = 0; i < old_tab->count; i++) {
        const sym_t *m = symtab_lookup_name(new_tab, old_tab->syms[i].name);
        if (m) {
            deltas[n++] = (long long)m->addr - (long long)old_tab->syms[i].addr;
        }
    }
    if (n == 0) {
        free(deltas);
        return 0;
    }
    qsort(deltas, n, sizeof(*deltas), cmp_delta_value);

    for (i = 1; i <= n; i++) {
        if (i == n || deltas[i] != deltas[run]) {
            size_t len = i - run;
            if (len > best_len) {
                best_len = len;
                best_run = run;
            }
            run = i;
        }
    }
    for (i = 1; i < n; i++) {
        if (deltas[i] != deltas[i - 1]) {
            distinct++;
        }
    }

    out->modal = deltas[best_run];
    out->matched = n;
    out->modal_count = best_len;
    out->distinct = distinct;
    free(deltas);
    return 1;
}
