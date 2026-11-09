/*
 * symdiff - find changed neighbourhoods between two kernel symbol lists.
 *
 * The KASLR slide is unknown and changes every boot, so raw address
 * differences are meaningless. But if you take two kernelcaches from different
 * builds and compare (symbol address - a reference point), most symbols move by
 * the same number of bytes: the slide plus the size of everything Apple
 * inserted before them. Symbols that *leave* that common delta sit next to an
 * edit. That group is where a patch lives.
 *
 * This is a heuristic, not a patchdiffer. It exists to turn a 40,000-symbol
 * kernelcache pair into a few hundred candidates you can hand to a disassembler.
 *
 *   symdiff <old.syms> <new.syms> [--limit N]
 *
 * Both files: "0xfffffff00b123456 _symbol_name" (or name-first, both work).
 */

#include "offset_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *old_path = NULL;
    const char *new_path = NULL;
    size_t limit = 200;
    symtab_t a;
    symtab_t b;
    symtab_delta_stats_t stats;
    size_t changed = 0;
    size_t i;
    char err[256];
    int j;

    for (j = 1; j < argc; j++) {
        if (strcmp(argv[j], "--limit") == 0 && j + 1 < argc) {
            limit = (size_t)strtoul(argv[++j], NULL, 10);
        } else if (!old_path) {
            old_path = argv[j];
        } else if (!new_path) {
            new_path = argv[j];
        }
    }
    if (!old_path || !new_path) {
        fprintf(stderr, "usage: symdiff <old.syms> <new.syms> [--limit N]\n");
        return 1;
    }

    if (!symtab_load(&a, old_path, err, sizeof(err))) {
        fprintf(stderr, "symdiff: %s: %s\n", old_path, err);
        return 2;
    }
    if (!symtab_load(&b, new_path, err, sizeof(err))) {
        fprintf(stderr, "symdiff: %s: %s\n", new_path, err);
        symtab_free(&a);
        return 2;
    }

    symtab_sort_by_name(&a);
    symtab_sort_by_name(&b);

    if (!symtab_delta_stats(&a, &b, &stats) || stats.matched == 0) {
        fprintf(stderr, "symdiff: no common symbols; wrong files?\n");
        symtab_free(&a);
        symtab_free(&b);
        return 2;
    }

    printf("common symbols: %zu\n", stats.matched);
    printf("modal delta: 0x%llx (%lld) covering %zu symbols\n", (unsigned long long)stats.modal, stats.modal, stats.modal_count);
    printf("distinct deltas: %zu\n\n", stats.distinct);
    printf("candidates (delta differs from modal):\n");
    printf("%-40s %14s %14s %16s\n", "symbol", "old", "new", "delta-modal");
    for (i = 0; i < a.count && changed < limit; i++) {
        const sym_t *m = symtab_lookup_name(&b, a.syms[i].name);
        long long d;
        long long rel;

        if (!m) {
            continue;
        }
        d = (long long)m->addr - (long long)a.syms[i].addr;
        rel = d - stats.modal;
        if (rel == 0) {
            continue;
        }
        printf("%-40s 0x%012llx 0x%012llx %+16lld\n", a.syms[i].name, (unsigned long long)a.syms[i].addr, (unsigned long long)m->addr, rel);
        changed++;
    }
    if (changed == 0) {
        printf("  none - the two symbol lists are consistent with an unchanged\n"  "  text layout (that does not prove the code is identical).\n");
    } else if (changed >= limit) {
        printf("\n... limited to %zu rows; raise --limit to see more\n", limit);
    }
    printf("\nnote: a symbol whose delta differs may simply be adjacent to an\n" "insertion. Treat the neighbourhood as the candidate, not the symbol.\n");
    symtab_free(&a);
    symtab_free(&b);
    return 0;
}
