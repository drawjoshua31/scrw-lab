/*
 * panicdiff.h - map a panic caller onto two kernel symbol dumps.
 *
 * A log carries several KASLR slides and does not say which one applies to a
 * given frame. This module tries every reported slide, resolves the caller in
 * the old table, and prefers a candidate whose symbol name also exists in the
 * new table. Every candidate is kept so the caller can print the choice instead
 * of hiding it.
 */

#ifndef PANICDIFF_H
#define PANICDIFF_H
#include "offset_db.h"
#include <stddef.h>
#include <stdint.h>
#define PANICDIFF_MAX_SLIDES 4

typedef enum panicdiff_kind {
    PANICDIFF_NO_CALLER = 0,
    PANICDIFF_NO_TEXT_BASE,
    PANICDIFF_BELOW_TEXT,
    PANICDIFF_NO_STATIC,
    PANICDIFF_NO_OLD_SYMBOL,
    PANICDIFF_SYMBOL_GONE,
    PANICDIFF_NO_COMMON,
    PANICDIFF_STABLE,
    PANICDIFF_SHIFTED
} panicdiff_kind_t;

typedef struct panicdiff_candidate {
    uint64_t slide;
    uint64_t static_addr;
    int have_old;
    char old_name[96];
    uint64_t old_addr;
    uint64_t old_off;
    int have_new;
    char new_name[96];
    uint64_t new_addr;
    uint64_t new_site;
    long long delta;
} panicdiff_candidate_t;

typedef struct panicdiff_site {
    panicdiff_kind_t kind;
    uint64_t caller;
    uint64_t text_base;
    uint64_t offset;
    size_t ncandidates;
    panicdiff_candidate_t candidates[PANICDIFF_MAX_SLIDES];
    size_t chosen;
    int have_chosen;
    symtab_delta_stats_t stats;
} panicdiff_site_t;

void panicdiff_site_init(panicdiff_site_t *site);
const char *panicdiff_kind_name(panicdiff_kind_t kind);

/*
 * Sorts both tables internally, so they may arrive in any order. Returns 1 when
 * at least one slide resolves the caller, 0 otherwise. kind explains a failure.
 * caller and text_base are runtime addresses taken from the log.
 */
int panicdiff_analyse(symtab_t *old_tab, symtab_t *new_tab, uint64_t caller, uint64_t text_base, const uint64_t *slides, size_t nslides, panicdiff_site_t *site);

#endif /* PANICDIFF_H */
