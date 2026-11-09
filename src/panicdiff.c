/*
 * panicdiff.c - see panicdiff.h.
 */

#include "panicdiff.h"
#include <stdio.h>
#include <string.h>

void panicdiff_site_init(panicdiff_site_t *site)
{
    if (!site) {
        return;
    }
    memset(site, 0, sizeof(*site));
    site->kind = PANICDIFF_NO_CALLER;
}

const char *panicdiff_kind_name(panicdiff_kind_t kind)
{
    switch (kind) {
    case PANICDIFF_NO_CALLER:
        return "no-caller";
    case PANICDIFF_NO_TEXT_BASE:
        return "no-text-base";
    case PANICDIFF_BELOW_TEXT:
        return "below-text";
    case PANICDIFF_NO_STATIC:
        return "no-slide";
    case PANICDIFF_NO_OLD_SYMBOL:
        return "no-old-symbol";
    case PANICDIFF_SYMBOL_GONE:
        return "symbol-gone";
    case PANICDIFF_NO_COMMON:
        return "no-common-symbols";
    case PANICDIFF_STABLE:
        return "stable";
    case PANICDIFF_SHIFTED:
        return "shifted";
    }
    return "unknown";
}

static int candidate_is_better(const panicdiff_candidate_t *best, const panicdiff_candidate_t *cand, long long modal, int have_modal)
{
    int best_modal;
    int cand_modal;

    if (best->have_new != cand->have_new) {
        return cand->have_new;
    }
    if (have_modal && best->have_new) {
        best_modal = best->delta == modal;
        cand_modal = cand->delta == modal;
        if (best_modal != cand_modal) {
            return cand_modal;
        }
    }
    /* A tighter offset is the weaker tie-break, not the primary signal. */
    return cand->old_off < best->old_off;
}

int panicdiff_analyse(symtab_t *old_tab, symtab_t *new_tab, uint64_t caller, uint64_t text_base, const uint64_t *slides, size_t nslides, panicdiff_site_t *site)
{
    size_t i;
    int have_modal;
    panicdiff_candidate_t *chosen;

    if (!site) {
        return 0;
    }
    panicdiff_site_init(site);
    site->caller = caller;
    site->text_base = text_base;

    if (caller == 0) {
        site->kind = PANICDIFF_NO_CALLER;
        return 0;
    }
    if (text_base == 0) {
        site->kind = PANICDIFF_NO_TEXT_BASE;
        return 0;
    }
    if (caller < text_base) {
        site->kind = PANICDIFF_BELOW_TEXT;
        return 0;
    }
    site->offset = caller - text_base;

    if (!old_tab || !new_tab || old_tab->count == 0 || new_tab->count == 0) {
        site->kind = PANICDIFF_NO_OLD_SYMBOL;
        return 0;
    }
    if (!slides || nslides == 0) {
        site->kind = PANICDIFF_NO_STATIC;
        return 0;
    }
    if (nslides > PANICDIFF_MAX_SLIDES) {
        nslides = PANICDIFF_MAX_SLIDES;
    }

    symtab_sort_by_name(old_tab);
    symtab_sort_by_name(new_tab);
    (void)symtab_delta_stats(old_tab, new_tab, &site->stats);
    have_modal = site->stats.matched > 0;

    symtab_sort_by_addr(old_tab);
    for (i = 0; i < nslides; i++) {
        panicdiff_candidate_t *c;
        const sym_t *o;
        const sym_t *n;

        if (caller < slides[i]) {
            continue;
        }
        c = &site->candidates[site->ncandidates];
        memset(c, 0, sizeof(*c));
        c->slide = slides[i];
        c->static_addr = caller - slides[i];

        o = symtab_lookup_addr(old_tab, c->static_addr);
        if (!o) {
            continue;
        }
        c->have_old = 1;
        snprintf(c->old_name, sizeof(c->old_name), "%s", o->name);
        c->old_addr = o->addr;
        c->old_off = c->static_addr - o->addr;

        n = symtab_lookup_name(new_tab, c->old_name);
        if (n) {
            c->have_new = 1;
            snprintf(c->new_name, sizeof(c->new_name), "%s", n->name);
            c->new_addr = n->addr;
            c->new_site = n->addr + c->old_off;
            c->delta = (long long)n->addr - (long long)o->addr;
        }
        site->ncandidates++;
    }

    if (site->ncandidates == 0) {
        site->kind = PANICDIFF_NO_OLD_SYMBOL;
        return 0;
    }

    site->chosen = 0;
    for (i = 1; i < site->ncandidates; i++) {
        if (candidate_is_better(&site->candidates[site->chosen], &site->candidates[i], site->stats.modal, have_modal)) {
            site->chosen = i;
        }
    }
    site->have_chosen = 1;
    chosen = &site->candidates[site->chosen];

    if (!chosen->have_new) {
        site->kind = PANICDIFF_SYMBOL_GONE;
    } else if (!have_modal) {
        site->kind = PANICDIFF_NO_COMMON;
    } else if (chosen->delta == site->stats.modal) {
        site->kind = PANICDIFF_STABLE;
    } else {
        site->kind = PANICDIFF_SHIFTED;
    }
    return 1;
}
