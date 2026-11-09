/*
 * panic_report.h - turn a parsed panic into an actionable analysis.
 *
 * The report is opinionated on purpose: it computes the caller's offset into
 * kernel text, classifies every register value, looks for a sprayed marker,
 * and prints the next experiment to run. The goal is to make a panic log
 * produce a decision instead of a shrug.
 */

#ifndef PANIC_REPORT_H
#define PANIC_REPORT_H
#include "offset_db.h"
#include "panic_log.h"
#include <stdio.h>

typedef struct panic_report_opts {
    /* --marker: a value the trigger sprays, to prove value control. */
    uint64_t marker;
    uint64_t marker_mask; /* bits to ignore when comparing */
    int have_marker;
    /* Plausibility ceiling for (pc - kernel_text_base). Default 0x04000000. */
    uint64_t text_size_hint;
    /* Optional symbol table for pc / caller / frame symbolication. */
    const symtab_t *sym;

    int json;
} panic_report_opts_t;

void panic_report_opts_default(panic_report_opts_t *o);
void panic_report(const panic_log_t *p, const panic_report_opts_t *o, FILE *out);
#endif /* PANIC_REPORT_H */
