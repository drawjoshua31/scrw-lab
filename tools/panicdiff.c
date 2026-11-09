/*
 * panicdiff - map a panic caller onto two kernel symbol dumps.
 *
 *   panicdiff <panic.ips|panic.panic> <old.syms> <new.syms> [options]
 *
 *   --slide <hex>       use this slide instead of the ones in the log
 *   --text-base <hex>   override Kernel text base
 *   --window <bytes>    neighbourhood radius in the old table (default 0x2000)
 *   --limit <n>         max neighbourhood rows (default 40)
 *   --json              machine-readable output
 *
 * The log carries several slides. This tool resolves the caller once per slide
 * and prints every candidate, preferring one whose symbol name also exists in
 * the new table. It does not pretend a symbol list can prove the code is
 * unchanged.
 */

#include "offset_db.h"
#include "panic_log.h"
#include "panicdiff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fputs("usage: panicdiff <panic.ips|panic.panic> <old.syms> <new.syms>\n"
          "  --slide <hex>       use this slide instead of the log's\n"
          "  --text-base <hex>   override Kernel text base\n"
          "  --window <bytes>    neighbourhood radius (default 0x2000)\n"
          "  --limit <n>         max neighbourhood rows (default 40)\n"
          "  --json              JSON output\n",
          out);
}

static void json_quote(const char *s, FILE *out)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    fputc('"', out);
    for (; *p; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", out);
            break;
        case '\\':
            fputs("\\\\", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20) {
                fprintf(out, "\\u%04x", *p);
            } else {
                fputc(*p, out);
            }
        }
    }
    fputc('"', out);
}

static void print_verdict(const panicdiff_site_t *site, FILE *out)
{
    const panicdiff_candidate_t *c = NULL;

    if (site->have_chosen) {
        c = &site->candidates[site->chosen];
    }

    switch (site->kind) {
    case PANICDIFF_STABLE:
        if (!c) {
            break;
        }
        fprintf(out,
                "  The caller's function moved by the modal delta. In these two\n"
                "  lists it did not change size relative to the rest of the\n"
                "  kernel. That is a weak negative: a same-size edit is invisible\n"
                "  to symbol deltas.\n");
        break;
    case PANICDIFF_SHIFTED:
        if (!c) {
            break;
        }
        fprintf(out,
                "  The caller's function moved by %+lld while the kernel moved by\n"
                "  %+lld, a difference of %+lld. Something between this function\n"
                "  and the reference point changed size by that much. That is the\n"
                "  neighbourhood to disassemble.\n",
                c->delta, site->stats.modal, c->delta - site->stats.modal);
        break;
    case PANICDIFF_SYMBOL_GONE:
        if (!c) {
            break;
        }
        fprintf(out,
                "  The old symbol %s is absent from the new list. It was renamed,\n"
                "  merged or removed. Search the new table near the mapped address\n"
                "  rather than trusting a neighbour.\n",
                c->old_name);
        break;
    case PANICDIFF_NO_COMMON:
        fprintf(out,
                "  The two lists share no symbol names, so there is no modal\n"
                "  delta to compare against. Check that both dumps are kernel\n"
                "  symbols for comparable builds.\n");
        break;
    case PANICDIFF_NO_OLD_SYMBOL:
        fprintf(out,
                "  No symbol covers the caller at any reported slide. If the list\n"
                "  came from nm on a release kernelcache, core XNU text is\n"
                "  stripped and this is expected. Use a signature-based symbol\n"
                "  source, or a list that covers the kernel proper.\n");
        break;
    case PANICDIFF_NO_STATIC:
        fprintf(out,
                "  The log has no usable slide. Pass --slide with the value that\n"
                "  matches your kernelcache.\n");
        break;
    case PANICDIFF_BELOW_TEXT:
        fprintf(out,
                "  The caller is below Kernel text base. Check that the value you\n"
                "  subtracted is the text base, not Kernel text exec base.\n");
        break;
    case PANICDIFF_NO_TEXT_BASE:
        fprintf(out, "  The artifact has no Kernel text base. Pass --text-base.\n");
        break;
    case PANICDIFF_NO_CALLER:
        fprintf(out, "  The artifact has no caller field to map.\n");
        break;
    }
}

static void print_neighbourhood(const symtab_t *old_tab, const symtab_t *new_tab, const panicdiff_site_t *site, uint64_t window, size_t limit, FILE *out)
{
    const panicdiff_candidate_t *c;
    uint64_t lo;
    uint64_t hi;
    size_t i;
    size_t shown = 0;
    size_t odd = 0;
    char first_odd[96] = "";
    long long first_rel = 0;

    if (!site->have_chosen) {
        return;
    }
    c = &site->candidates[site->chosen];
    lo = (c->old_addr > window) ? c->old_addr - window : 0;
    hi = (c->old_addr > UINT64_MAX - window) ? UINT64_MAX : c->old_addr + window;

    fprintf(out, "\n== neighbourhood (old table, +/- 0x%llx) ==\n", (unsigned long long)window);
    for (i = 0; i < old_tab->count && shown < limit; i++) {
        const sym_t *o = &old_tab->syms[i];
        const sym_t *n;
        long long rel;

        if (o->addr < lo) {
            continue;
        }
        if (o->addr > hi) {
            break;
        }
        n = symtab_lookup_name(new_tab, o->name);
        rel = n ? ((long long)n->addr - (long long)o->addr) - site->stats.modal : 0;
        fprintf(out, "  %+16lld  %-40.40s %-40.40s%s\n", rel, o->name, n ? n->name : "(absent)", (o->addr == c->old_addr && strcmp(o->name, c->old_name) == 0) ? "  <- caller" : "");
        if (rel != 0 && first_odd[0] == '\0') {
            snprintf(first_odd, sizeof(first_odd), "%s", o->name);
            first_rel = rel;
        }
        if (rel != 0) {
            odd++;
        }
        shown++;
    }
    if (shown == 0) {
        fprintf(out, "  no symbols in this window\n");
    }
    if (odd) {
        fprintf(out, "  note: %zu symbol(s) here moved differently; first is %s " "(%+lld).\n", odd, first_odd, first_rel);
    }
}

int main(int argc, char **argv)
{
    const char *panic_path = NULL;
    const char *old_path = NULL;
    const char *new_path = NULL;
    uint64_t window = 0x2000;
    uint64_t text_base_override = 0;
    uint64_t slide_override = 0;
    size_t limit = 40;
    int have_text_base = 0;
    int have_slide = 0;
    int json = 0;
    int i;
    panic_log_t pl;
    symtab_t old_tab;
    symtab_t new_tab;
    panicdiff_site_t site;
    uint64_t slides[PANICDIFF_MAX_SLIDES];
    size_t nslides = 0;
    char err[256];

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--json") == 0) {
            json = 1;
        } else if (strcmp(a, "--slide") == 0 && i + 1 < argc) {
            slide_override = (uint64_t)strtoull(argv[++i], NULL, 16);
            have_slide = 1;
        } else if (strcmp(a, "--text-base") == 0 && i + 1 < argc) {
            text_base_override = (uint64_t)strtoull(argv[++i], NULL, 16);
            have_text_base = 1;
        } else if (strcmp(a, "--window") == 0 && i + 1 < argc) {
            window = (uint64_t)strtoull(argv[++i], NULL, 0);
        } else if (strcmp(a, "--limit") == 0 && i + 1 < argc) {
            limit = (size_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (a[0] == '-') {
            fprintf(stderr, "panicdiff: unknown option %s\n", a);
            usage(stderr);
            return 1;
        } else if (!panic_path) {
            panic_path = a;
        } else if (!old_path) {
            old_path = a;
        } else if (!new_path) {
            new_path = a;
        } else {
            fprintf(stderr, "panicdiff: too many positional arguments\n");
            return 1;
        }
    }
    if (!panic_path || !old_path || !new_path) {
        usage(stderr);
        return 1;
    }

    if (!panic_log_parse_file(panic_path, &pl, err, sizeof(err))) {
        fprintf(stderr, "panicdiff: %s: %s\n", panic_path, err);
        return 2;
    }
    if (!symtab_load(&old_tab, old_path, err, sizeof(err))) {
        fprintf(stderr, "panicdiff: %s: %s\n", old_path, err);
        return 2;
    }
    if (!symtab_load(&new_tab, new_path, err, sizeof(err))) {
        fprintf(stderr, "panicdiff: %s: %s\n", new_path, err);
        symtab_free(&old_tab);
        return 2;
    }

    if (have_slide) {
        slides[0] = slide_override;
        nslides = 1;
    } else {
        nslides = panic_log_slides(&pl, slides, PANICDIFF_MAX_SLIDES);
    }

    panicdiff_analyse(&old_tab, &new_tab, pl.has_caller ? pl.caller : 0, have_text_base ? text_base_override : (pl.has_kernel_text_base ? pl.kernel_text_base : 0), slides, nslides, &site);

    if (json) {
        size_t k;
        fputs("{\"panic\":{\"build\":", stdout);
        json_quote(pl.build, stdout);
        fputs(",\"product\":", stdout);
        json_quote(pl.product, stdout);
        fprintf(stdout, ",\"caller\":%llu,\"offset\":%llu}", (unsigned long long)site.caller, (unsigned long long)site.offset);
        fputs(",\"kind\":", stdout);
        json_quote(panicdiff_kind_name(site.kind), stdout);
        fprintf(stdout, ",\"chosen\":%d,\"modal\":%lld,\"matched\":%zu,\"distinct\":%zu", site.have_chosen ? (int)site.chosen : -1, site.stats.modal, site.stats.matched, site.stats.distinct);
        fputs(",\"candidates\":[", stdout);

        for (k = 0; k < site.ncandidates; k++) {
            const panicdiff_candidate_t *c = &site.candidates[k];
            if (k) {
                fputc(',', stdout);
            }
            fprintf(stdout, "{\"slide\":%llu,\"static\":%llu,\"old\":", (unsigned long long)c->slide, (unsigned long long)c->static_addr);
            json_quote(c->have_old ? c->old_name : "", stdout);
            fprintf(stdout, ",\"oldOffset\":%llu,\"new\":", (unsigned long long)c->old_off);
            json_quote(c->have_new ? c->new_name : "", stdout);
            fprintf(stdout, ",\"newSite\":%llu,\"delta\":%lld}", (unsigned long long)(c->have_new ? c->new_site : 0), c->delta);
        }
        fputs("]}\n", stdout);
    } else {
        fprintf(stdout, "== panic ==\n");
        fprintf(stdout, "  build      %s\n", pl.build[0] ? pl.build : "<unknown>");
        fprintf(stdout, "  product    %s\n", pl.product[0] ? pl.product : "<unknown>");
        if (pl.fileset_uuid[0]) {
            fprintf(stdout, "  fileset    %s\n", pl.fileset_uuid);
        }
        if (pl.has_caller) {
            fprintf(stdout, "  caller     0x%016llx", (unsigned long long)pl.caller);
            if (site.offset) {
                fprintf(stdout, "  +0x%llx from text base 0x%016llx", (unsigned long long)site.offset, (unsigned long long)site.text_base);
            }
            fputc('\n', stdout);
        } else {
            fprintf(stdout, "  caller     <not in log>\n");
        }
        fprintf(stdout, "  slides    ");
        if (nslides == 0) {
            fprintf(stdout, " <none in log>");
        }
        for (i = 0; (size_t)i < nslides; i++) {
            fprintf(stdout, " 0x%llx", (unsigned long long)slides[i]);
        }
        fprintf(stdout, "\n");

        fprintf(stdout, "\n== mapping ==\n");
        if (site.ncandidates == 0) {
            fprintf(stdout, "  no candidate symbol at the reported slide(s)\n");
            goto after_mapping;
        }
        fprintf(stdout, "  %-2s %-12s %-18s %-40s %-40s %12s\n", "", "slide", "static", "old symbol", "new symbol", "delta");
        for (i = 0; (size_t)i < site.ncandidates; i++) {
            const panicdiff_candidate_t *c = &site.candidates[i];
            char oldbuf[160];
            char newbuf[160];

            if (c->have_old) {
                snprintf(oldbuf, sizeof(oldbuf), "%s+0x%llx", c->old_name, (unsigned long long)c->old_off);
            } else {
                snprintf(oldbuf, sizeof(oldbuf), "-");
            }
            if (c->have_new) {
                snprintf(newbuf, sizeof(newbuf), "%s+0x%llx", c->new_name, (unsigned long long)c->old_off);
            } else {
                snprintf(newbuf, sizeof(newbuf), "absent");
            }
            fprintf(stdout, "  %c %-12llx 0x%016llx %-40.40s %-40.40s %+12lld\n", (site.have_chosen && (size_t)i == site.chosen) ? '*' : ' ', (unsigned long long)c->slide, (unsigned long long)c->static_addr, oldbuf, newbuf, c->delta);
        }
        if (site.stats.matched) {
            fprintf(stdout, "\n  kernel delta %+lld (modal, %zu of %zu common symbols, " "%zu distinct)\n", site.stats.modal, site.stats.modal_count, site.stats.matched, site.stats.distinct);
        } else {
            fprintf(stdout, "\n  kernel delta unavailable: no common symbols\n");
        }

after_mapping:
        fprintf(stdout, "\n== verdict ==\n");
        print_verdict(&site, stdout);

        print_neighbourhood(&old_tab, &new_tab, &site, window, limit, stdout);

        if (site.have_chosen && site.candidates[site.chosen].have_new) {
            const panicdiff_candidate_t *c =
                &site.candidates[site.chosen];
            fprintf(stdout,
                    "\n== next ==\n"
                    "  static site   0x%016llx (chosen slide 0x%llx)\n"
                    "  new site      0x%016llx\n"
                    "  disassemble   old 0x%016llx, new 0x%016llx\n",
                    (unsigned long long)c->static_addr,
                    (unsigned long long)c->slide,
                    (unsigned long long)c->new_site,
                    (unsigned long long)c->old_addr,
                    (unsigned long long)c->new_addr);
        }
    }

    symtab_free(&old_tab);
    symtab_free(&new_tab);
    return 0;
}
