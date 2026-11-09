/*
 * panicdump - analyse an Apple panic log.
 *
 *   panicdump [options] <artifact.ips|artifact.panic>
 *
 *   --json                 machine-readable output
 *   --marker <hex>         value the trigger sprayed
 *   --marker-mask <hex>    bits to ignore when matching the marker
 *   --symbols <file>       "0xaddr name" list for symbolication
 *   --slide <hex>          override the parsed kernel slide
 *   --text-base <hex>      override the parsed kernel text base
 *   --text-size <hex>      plausibility ceiling for caller/pc offsets
 *   --check                exit 3 if the artifact is not a panic at all
 *
 * Exit codes: 0 ok, 1 usage, 2 parse failure, 3 --check found no panic.
 */

#include "offset_db.h"
#include "panic_log.h"
#include "panic_report.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out,
            "usage: panicdump [options] <panic.ips|panic.panic>\n"
            "  --json                 JSON output\n"
            "  --marker <hex>         sprayed value to look for\n"
            "  --marker-mask <hex>    bits to ignore when matching\n"
            "  --symbols <file>       symbol list (0xaddr name)\n"
            "  --slide <hex>          override kernel slide\n"
            "  --text-base <hex>      override kernel text base\n"
            "  --text-size <hex>      offset plausibility ceiling\n"
            "  --check                exit 3 when no panic is recognised\n");
}

int main(int argc, char **argv)
{
    const char *path = NULL;
    const char *symbols = NULL;
    const char *marker = NULL;
    const char *marker_mask = NULL;
    const char *slide = NULL;
    const char *text_base = NULL;
    const char *text_size = NULL;
    int json = 0;
    int check = 0;
    int i;
    panic_log_t pl;
    panic_report_opts_t opts;
    symtab_t st;
    char err[256];
    int have_symtab = 0;

    panic_report_opts_default(&opts);
    memset(&st, 0, sizeof(st));

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--json") == 0) {
            json = 1;
        } else if (strcmp(a, "--check") == 0) {
            check = 1;
        } else if (strcmp(a, "--marker") == 0 && i + 1 < argc) {
            marker = argv[++i];
        } else if (strcmp(a, "--marker-mask") == 0 && i + 1 < argc) {
            marker_mask = argv[++i];
        } else if (strcmp(a, "--symbols") == 0 && i + 1 < argc) {
            symbols = argv[++i];
        } else if (strcmp(a, "--slide") == 0 && i + 1 < argc) {
            slide = argv[++i];
        } else if (strcmp(a, "--text-base") == 0 && i + 1 < argc) {
            text_base = argv[++i];
        } else if (strcmp(a, "--text-size") == 0 && i + 1 < argc) {
            text_size = argv[++i];
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (a[0] == '-') {
            fprintf(stderr, "panicdump: unknown option %s\n", a);
            usage(stderr);
            return 1;
        } else if (!path) {
            path = a;
        } else {
            fprintf(stderr, "panicdump: more than one input file\n");
            return 1;
        }
    }

    if (!path) {
        usage(stderr);
        return 1;
    }

    if (!panic_log_parse_file(path, &pl, err, sizeof(err))) {
        fprintf(stderr, "panicdump: %s: %s\n", path, err);
        return 2;
    }

    if (slide) {
        pl.kernel_slide = (uint64_t)strtoull(slide, NULL, 16);
        pl.has_kernel_slide = 1;
    }
    if (text_base) {
        pl.kernel_text_base = (uint64_t)strtoull(text_base, NULL, 16);
        pl.has_kernel_text_base = 1;
    }
    if (marker) {
        opts.marker = (uint64_t)strtoull(marker, NULL, 16);
        opts.have_marker = 1;
    }
    if (marker_mask) {
        opts.marker_mask = (uint64_t)strtoull(marker_mask, NULL, 16);
    }
    if (text_size) {
        opts.text_size_hint = (uint64_t)strtoull(text_size, NULL, 16);
    }
    opts.json = json;

    if (symbols) {
        if (!symtab_load(&st, symbols, err, sizeof(err))) {
            fprintf(stderr, "panicdump: %s: %s\n", symbols, err);
            return 2;
        }
        have_symtab = 1;
        opts.sym = &st;
    }

    panic_report(&pl, &opts, stdout);

    if (have_symtab) {
        symtab_free(&st);
    }

    if (check && !pl.panic_head[0]) {
        return 3;
    }
    return 0;
}
