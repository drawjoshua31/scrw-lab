/*
 * panic_report.c - turn a parsed panic into a decision.
 *
 * Two ideas drive the output:
 *   - offset, not address. A raw kernel VA means nothing across boots; caller
 *     minus the kernel text base is a stable fingerprint of the panicking site,
 *     and that is what you feed into a kernelcache diff.
 *   - marker discipline. If you sprayed a unique value, its presence in a
 *     register proves you control the faulting value. That fact decides
 *     whether you own the corruption or are looking at a stale object.
 *
 * Address classification is relative to the parsed text base, because kernel
 * VA layout changed in 27.x: text now sits in the 0xfffffe... range on some
 * SoCs, so fixed range checks would mislabel it as heap.
 */

#include "panic_report.h"
#include <ctype.h>
#include <string.h>

void panic_report_opts_default(panic_report_opts_t *o)
{
    if (!o) {
        return;
    }
    memset(o, 0, sizeof(*o));
    /*
     * Generous sanity ceiling for (pc - text base). XNU plus kexts is large on
     * 27.x; the value only exists to catch a wrong slide, not to bound text.
     */
    o->text_size_hint = 0x20000000ULL;
}

static const char *kva_class(const panic_log_t *p, uint64_t v)
{
    if (v == 0) {
        return "zero";
    }
    if (v < 0x0001000000000000ULL) {
        return "small/user";
    }
    /* Pre-27 layout: text lived at 0xfffffff0... */
    if (v >= 0xfffffff000000000ULL) {
        return "kernel text/static";
    }
    if (p && p->has_kernel_text_base && v >= p->kernel_text_base && v < p->kernel_text_base + 0x20000000ULL) {
        return "kernel text";
    }
    if (v >= 0xfffffe0000000000ULL) {
        return "kernel VA";
    }
    return "non-canonical";
}

static const char *reg_class(const panic_log_t *p, int idx, uint64_t v)
{
    if (idx == 33) {
        return "flags";
    }
    if (idx == 34) {
        return "fault address";
    }
    if (idx == 35) {
        return "syndrome";
    }
    return kva_class(p, v);
}

static const char *esr_ec_name(unsigned ec)
{
    switch (ec) {
    case 0x00:
        return "unknown";
    case 0x01:
        return "WFx trap";
    case 0x07:
        return "SVE/SIMD/FP access";
    case 0x0e:
        return "illegal execution state";
    case 0x11:
        return "SVC (AArch32)";
    case 0x15:
        return "SVC (AArch64)";
    case 0x18:
        return "trapped MSR/MRS";
    case 0x20:
        return "instruction abort, lower EL";
    case 0x21:
        return "instruction abort, same EL";
    case 0x22:
        return "PC alignment fault";
    case 0x24:
        return "data abort, lower EL";
    case 0x25:
        return "data abort, same EL";
    case 0x26:
        return "SP alignment fault";
    case 0x2f:
        return "SError";
    case 0x3c:
        return "BRK";
    default:
        return "other";
    }
}

static const char *fsc_name(unsigned fsc)
{
    switch (fsc) {
    case 0x04:
        return "translation fault, level 0";
    case 0x05:
        return "translation fault, level 1";
    case 0x06:
        return "translation fault, level 2";
    case 0x07:
        return "translation fault, level 3";
    case 0x09:
        return "access flag fault, level 1";
    case 0x0a:
        return "access flag fault, level 2";
    case 0x0b:
        return "access flag fault, level 3";
    case 0x0d:
        return "permission fault, level 1";
    case 0x0e:
        return "permission fault, level 2";
    case 0x0f:
        return "permission fault, level 3";
    case 0x10:
        return "synchronous external abort";
    case 0x11:
        return "synchronous external abort on walk";
    case 0x13:
        return "synchronous parity/ECC error";
    case 0x21:
        return "alignment fault";
    case 0x22:
        return "debug event";
    case 0x30:
        return "TLB conflict";
    default:
        return "unknown code";
    }
}

static void print_esr(uint64_t esr, FILE *out)
{
    unsigned ec = (unsigned)((esr >> 26) & 0x3fu);
    unsigned fsc = (unsigned)(esr & 0x3fu);
    int is_abort = (ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25);

    fprintf(out, "EC=0x%02x (%s)", ec, esr_ec_name(ec));
    if (is_abort) {
        fprintf(out, " FSC=0x%02x (%s)", fsc, fsc_name(fsc));
    }
    fprintf(out, " IL=%u", (unsigned)((esr >> 25) & 1u));
}

static int marker_match(uint64_t v, uint64_t marker, uint64_t mask)
{
    return (v & ~mask) == (marker & ~mask);
}

static uint64_t aux_value(const panic_log_t *p, int idx)
{
    switch (idx) {
    case 29:
        return p->fp;
    case 30:
        return p->lr;
    case 31:
        return p->sp;
    case 32:
        return p->pc;
    case 33:
        return p->cpsr;
    case 34:
        return p->far;
    case 35:
        return p->esr;
    default:
        return 0;
    }
}

static int aux_present(const panic_log_t *p, int idx)
{
    static const uint32_t bits[] = {PL_AUX_FP, PL_AUX_LR, PL_AUX_SP, PL_AUX_PC, PL_AUX_CPSR, PL_AUX_FAR, PL_AUX_ESR};

    if (idx < 29 || idx > 35) {
        return 0;
    }
    return (p->aux_mask & bits[idx - 29]) != 0;
}

/*
 * There is no single slide that maps every kernel address into static symbol
 * space: the log reports separate fileset, __TEXT and text exec slides, and
 * XNU computes the last two from the kernelcache header rather than from the
 * segment base. Subtracting one lands on a static header, not on the code's
 * static address. Show a candidate per slide instead of silently picking one.
 */
static void print_symbol_candidates(const panic_log_t *p, const panic_report_opts_t *o, uint64_t addr, FILE *out)
{
    uint64_t slides[PL_MAX_SLIDES];
    size_t n;
    size_t i;
    int printed = 0;

    if (!o->sym) {
        return;
    }
    n = panic_log_slides(p, slides, PL_MAX_SLIDES);
    fprintf(out, "symbols:");
    if (n == 0) {
        fprintf(out, " no slide in log, cannot convert to symbol space\n");
        return;
    }
    for (i = 0; i < n; i++) {
        const sym_t *s;
        if (addr < slides[i]) {
            continue;
        }
        s = symtab_lookup_addr(o->sym, addr - slides[i]);
        if (!s) {
            continue;
        }
        fprintf(out, " [0x%llx] %s+0x%llx", (unsigned long long)slides[i], s->name, (unsigned long long)(addr - slides[i] - s->addr));
        printed = 1;
    }
    if (!printed) {
        fprintf(out, " none of the %zu slides resolve in this list", n);
    }
    fprintf(out, "\n");
}

static void print_offset(const char *label, uint64_t addr, int present, const panic_log_t *p, const panic_report_opts_t *o, FILE *out)
{
    if (!present) {
        fprintf(out, "  %-10s <not in log>\n", label);
        return;
    }
    fprintf(out, "  %-10s 0x%016llx", label, (unsigned long long)addr);
    if (p->has_kernel_text_base && addr >= p->kernel_text_base) {
        uint64_t off = addr - p->kernel_text_base;
        fprintf(out, "  +0x%llx from text base", (unsigned long long)off);
        if (o->text_size_hint && off > o->text_size_hint) {
            fprintf(out, " [!] outside text_size_hint, slide/base suspect");
        }
    }
    fprintf(out, "\n");
    print_symbol_candidates(p, o, addr, out);
}

static void json_escaped(const char *s, FILE *out)
{
    if (!s) {
        fputs("\"\"", out);
        return;
    }
    fputc('"', out);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fputc('\\', out);
            fputc(c, out);
        } else if (c == '\n') {
            fputs("\\n", out);
        } else if (c == '\t') {
            fputs("\\t", out);
        } else if (c < 0x20) {
            fprintf(out, "\\u%04x", c);
        } else {
            fputc(c, out);
        }
    }
    fputc('"', out);
}

static int has_marker_hit(const panic_log_t *p, const panic_report_opts_t *o)
{
    int i;

    for (i = 0; i <= 35; i++) {
        int present = (i <= 28) ? ((p->reg_mask >> i) & 1u) != 0 : aux_present(p, i);
        uint64_t v;
        if (!present) {
            continue;
        }
        v = (i <= 28) ? p->regs[i] : aux_value(p, i);
        if (marker_match(v, o->marker, o->marker_mask)) {
            return 1;
        }
    }
    return 0;
}

static const char *pac_key_kind(const char *key)
{
    if (!key || !key[0]) {
        return "unknown";
    }
    if (strcmp(key, "DA") == 0 || strcmp(key, "DB") == 0) {
        return "data address";
    }
    if (strcmp(key, "IA") == 0 || strcmp(key, "IB") == 0) {
        return "instruction address";
    }
    if (strcmp(key, "GA") == 0) {
        return "generic";
    }
    return "other";
}

static void report_json(const panic_log_t *p, const panic_report_opts_t *o, FILE *out)
{
    int i;
    fputs("{\n", out);
    fputs("  \"identity\": {", out);
    fputs("\"build\": ", out);
    json_escaped(p->build, out);
    fputs(", \"product\": ", out);
    json_escaped(p->product, out);
    fputs(", \"socId\": ", out);
    json_escaped(p->soc_id, out);
    fputs(", \"socRevision\": ", out);
    json_escaped(p->soc_revision, out);
    fputs(", \"kernel\": ", out);
    json_escaped(p->kernel_version, out);
    fputs(", \"bugType\": ", out);
    json_escaped(p->bug_type, out);
    fputs(", \"incident\": ", out);
    json_escaped(p->incident, out);
    fputs(", \"sptm\": ", out);
    json_escaped(p->sptm_version, out);
    fputs(", \"fileset\": ", out);
    json_escaped(p->fileset_uuid, out);
    fputs(", \"kext\": ", out);
    json_escaped(p->panicked_kext, out);
    fputc('}', out);

    fputs(",\n  \"panic\": {", out);
    fputs("\"head\": ", out);
    json_escaped(p->panic_head, out);
    fputs(", \"reason\": ", out);
    json_escaped(p->panic_reason, out);
    fputs(", \"pacFailure\": ", out);
    fputs(p->has_pac_failure ? "true" : "false", out);
    fputs(", \"pacKey\": ", out);
    json_escaped(p->pac_key, out);
    fputs(", \"pacReg\": ", out);
    json_escaped(p->pac_reg, out);
    fprintf(out, ", \"cpu\": %d, \"caller\": %llu", p->has_cpu ? p->cpu : -1, (unsigned long long)(p->has_caller ? p->caller : 0));
    fprintf(out, ", \"kernelcacheSlide\": %llu, \"textExecSlide\": %llu", (unsigned long long)(p->has_kernelcache_slide ? p->kernelcache_slide : 0), (unsigned long long)(p->has_text_exec_slide ? p->text_exec_slide : 0));
    fputs(", \"panickedPid\": ", out);
    json_escaped(p->panicked_pid, out);
    fputc('}', out);

    fputs(",\n  \"stackshot\": {", out);
    fprintf(out, "\"succeeded\": %s, \"bytes\": %lld, \"uncompressed\": %lld", p->stackshot_succeeded ? "true" : "false", p->stackshot_bytes, p->stackshot_uncompressed);
    fprintf(out, ", \"missingBuffer\": %s, \"resampledTruncated\": %s, " "\"zeroPids\": %s, \"exclavesMissing\": %s, " "\"inlineFrames\": %zu", p->note_missing_stackshot ? "true" : "false", p->note_resampled_truncated ? "true" : "false", p->note_zero_pids ? "true" : "false", p->note_exclaves_stackshot ? "true" : "false", p->nframes);
    fputs(", \"notes\": ", out);
    json_escaped(p->notes, out);
    fputc('}', out);

    fputs(",\n  \"registers\": {", out);
    {
        int first = 1;
        char name[8];
        for (i = 0; i <= 35; i++) {
            int present = (i <= 28) ? ((p->reg_mask >> i) & 1u) != 0  : aux_present(p, i);
            uint64_t v;
            if (!present) {
                continue;
            }
            v = (i <= 28) ? p->regs[i] : aux_value(p, i);
            if (!first) {
                fputs(", ", out);
            }
            first = 0;
            fprintf(out, "\"%s\": %llu", panic_reg_name(i, name, sizeof(name)), (unsigned long long)v);
        }
    }
    fputc('}', out);

    fputs(",\n  \"marker\": {", out);
    if (o->have_marker) {
        fprintf(out, "\"value\": %llu, \"mask\": %llu, \"hits\": [", (unsigned long long)o->marker, (unsigned long long)o->marker_mask);
        {
            int first = 1;
            char name[8];
            for (i = 0; i <= 35; i++) {
                int present = (i <= 28) ? ((p->reg_mask >> i) & 1u) != 0 : aux_present(p, i);
                uint64_t v;
                if (!present) {
                    continue;
                }
                v = (i <= 28) ? p->regs[i] : aux_value(p, i);
                if (!marker_match(v, o->marker, o->marker_mask)) {
                    continue;
                }
                if (!first) {
                    fputs(", ", out);
                }
                first = 0;
                json_escaped(panic_reg_name(i, name, sizeof(name)), out);
            }
        }
        fputs("]}", out);
    } else {
        fputs("\"value\": null}", out);
    }

    fputs(",\n  \"frames\": [", out);
    for (i = 0; i < (int)p->nframes; i++) {
        if (i) {
            fputs(", ", out);
        }
        fprintf(out, "%llu", (unsigned long long)p->frames[i]);
    }
    fputs("]\n}\n", out);
}

void panic_report(const panic_log_t *p, const panic_report_opts_t *o, FILE *out)
{
    panic_report_opts_t def;
    int i;

    if (!p || !out) {
        return;
    }
    if (!o) {
        panic_report_opts_default(&def);
        o = &def;
    }
    if (o->json) {
        report_json(p, o, out);
        return;
    }

    fprintf(out, "== identity ==\n");
    fprintf(out, "  build: %s\n", p->build[0] ? p->build : "<unknown>");
    fprintf(out, "  product: %s\n", p->product[0] ? p->product : "<unknown>");
    fprintf(out, "  soc: id %s rev %s\n", p->soc_id[0] ? p->soc_id : "?", p->soc_revision[0] ? p->soc_revision : "?");
    if (p->kernel_version[0]) {
        fprintf(out, "  kernel: %s\n", p->kernel_version);
    }
    if (p->sptm_version[0]) {
        fprintf(out, "  sptm: %s\n", p->sptm_version);
    }
    if (p->has_sptm_load_address) {
        fprintf(out, "  sptm load:  0x%016llx\n", (unsigned long long)p->sptm_load_address);
    }
    if (p->fileset_uuid[0]) {
        fprintf(out, "  fileset: %s\n", p->fileset_uuid);
    }
    fprintf(out, "  bug_type: %s\n", p->bug_type[0] ? p->bug_type : "<unknown>");
    if (p->has_developer_mode) {
        fprintf(out, "  developer mode: %d\n", p->developer_mode);
    }
    if (p->incident[0]) {
        fprintf(out, "  incident: %s\n", p->incident);
    }
    if (p->panicked_kext[0]) {
        fprintf(out, "  kext in trace: %s\n", p->panicked_kext);
    }

    fprintf(out, "\n== panic ==\n");
    fprintf(out, "  head: %s\n", p->panic_head[0] ? p->panic_head : "<empty>");
    if (p->panic_reason[0]) {
        fprintf(out, "  reason: %s\n", p->panic_reason);
    }
    print_offset("caller", p->caller, p->has_caller, p, o, out);
    print_offset("pc", p->pc, (p->aux_mask & PL_AUX_PC) != 0, p, o, out);
    print_offset("lr", p->lr, (p->aux_mask & PL_AUX_LR) != 0, p, o, out);
    if (p->aux_mask & PL_AUX_FAR) {
        fprintf(out, "  far: 0x%016llx  %s\n", (unsigned long long)p->far, kva_class(p, p->far));
    }
    if (p->aux_mask & PL_AUX_ESR) {
        fprintf(out, "  esr: 0x%016llx ", (unsigned long long)p->esr);
        print_esr(p->esr, out);
        fprintf(out, "\n");
    }
    if (p->has_kernel_text_base) {
        fprintf(out, "  text base: 0x%016llx\n", (unsigned long long)p->kernel_text_base);
    }
    if (p->has_kernel_slide) {
        fprintf(out, "  slide: 0x%llx\n", (unsigned long long)p->kernel_slide);
    }
    if (p->has_kernelcache_slide) {
        fprintf(out, "  k-cache: 0x%llx\n", (unsigned long long)p->kernelcache_slide);
    }
    if (p->has_text_exec_base) {
        fprintf(out, "  text exec: 0x%016llx\n", (unsigned long long)p->text_exec_base);
    }
    if (p->has_pac_failure) {
        fprintf(out, "  pac: PAC failure");
        if (p->pac_key[0]) {
            fprintf(out, " with %s key (%s)", p->pac_key, pac_key_kind(p->pac_key));
        }
        if (p->pac_reg[0]) {
            fprintf(out, " while authing %s", p->pac_reg);
        }
        fprintf(out, "\n");
    } else {
        fprintf(out, "  pac: not reported\n");
    }

    fprintf(out, "\n== stackshot ==\n");
    fprintf(out, "  succeeded:  %s\n", p->stackshot_succeeded ? "yes" : "no");
    if (p->stackshot_bytes >= 0) {
        fprintf(out, "  bytes:  %lld (uncompressed %lld)\n", p->stackshot_bytes, p->stackshot_uncompressed);
    }
    fprintf(out, "  inline frames: %zu\n", p->nframes);
    if (p->notes[0]) {
        fprintf(out, "  notes: %s\n", p->notes);
    }
    if (p->stackshot_succeeded &&
        (p->note_missing_stackshot || p->note_exclaves_stackshot)) {
        fprintf(out,
                "  reconcile      the primary stackshot is present, but a secondary\n"
                "                 collector reported an empty or missing buffer. Both\n"
                "                 lines can be true. Use the primary trace and treat\n"
                "                 process attribution from the secondary one as absent.\n");
    }
    if (p->note_zero_pids || p->note_resampled_truncated) {
        fprintf(out,
                "  reconcile      thread resampling saw zero processes, so process\n"
                "                 names and pids are unreliable. Identify the site by\n"
                "                 registers, caller offset and kext, not by pid.\n");
    }

    fprintf(out, "\n== registers ==\n");
    {
        char name[8];
        int printed = 0;
        for (i = 0; i <= 35; i++) {
            int present = (i <= 28) ? ((p->reg_mask >> i) & 1u) != 0 : aux_present(p, i);
            uint64_t v;
            if (!present) {
                continue;
            }
            v = (i <= 28) ? p->regs[i] : aux_value(p, i);
            fprintf(out, "  %-6s 0x%016llx  %-18s", panic_reg_name(i, name, sizeof(name)), (unsigned long long)v, reg_class(p, i, v));
            if (o->have_marker && marker_match(v, o->marker, o->marker_mask)) {
                fprintf(out, "  <== MARKER");
            }
            printed++;
            if (printed % 3 == 0) {
                fputc('\n', out);
            }
        }
        if (printed % 3 != 0) {
            fputc('\n', out);
        }
        if (printed == 0) {
            fprintf(out, "  <no register block in this artifact>\n");
        }
    }

    if (p->nframes) {
        fprintf(out, "\n== backtrace (inline) ==\n");
        for (i = 0; i < (int)p->nframes; i++) {
            fprintf(out, "  [%02d] 0x%016llx\n", i, (unsigned long long)p->frames[i]);
            print_symbol_candidates(p, o, p->frames[i], out);
        }
    } else {
        fprintf(out, "\n== backtrace ==\n  none inline. Decode the compressed stackshot\n" "  before concluding the trace is missing.\n");
    }

    if (o->have_marker) {
        char name[8];
        fprintf(out, "\n== marker ==\n  value 0x%016llx mask 0x%016llx\n", (unsigned long long)o->marker, (unsigned long long)o->marker_mask);
        for (i = 0; i <= 35; i++) {
            int present = (i <= 28) ? ((p->reg_mask >> i) & 1u) != 0 : aux_present(p, i);
            uint64_t v;
            if (!present) {
                continue;
            }
            v = (i <= 28) ? p->regs[i] : aux_value(p, i);
            if (marker_match(v, o->marker, o->marker_mask)) {
                fprintf(out, "  hit in %s\n", panic_reg_name(i, name, sizeof(name)));
            }
        }
        if (!has_marker_hit(p, o)) {
            fprintf(out, "  no register holds the marker. Either the value was\n" "  transformed before the fault, or you do not control it yet.\n");
        }
    }

    fprintf(out, "\n== verdict ==\n");
    if (p->has_pac_failure) {
        int data_key = p->pac_key[0] && (strcmp(p->pac_key, "DA") == 0 || strcmp(p->pac_key, "DB") == 0);
        int instr_key = p->pac_key[0] && (strcmp(p->pac_key, "IA") == 0 || strcmp(p->pac_key, "IB") == 0);

        if (data_key) {
            fprintf(out,
                    "  A data-address key failed while authenticating %s. That is a\n"
                    "  corrupted data pointer, not a hijacked return address. It also\n"
                    "  means the useful next step is data-only: find the object, shift\n"
                    "  the corruption onto a field the kernel does not authenticate,\n"
                    "  and leave PAC out of the path entirely.\n",
                    p->pac_reg[0] ? p->pac_reg : "a pointer register");
        } else if (instr_key) {
            fprintf(out,
                    "  An instruction-address key failed. That points at control flow:\n"
                    "  a function pointer, vtable slot or saved return address. This is\n"
                    "  a much longer project than a data corruption, and PAC forgery is\n"
                    "  not the way through it.\n");
        } else if (has_marker_hit(p, o)) {
            fprintf(out,
                    "  A sprayed value reached a slot the kernel authenticates. That is\n"
                    "  controlled pointer corruption. Retarget it at a non-signed field\n"
                    "  rather than trying to satisfy the authentication.\n");
        } else {
            fprintf(out,
                    "  PAC trap without evidence of value control. Either the\n"
                    "  corruption is indirect, or the written value was transformed.\n"
                    "  Run the marker matrix before changing the trigger.\n");
        }
    } else {
        fprintf(out,
                "  No PAC failure reported. Classify by EC/FSC first: a translation\n"
                "  fault on a wild address is a different bug from a permission fault\n"
                "  on a valid one.\n");
    }

    fprintf(out, "\n== next ==\n");
    if (p->note_missing_stackshot || p->note_resampled_truncated || p->note_exclaves_stackshot) {
        fprintf(out,
                "  1. Keep the artifact with its .panic and panic-full siblings; the\n"
                "     missing buffer is reported in a different section.\n"
                "  2. Decode the compressed stackshot rather than reading panicString\n"
                "     only.\n");
    } else {
        fprintf(out, "  1. Freeze this build: no OTA, no restore. Betas disappear.\n");
    }
    fprintf(out,
            "  3. Diff this build's kernelcache against a later one and look for the\n"
            "     function containing the caller offset above. If SPTM is in the trace,\n"
            "     compare that version first: %s\n",
            p->sptm_version[0] ? p->sptm_version : "(no SPTM version in log)");
    fprintf(out,
            "  4. Re-run the trigger with a different marker and one variable changed\n"
            "     per boot. Record the caller offset every time. A stable offset is a\n"
            "     stable site, and a stable site can be reversed.\n");
}
