/*
 * panic_log.c - tolerant panic-log parser for real Apple artifacts.
 *
 * Field layouts differ between releases and between capture paths. The parser
 * therefore scans for known markers instead of assuming a schema, and it
 * treats the first occurrence of a register as authoritative: the register
 * block comes before the backtrace, so an "lr:" inside a stack frame must not
 * overwrite the trapped lr.
 */

#include "panic_log.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* small string helpers                                                */
/* ------------------------------------------------------------------ */

static const char *ci_strstr(const char *hay, const char *needle)
{
    size_t nlen;

    if (!hay || !needle) {
        return NULL;
    }
    nlen = strlen(needle);
    if (nlen == 0) {
        return hay;
    }
    for (; *hay; hay++) {
        size_t i;
        for (i = 0; i < nlen; i++) {
            unsigned char a = (unsigned char)hay[i];
            unsigned char b = (unsigned char)needle[i];
            if (!a) {
                return NULL;
            }
            if (a >= 'A' && a <= 'Z') {
                a = (unsigned char)(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = (unsigned char)(b - 'A' + 'a');
            }
            if (a != b) {
                break;
            }
        }
        if (i == nlen) {
            return hay;
        }
    }
    return NULL;
}

static char *slurp(const char *path, size_t *len_out)
{
    FILE *f;
    long sz;
    char *buf;
    size_t rd;

    if (!path || !len_out) {
        return NULL;
    }
    f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0 || sz > (long)(16L * 1024L * 1024L)) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    *len_out = rd;
    return buf;
}

/*
 * Extracts a JSON string value, unescaping \n \t \r \" \\ \/ and \uXXXX.
 */
static int json_get_string(const char *text, const char *key, char *out, size_t cap)
{
    char pat[128];
    const char *p;
    const char *q;
    size_t o = 0;

    if (!text || !key || !out || cap == 0) {
        return 0;
    }
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(text, pat);
    if (!p) {
        return 0;
    }
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    if (*p != ':') {
        return 0;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    if (*p != '"') {
        return 0;
    }
    p++;
    q = p;
    while (*q && *q != '"') {
        if (*q == '\\' && q[1]) {
            q++;
        }
        q++;
    }
    if (*q != '"') {
        return 0;
    }

    while (p < q && o + 1 < cap) {
        char ch = *p++;
        if (ch == '\\' && p < q) {
            char esc = *p++;
            switch (esc) {
            case 'n':
                ch = '\n';
                break;
            case 't':
                ch = '\t';
                break;
            case 'r':
                ch = '\r';
                break;
            case '"':
                ch = '"';
                break;
            case '\\':
                ch = '\\';
                break;
            case '/':
                ch = '/';
                break;
            case 'u': {
                unsigned v = 0;
                int k;
                for (k = 0; k < 4 && p < q; k++) {
                    char h = *p++;
                    v <<= 4;
                    if (h >= '0' && h <= '9') {
                        v |= (unsigned)(h - '0');
                    } else if (h >= 'a' && h <= 'f') {
                        v |= (unsigned)(h - 'a' + 10);
                    } else if (h >= 'A' && h <= 'F') {
                        v |= (unsigned)(h - 'A' + 10);
                    }
                }
                ch = (v < 0x80u) ? (char)v : '?';
                break;
            }
            default:
                ch = esc;
                break;
            }
        }
        out[o++] = ch;
    }
    out[o] = '\0';
    return 1;
}

static int take_line(const char *start, char *out, size_t cap)
{
    const char *nl;
    size_t n;

    if (!start || !out || cap == 0) {
        return 0;
    }
    nl = strchr(start, '\n');
    n = nl ? (size_t)(nl - start) : strlen(start);
    while (n > 0 && (start[n - 1] == '\r' || start[n - 1] == ' ')) {
        n--;
    }
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(out, start, n);
    out[n] = '\0';
    return 1;
}

static int find_hex_after(const char *text, const char *label, uint64_t *out)
{
    const char *p;
    const char *h;
    char *end = NULL;
    unsigned long long v;

    if (!text || !label || !out) {
        return 0;
    }
    p = strstr(text, label);
    if (!p) {
        return 0;
    }
    h = strstr(p + strlen(label), "0x");
    if (!h || h - p > 96) {
        return 0;
    }
    v = strtoull(h, &end, 16);
    if (!end || end == h + 2) {
        return 0;
    }
    *out = (uint64_t)v;
    return 1;
}

/* Copies the token after a label: stops at space, tab or newline. */
static void copy_token_after(const char *text, const char *label, char *out, size_t cap)
{
    const char *p;
    size_t n = 0;

    if (!text || !label || !out || cap == 0) {
        return;
    }
    p = strstr(text, label);
    if (!p) {
        return;
    }
    p += strlen(label);
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' && n + 1 < cap) {
        out[n++] = *p++;
    }
    out[n] = '\0';
}

/* Copies a short identifier-like word: letters, digits, underscore. */
static void copy_word(const char *s, char *out, size_t cap)
{
    size_t n = 0;

    if (!s || !out || cap == 0) {
        return;
    }
    while (s[n] && (isalnum((unsigned char)s[n]) || s[n] == '_') && n + 1 < cap) {
        out[n] = s[n];
        n++;
    }
    out[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* register / backtrace scanning                                       */
/* ------------------------------------------------------------------ */

static void store_aux(panic_log_t *p, uint32_t bit, uint64_t *slot, uint64_t v)
{
    /* First occurrence wins: the register block precedes the frames. */
    if (!(p->aux_mask & bit)) {
        *slot = v;
        p->aux_mask |= bit;
    }
}

static void store_reg(panic_log_t *p, const char *name, uint64_t v)
{
    if (name[0] == 'x' && name[1]) {
        char *end = NULL;
        long idx = strtol(name + 1, &end, 10);
        if (end && *end == '\0' && idx >= 0 && idx <= 28) {
            if (!(p->reg_mask & (1u << idx))) {
                p->regs[idx] = v;
                p->reg_mask |= 1u << idx;
            }
            return;
        }
    }
    if (strcmp(name, "fp") == 0) {
        store_aux(p, PL_AUX_FP, &p->fp, v);
    } else if (strcmp(name, "lr") == 0) {
        store_aux(p, PL_AUX_LR, &p->lr, v);
    } else if (strcmp(name, "sp") == 0) {
        store_aux(p, PL_AUX_SP, &p->sp, v);
    } else if (strcmp(name, "pc") == 0) {
        store_aux(p, PL_AUX_PC, &p->pc, v);
    } else if (strcmp(name, "cpsr") == 0) {
        store_aux(p, PL_AUX_CPSR, &p->cpsr, v);
    } else if (strcmp(name, "far") == 0) {
        store_aux(p, PL_AUX_FAR, &p->far, v);
    } else if (strcmp(name, "esr") == 0) {
        store_aux(p, PL_AUX_ESR, &p->esr, v);
    }
}

static void scan_registers(const char *s, panic_log_t *p)
{
    const char *q = s;

    while (*q) {
        int boundary = (q == s) || !(isalnum((unsigned char)q[-1]) || q[-1] == '_');
        if (boundary && (isalpha((unsigned char)*q) || *q == 'x')) {
            const char *t = q;
            char name[8];
            size_t n = 0;

            while (n + 1 < sizeof(name) && (isalnum((unsigned char)*t) || *t == '_')) {
                name[n++] = *t++;
            }
            name[n] = '\0';

            {
                const char *r = t;
                while (*r == ' ' || *r == '\t') {
                    r++;
                }
                if (*r == ':') {
                    r++;
                    while (*r == ' ' || *r == '\t') {
                        r++;
                    }
                    if (r[0] == '0' && (r[1] == 'x' || r[1] == 'X')) {
                        char *end = NULL;
                        unsigned long long v = strtoull(r, &end, 16);
                        if (end && end > r + 2) {
                            store_reg(p, name, (uint64_t)v);
                        }
                    }
                }
            }
            q = t;
            continue;
        }
        q++;
    }
}

/*
 * Inline frames appear either as bare 64-bit addresses or as "lr: 0x..."
 * pairs, which is what recent builds print. Register lines before the marker
 * are skipped because scanning starts after the first "backtrace".
 */
static void scan_backtrace(const char *s, panic_log_t *p)
{
    const char *q = strstr(s, "backtrace");

    if (!q) {
        return;
    }
    q = strchr(q, '\n');
    if (!q) {
        return;
    }

    while (*q && p->nframes < PL_MAX_FRAMES) {
        const char *line = q + 1;
        const char *nl = strchr(line, '\n');
        const char *t = line;
        const char *h = NULL;

        while (*t == ' ' || *t == '\t') {
            t++;
        }
        if (t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
            h = t;
        } else if (t[0] == 'l' && t[1] == 'r' && t[2] == ':') {
            h = t + 3;
            while (*h == ' ' || *h == '\t') {
                h++;
            }
        }
        if (h && h[0] == '0' && (h[1] == 'x' || h[1] == 'X')) {
            char *end = NULL;
            unsigned long long v = strtoull(h, &end, 16);
            if (end && end > h + 2) {
                p->frames[p->nframes++] = (uint64_t)v;
            }
        }
        if (strncmp(t, "missing stackshot", 17) == 0 ||
            strncmp(t, "resampled threads", 17) == 0) {
            break;
        }
        if (!nl) {
            break;
        }
        q = nl;
    }
}

static void note_add(panic_log_t *p, const char *text)
{
    size_t used = strlen(p->notes);

    if (used + 4 >= sizeof(p->notes)) {
        return;
    }
    if (used) {
        p->notes[used++] = ';';
        p->notes[used++] = ' ';
        p->notes[used] = '\0';
    }
    strncat(p->notes, text, sizeof(p->notes) - strlen(p->notes) - 1);
}

static void scan_notes(const char *raw, panic_log_t *p)
{
    if (strstr(raw, "missing stackshot buffer") != NULL) {
        p->note_missing_stackshot = 1;
        note_add(p, "missing stackshot buffer or size");
    }
    if (strstr(raw, "resampled threads with truncated backtraces") != NULL) {
        p->note_resampled_truncated = 1;
        note_add(p, "resampled threads with truncated backtraces");
    }
    if (strstr(raw, "from 0 pids") != NULL) {
        p->note_zero_pids = 1;
        note_add(p, "0 pids");
    }
    if (strstr(raw, "Exclaves panic stackshot not found") != NULL) {
        p->note_exclaves_stackshot = 1;
        note_add(p, "exclaves stackshot not found");
    }
}

static void scan_stackshot(const char *raw, panic_log_t *p)
{
    const char *s = ci_strstr(raw, "Stackshot Succeeded");
    const char *b;
    long long traced = 0;
    long long uncomp = 0;

    if (!s) {
        return;
    }
    p->stackshot_succeeded = 1;
    b = strstr(s, "Bytes Traced");
    if (b && sscanf(b, "Bytes Traced %lld (Uncompressed %lld)", &traced, &uncomp) == 2) {
        p->stackshot_bytes = traced;
        p->stackshot_uncompressed = uncomp;
    }
}

static void parse_pac_detail(panic_log_t *p)
{
    const char *s = strstr(p->panic_string, "PAC failure from kernel with ");
    const char *a;

    if (!s) {
        return;
    }
    s += strlen("PAC failure from kernel with ");
    copy_word(s, p->pac_key, sizeof(p->pac_key));
    a = strstr(s, "while authing ");
    if (a) {
        a += strlen("while authing ");
        copy_word(a, p->pac_reg, sizeof(p->pac_reg));
    }
}

static void parse_sptm(panic_log_t *p, const char *inner)
{
    const char *s = strstr(inner, "SPTM-");

    if (s) {
        size_t n = 0;
        while (s[n] && s[n] != '|' && s[n] != '\n' && s[n] != ' ' && n + 1 < sizeof(p->sptm_version)) {
            p->sptm_version[n] = s[n];
            n++;
        }
        p->sptm_version[n] = '\0';
    }
    if (find_hex_after(inner, "SPTM load address:", &p->sptm_load_address)) {
        p->has_sptm_load_address = 1;
    }
}

static void parse_kext(panic_log_t *p, const char *inner)
{
    const char *s = strstr(inner, "Kernel Extensions in backtrace:");
    const char *e;
    size_t n = 0;

    if (!s) {
        return;
    }
    s = strchr(s, '\n');
    if (!s) {
        return;
    }
    s++;
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    e = s;
    while (*e && *e != '(' && *e != '\n' && *e != ' ' && n + 1 < sizeof(p->panicked_kext)) {
        p->panicked_kext[n++] = *e++;
    }
    p->panicked_kext[n] = '\0';
}

static void parse_panic_head(panic_log_t *p)
{
    const char *nl;
    char *c;
    size_t n;

    if (!p->panic_string[0]) {
        return;
    }
    nl = strchr(p->panic_string, '\n');
    n = nl ? (size_t)(nl - p->panic_string) : strlen(p->panic_string);
    if (n >= sizeof(p->panic_head)) {
        n = sizeof(p->panic_head) - 1;
    }
    memcpy(p->panic_head, p->panic_string, n);
    p->panic_head[n] = '\0';

    p->has_pac_failure = ci_strstr(p->panic_string, "PAC failure") != NULL;

    if (strncmp(p->panic_string, "panic(", 6) != 0) {
        return;
    }
    c = strstr(p->panic_head, "cpu ");
    if (c) {
        p->cpu = atoi(c + 4);
        p->has_cpu = 1;
    }
    c = strstr(p->panic_head, "caller ");
    if (c) {
        char *end = NULL;
        unsigned long long v = strtoull(c + 7, &end, 16);
        if (end && end > c + 7) {
            p->caller = (uint64_t)v;
            p->has_caller = 1;
            snprintf(p->caller_hex, sizeof(p->caller_hex), "0x%016llx", v);
        }
    }
    c = strstr(p->panic_head, "): ");
    if (c) {
        snprintf(p->panic_reason, sizeof(p->panic_reason), "%s", c + 3);
    }
}

/* ------------------------------------------------------------------ */
/* entry points                                                        */
/* ------------------------------------------------------------------ */

int panic_log_parse_text(const char *text, panic_log_t *out, char *err, size_t err_cap)
{
    char panic_buf[PL_TEXT_MAX];
    const char *inner;
    uint64_t v = 0;

    if (err && err_cap) {
        err[0] = '\0';
    }
    if (!text || !out) {
        if (err && err_cap) {
            snprintf(err, err_cap, "null input");
        }
        return 0;
    }
    if (text[0] == '\0') {
        if (err && err_cap) {
            snprintf(err, err_cap, "empty input");
        }
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->cpu = -1;
    out->stackshot_bytes = -1;
    out->stackshot_uncompressed = -1;

    json_get_string(text, "build", out->build, sizeof(out->build));
    if (!out->build[0]) {
        /* 27.x artifacts often carry the build only in the metadata line. */
        json_get_string(text, "os_version", out->build, sizeof(out->build));
    }
    json_get_string(text, "product", out->product, sizeof(out->product));
    json_get_string(text, "socId", out->soc_id, sizeof(out->soc_id));
    json_get_string(text, "socRevision", out->soc_revision, sizeof(out->soc_revision));
    json_get_string(text, "kernel", out->kernel_version, sizeof(out->kernel_version));
    json_get_string(text, "incident", out->incident, sizeof(out->incident));
    json_get_string(text, "incident_id", out->incident, sizeof(out->incident));
    json_get_string(text, "crashReporterKey", out->crash_reporter_key, sizeof(out->crash_reporter_key));
    json_get_string(text, "date", out->date, sizeof(out->date));
    json_get_string(text, "bug_type", out->bug_type, sizeof(out->bug_type));

    panic_buf[0] = '\0';
    json_get_string(text, "panicString", panic_buf, sizeof(panic_buf));
    if (panic_buf[0]) {
        snprintf(out->panic_string, sizeof(out->panic_string), "%s", panic_buf);
    } else {
        snprintf(out->panic_string, sizeof(out->panic_string), "%s", text);
    }
    inner = out->panic_string;

    {
        const char *dm = strstr(text, "\"developerMode\"");
        if (dm) {
            const char *colon = strchr(dm, ':');
            if (colon) {
                out->developer_mode = atoi(colon + 1);
                out->has_developer_mode = 1;
            }
        }
    }

    if (find_hex_after(inner, "Kernel slide:", &v) ||
        find_hex_after(text, "Kernel slide:", &v)) {
        out->kernel_slide = v;
        out->has_kernel_slide = 1;
    }
    if (find_hex_after(inner, "Kernel text base:", &v) ||
        find_hex_after(text, "Kernel text base:", &v)) {
        out->kernel_text_base = v;
        out->has_kernel_text_base = 1;
    }
    if (find_hex_after(inner, "KernelCache slide:", &v)) {
        out->kernelcache_slide = v;
        out->has_kernelcache_slide = 1;
    }
    if (find_hex_after(inner, "KernelCache base:", &v)) {
        out->kernelcache_base = v;
        out->has_kernelcache_base = 1;
    }
    if (find_hex_after(inner, "Kernel text exec slide:", &v)) {
        out->text_exec_slide = v;
        out->has_text_exec_slide = 1;
    }
    if (find_hex_after(inner, "Kernel text exec base:", &v)) {
        out->text_exec_base = v;
        out->has_text_exec_base = 1;
    }
    copy_token_after(inner, "Fileset Kernelcache UUID:", out->fileset_uuid, sizeof(out->fileset_uuid));
    copy_token_after(inner, "SPTM UUID:", out->sptm_uuid, sizeof(out->sptm_uuid));

    scan_registers(inner, out);
    scan_backtrace(inner, out);
    scan_notes(text, out);
    scan_stackshot(text, out);
    parse_panic_head(out);
    parse_pac_detail(out);
    parse_sptm(out, inner);
    parse_kext(out, inner);

    {
        const char *pt = strstr(inner, "panicked task");
        if (!pt) {
            pt = strstr(inner, "Panicked task");
        }
        if (pt) {
            char line[320];
            take_line(pt, line, sizeof(line));
            snprintf(out->panicked_task, sizeof(out->panicked_task), "%s", line);
            {
                const char *pid = strstr(line, "pid ");
                if (pid) {
                    snprintf(out->panicked_pid, sizeof(out->panicked_pid), "%d", atoi(pid + 4));
                }
            }
        }
    }
    {
        const char *pt = strstr(inner, "panicked thread");
        if (!pt) {
            pt = strstr(inner, "Panicked thread");
        }
        if (pt) {
            char line[320];
            take_line(pt, line, sizeof(line));
            snprintf(out->panicked_thread, sizeof(out->panicked_thread), "%s", line);
            {
                const char *tid = strstr(line, "tid: ");
                if (tid) {
                    snprintf(out->panicked_tid, sizeof(out->panicked_tid), "%d", atoi(tid + 5));
                }
            }
        }
    }

    out->recognised = out->build[0] || out->panic_string[0] || out->reg_mask || out->nframes || out->product[0];
    if (!out->recognised) {
        if (err && err_cap) {
            snprintf(err, err_cap, "no recognisable panic fields");
        }
        return 0;
    }
    return 1;
}

int panic_log_parse_file(const char *path, panic_log_t *out, char *err, size_t err_cap)
{
    char *text;
    size_t len = 0;
    int ok;

    if (err && err_cap) {
        err[0] = '\0';
    }
    text = slurp(path, &len);
    if (!text) {
        if (err && err_cap) {
            snprintf(err, err_cap, "cannot read %s", path ? path : "(null)");
        }
        return 0;
    }
    ok = panic_log_parse_text(text, out, err, err_cap);
    free(text);
    return ok;
}

size_t panic_log_slides(const panic_log_t *p, uint64_t *out, size_t cap)
{
    size_t n = 0;

    if (!p || !out || cap == 0) {
        return 0;
    }
    if (p->has_kernelcache_slide && p->kernelcache_slide && n < cap) {
        out[n++] = p->kernelcache_slide;
    }
    if (p->has_kernel_slide && p->kernel_slide) {
        size_t i;
        int dup = 0;
        for (i = 0; i < n; i++) {
            if (out[i] == p->kernel_slide) {
                dup = 1;
            }
        }
        if (!dup && n < cap) {
            out[n++] = p->kernel_slide;
        }
    }
    if (p->has_text_exec_slide && p->text_exec_slide) {
        size_t i;
        int dup = 0;
        for (i = 0; i < n; i++) {
            if (out[i] == p->text_exec_slide) {
                dup = 1;
            }
        }
        if (!dup && n < cap) {
            out[n++] = p->text_exec_slide;
        }
    }
    return n;
}

const char *panic_reg_name(int index, char *buf, size_t cap)
{
    static const char *aux[] = {"fp", "lr", "sp", "pc", "cpsr", "far", "esr"};

    if (!buf || cap == 0) {
        return "?";
    }
    if (index >= 0 && index <= 28) {
        snprintf(buf, cap, "x%d", index);
    } else if (index >= 29 && index <= 35) {
        snprintf(buf, cap, "%s", aux[index - 29]);
    } else {
        snprintf(buf, cap, "r%d", index);
    }
    return buf;
}
