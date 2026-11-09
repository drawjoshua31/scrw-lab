# Architecture

## Modules

| # | Module | Purpose | 27.x challenge | Inspired by |
|---|---|---|---|---|
| M0 | Target profile (`offset_db`, `symtab`) | Identify the build, hold per-build constants, symbolicate | Builds move fast, betas disappear, offsets must fail loudly | Dopamine's per-version offset tables; ipsw and jtool2 output |
| M1 | Initial access (external) | Get code running in a context that can reach the bug | Your posture (app sandbox, WebContent, daemon) decides the reachable surface | pois0nSword, bad_query |
| M2 | Reach widening (`research/`) | Sandbox escape or entitlement step to reach more kernel surface | Extension issuance is still logic, and logic still breaks | bad_query |
| M3 | System core bug (external) | The memory corruption itself | kalloc_type segregation; no EMTE before A19, which helps | DarkSword, AVETemporal |
| M4 | Primitive shaping (`poc_pac_probe`, `panicdump`) | Turn a crash into controlled corruption: value, offset and lifetime control | One panic per boot, so every run must be instrumented | AVETemporal's negative result; kfd's primitive ladder |
| M5 | PAC strategy (`pac_lab`, docs) | Understand what traps and why; choose avoid or confuse | Keys are secret, so route around authentication | Fugu15 badRecovery; Titan; pois0nSword |
| M6 | SCRW (`scrw.c`, `scrw_stub.c`) | Stable kernel read/write behind a policy layer | On SPTM hardware there is no page-table path, so data-only only | Dopamine's libkernrw/pplrw split |
| M7 | Post (out of scope here) | Credentials, trust caches, daemon state, reporting | Executable mappings need TXM and SPTM cooperation | CryptSn0w's bootstrap; TrollStore lineage |
| M8 | Stability (`breadcrumb`, stats, selftest) | Survive, measure, recover | Panics destroy in-process logs, so the log needs an fsync WAL | Dopamine's PPLRW performance discipline |
| M9 | Research infra (`symdiff`, `panicdiff`, `research/`) | Patch diff, hypothesis log, artifact pipeline | Fixes are protocol-shaped; server-side fixes are invisible | ABrake27; iOS27.0.1-SPTM-Research |

## Data flow

```
panic .ips -> panic_log_parse_file -> panic_log_t
                                        |
              symtab (0xaddr name) -----+
                                        v
                                 panic_report -> text / JSON
                                        |
                                        +- caller offset -> kernelcache diff
                                        +- PAC key/reg   -> data vs control flow
                                        +- marker hits   -> value-control verdict
                                        +- ESR/EC/FSC    -> fault classification

device trigger -> breadcrumb WAL (fsync) -> survives panic
       |
       +-> avet_trigger(params) -> panic or return

backend (your bug) -> scrw_backend_t -> scrw_cread / scrw_cwrite
                                            |
                          guard, arming, bounds, chunking, stats
                                            |
                                     selftest (Mach-O magic, known strings)
```

## Parsing a real artifact

The parser is written against logs, not against a schema, because three things
vary in practice:

1. `build` is often absent from the JSON body on 27.x. It exists in the metadata
   line as `os_version`, so the parser falls back to that and never invents one.
2. Kernel virtual addresses moved. Older logs put text at `0xfffffff0...`, the
   shipped 27.0.1 artifact puts it at `0xfffffe0041d3c000`. Classification is
   therefore relative to the parsed `Kernel text base`, not a fixed mask.
3. A backtrace is printed as `lr:` and `fp:` pairs in recent builds, and the
   register block also contains `lr:`. Registers are first-wins, so a frame can
   never overwrite the trapped `lr`.

Extras that turned out to be worth parsing:

| Field | Why it matters |
|---|---|
| `SPTM-<version>|timestamp|` | Names the exact SPTM build, which is the first component to compare when a fix lands |
| `KernelCache slide` and base | Fileset-wide slide; the first candidate for converting a runtime frame into static symbol space |
| `Kernel text exec slide` and base | Computed from the kernelcache header, so subtracting it does not give the segment's static base |
| `Fileset Kernelcache UUID` | Identifies the exact kernelcache to diff; a build string alone can match several |
| `SPTM load address` | Separates the monitor from kernel text when classifying pointers |
| `Kernel Extensions in backtrace` | `name(version)[UUID]@start->end` names the driver and its range, so a caller outside text still resolves |
| `PAC failure from kernel with <key> key while authing <reg>` | Decides data pointer versus control flow before you spend a boot |
| `Exclaves panic stackshot not found` | Explains a contradiction that otherwise looks like data loss |

## Address classification

`kva_class` answers "what kind of pointer is this", in this order:

1. zero
2. below 1 TB: small or user
3. at or above `0xfffffff000000000`: old-layout kernel text or static data
4. inside `[text_base, text_base + 512 MB)`: kernel text on the current layout
5. at or above `0xfffffe0000000000`: kernel VA, heap or kext
6. anything else: non-canonical

The 512 MB ceiling is a sanity check for a wrong slide, not a claim about text
size. A real 27.0.1 caller sat 71 MB above text base and was still legitimate.

## Symbolication and slides

The log carries `KernelCache`, `Kernel` and `Kernel text exec` slides. XNU
computes the latter two from the kernelcache header, not from the segment base:
`stext - kch + vm_kernel_slide` and `TEXT_EXEC - kch + vm_kernel_slide`.
Subtracting one from the matching runtime base therefore lands on the static
kernelcache header, not on the static address of that segment. There is no
single slide that maps every frame, and this project does not pretend
otherwise.

The report therefore treats symbolication as a candidate set:

```
for each slide in {kernelcache, kernel, text_exec}:
    static = runtime - slide
    candidate = greatest symbol <= static
print every candidate, labelled with the slide
```

For `panicdiff`, the candidate set is scored across two builds: a slide whose
resolved old symbol name also exists in the new table is preferred, and the
choice is printed. Same-symbol delta is not proof of unchanged code. It only
means the function did not change size relative to the modal shift.

## The SCRW contract

```c
scrw_err_t scrw_cread (scrw_ctx_t *, uint64_t addr, void *buf, size_t len, size_t *done);
scrw_err_t scrw_cwrite(scrw_ctx_t *, uint64_t addr, const void *buf, size_t len, size_t *done);
```

Guarantees the layer provides:

- No wrapping. `addr + len` is checked before anything else.
- No accidental writes. `require_arm_for_writes` defaults to 1, and arming needs
  `SCRW_ARM_MAGIC` plus a backend that advertises `can_write`.
- No blind reads. `enforce_windows` and `scrw_add_window` confine a wobbly
  primitive to ranges you have validated.
- No silent truncation. A short transfer is an error, and `*done` says how far
  it got.
- No lying selftests. `scrw_selftest` returns `SCRW_E_STATE` if any check fails,
  and never reports ok for a read that errored.

Backend obligations:

- exact or error, no partial fills
- `SCRW_E_FAULT` for inaccessible addresses, never `abort()`
- single-threaded unless documented otherwise

## Invariants

1. The slide is proven, not assumed. `open()` verifies it by reading
   `MH_MAGIC_64` at `kernel_text_base`. Otherwise every later read is fiction.
2. Offsets fail loudly. Call `offset_db_require` at the use site, with no zero
   defaults.
3. One hypothesis per boot. The harness takes a full parameter set and one
   attempt. Two changes give zero information.
4. Breadcrumb before the dangerous call, not after. The mark is fsynced before
   the operation that can panic.
5. Never corrupt a signed pointer on purpose. If the target is signed, shift the
   write (H1) instead of trying to satisfy authentication.
6. Writes are validated by read-back on a harmless field first. A write that
   returns success but writes garbage is worse than none.

## Failure model

A kernel fault is not catchable from userland. There is no try/except around a
bad `cwrite`: the phone panics. The architecture therefore optimises for
learning per boot, not for runtime safety:

- breadcrumbs make the last stage recoverable after reset
- markers make value control provable from the panic artifact
- the caller offset makes the site stable across boots and KASLR
- `symdiff` turns "fixed in a later build" into a location
- the loopback backend tests the policy layer without risking a boot

## Adding a backend

1. Copy `src/scrw_stub.c` to a new file. Do not edit the stub.
2. Fill `open()`: slide, text base and size, and prove the magic.
3. Implement `read()` for three addresses you can verify independently.
4. Run `scrw_selftest` with those three checks. If it passes, add more.
5. Add `write()` behind arming. Test write then read-back on a field you own.
6. Only then wire it into a tool. Keep the stub in the tree as the reference.

## Adding a hypothesis

Copy `research/hypotheses/TEMPLATE.md`. Every hypothesis needs the claim, the
surface, the expected primitive, the test, the instrumentation, the kill
criterion, and the patch-diff evidence that motivated it. A hypothesis without a
kill criterion is a wish.

## Test strategy

- Policy layer: loopback backend, deterministic. Covers arming, guard, overflow,
  chunking, stats and selftest failure.
- Parser, real artifact: `panic_real_27_0_1_ave.ips` exercises the build
  fallback, the new VA layout, all three slides, `lr:` frames, SPTM parsing,
  kext parsing, and a stackshot section that reports success and a missing
  exclaves buffer together.
- Parser, PAC artifact: `panic_pac_template.ips` exercises the PAC key and
  register fields, the old VA layout, and the missing-buffer and zero-pid notes.
- Report: marker detection in text and JSON, PAC verdict wording, caller offset
  arithmetic.
- Offsets and symbols: wrong-build rejection, missing-key behaviour, lookup
  ordering, and refusal to answer after an incompatible sort.
- `panicdiff`: exact modal delta, a stable mapping, one function shifted by
  `0x200` against the modal delta, a removed symbol, a multi-slide tie-break,
  and the no-caller, no-text-base, below-text, no-slide and no-old-symbol
  failures. It also checks that the text exec slide does not resolve the PAC
  caller in the fixture table.

Run `./scripts/build_host.sh test`.
