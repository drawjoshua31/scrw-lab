# Panic triage: reading a real log

This is a guide to the artifacts this repository ships, not to one person's
phone. Both fixtures are real material:

- `tests/fixtures/panic_real_27_0_1_ave.ips`: a published 27.0.1 panic, product
  iPhone18,1, SoC T8150, with the large process map elided and every panic field
  left verbatim.
- `tests/fixtures/panic_pac_template.ips`: the standard 27.x PAC panic wording,
  with product and build redacted.

Read the field names, then apply them to your own log. Values differ. The shape
does not.

## Shape 1: the data abort

The first artifact's `panicString` opens with:

```
panic(cpu 5 caller 0xfffffe00461651f8): Kernel data abort.
```

and later carries a register block:

```
    x24: 0x0000000000000003 x25: 0x0000000000000000  x26: 0x0000000000000004  x27: 0x000000002ba60044
    x28: 0x0000000000000020 fp:  0xfffffeba5b71b460  lr:  0xfffffe00435710c4  sp:  0xfffffeba5b71b3f0
    pc:  0xfffffe004345b188 cpsr: 0x20400208         esr: 0x0000000096000046  far: 0x0000000100000059
```

Three things are worth noticing before any interpretation.

First, addresses are in the `0xfffffe...` range and `Kernel text base` is
`0xfffffe0041d3c000`. Older logs put text at `0xfffffff0...`. Never hardcode a
kernel mask. Subtract the parsed text base.

Second, `esr = 0x96000046` decodes as EC `0x25` (data abort, same EL) and FSC
`0x06` (translation fault, level 2). The faulting address `0x100000059` is not a
kernel pointer at all. It looks like a small value with bit 32 set, which is what
you get when a shorter value is used as a pointer.

Third, `lr` appears twice in this artifact: once in the register block and again
on every backtrace line. They are different. The trapped `lr` is the register
block value, and a parser that lets a frame line overwrite it will mislead you.

## Shape 2: the PAC failure

The second artifact's first line is the whole story:

```
panic(cpu 1 caller 0xfffffff0449b3478): PAC failure from kernel with DA key while authing x16 at pc 0xfffffff0449b3478
```

The template is stable across reports:

```
PAC failure from kernel with <key> key while authing <register> at pc <address>
```

Key meanings:

| Key | Signs | What a failure implies |
|---|---|---|
| DA, DB | data addresses, per diversifier | a corrupted pointer field, read from memory |
| IA, IB | instruction addresses | a function pointer, vtable slot or saved return address |
| GA | generic | context-dependent, usually a signed blob |

So `DA ... x16` says the kernel loaded a data pointer into x16, authenticated it
with the data-address key, and the value did not match. The kernel did not jump
anywhere. It refused to use a pointer it had been handed.

This distinction decides your next week of work. A data-key failure is
compatible with a write primitive that landed on a signed field, and the fix
direction is to move the write (H1 in `PLAN.md`). An instruction-key failure is a
control-flow project, and PAC forgery is not the way through it.

## Field by field

| Field | Real value in fixture 1 | Reading |
|---|---|---|
| `product` | `iPhone18,1` | hardware identifier, useful for offsets, not for the method |
| `socRevision` | `11` | revision, keep it with the build string |
| `socId` | absent | this artifact genuinely omits it; do not invent one |
| build | `iPhone OS 27.0.1 (24A446)` from `os_version` | the body has no `build` key, so the parser falls back |
| `kernel` | `xnu-13432.2.10~2/RELEASE_ARM64_T8150` | pick the kernelcache by this line |
| `caller` | `0xfffffe00461651f8` | return address into the code that called `panic()`, your fingerprint |
| `pc` | `0xfffffe004345b188` | where the fault happened |
| `far` | `0x0000000100000059` | faulting address; small and non-canonical |
| `esr` | `0x0000000096000046` | EC `0x25`, FSC `0x06` |
| `Kernel slide` | `0x000000003ad38000` | `stext - kch + KernelCache slide`; not a plain text slide |
| `Kernel text base` | `0xfffffe0041d3c000` | subtract this for the stable caller offset |
| `KernelCache slide` | `0x000000003ad30000` | fileset-wide slide, the first candidate for static symbol space |
| `KernelCache base` | `0xfffffe0041d34000` | base minus slide gives the static fileset base |
| `Kernel text exec slide` | `0x000000003e870000` | `TEXT_EXEC - kch + KernelCache slide`; header-relative |
| `Kernel text exec base` | `0xfffffe0048f14000` | start of the executable segment, not a symbol base |
| `SPTM-820.0.22` | version plus timestamp | names the monitor build, compare this first when diffing |
| `SPTM load address` | `0xfffffe0021d34000` | separate range from kernel text |
| `Panicked task` | `pid 20690: videocodecd` | attribution, but read the next section before trusting pids |
| `Kernel Extensions in backtrace` | `com.apple.driver.AppleAVE2(913.43.1)` | the driver owning a frame, with its `start->end` range |
| `otherString` | exclaves stackshot not found, then stackshot succeeded, 506986 bytes | both statements are true, see below |

## Three slides, not one

This is the part that costs people a day. The log reports a fileset slide, a
`__TEXT` slide and a text exec slide. They differ, and none is a plain KASLR
delta for the segment it names.

XNU's panic formatting code makes that explicit. In `osfmk/kern/debug.c` it
prints:

```c
void *kch = PE_get_kc_header(KCKindPrimary);
paniclog_append_noflush("KernelCache slide: 0x%016lx\n", vm_kernel_slide);
paniclog_append_noflush("KernelCache base:  %p\n", (void *)kch);
paniclog_append_noflush("Kernel slide:      0x%016lx\n",
    vm_kernel_stext - (unsigned long)kch + vm_kernel_slide);
paniclog_append_noflush("Kernel text base:  %p\n", (void *)vm_kernel_stext);
paniclog_append_noflush("Kernel text exec slide: 0x%016lx\n",
    (unsigned long)segTEXTEXECB - (unsigned long)kch + vm_kernel_slide);
paniclog_append_noflush("Kernel text exec base:  0x%016lx\n",
    (unsigned long)segTEXTEXECB);
```

The `Kernel slide` and `Kernel text exec slide` values are measured from the
kernelcache header, not from the segment's own static base. Subtract one from
the matching runtime base and you get the static header, not the static address
of the code you started with.

The shipped 27.0.1 artifact shows the same pattern:

```
KernelCache base - KernelCache slide = 0xfffffe0007004000
Kernel text base - Kernel slide       = 0xfffffe0007004000
Kernel text exec base - slide         = 0xfffffe000a6a4000
```

The first two agree because `__TEXT` begins at the header. The third does not.
That is why treating the text exec slide as a code slide produces a plausible
symbol at the wrong address. The log does not state which cache header a given
slide was computed against, so the tool has to test the candidates.

Practical rules:

1. Use `caller - Kernel text base` as the fingerprint. It is stable across
   boots and is what you record in `research/runs.md`.
2. Do not treat that number as a static address in a symbol dump. The caller
   and the text base are not accounted against the same slide.
3. When symbolicating, try every slide in the log and keep the one whose
   resolved names are coherent. `panicdump` prints one candidate per slide,
   labelled with the slide, and refuses to pick silently.
4. A release kernelcache has no core XNU symbols. `nm` returns mostly kext
   symbols, so a core XNU frame resolves to whatever kext sits before it. The
   giveaway is a stack that mixes GPU, video and Neural Engine frames. Use
   `ipsw kernel symbolicate` with the signature set for a real XNU table.

## The contradiction, resolved

Real 27.x artifacts can contain all three of these at once:

```
** Exclaves panic stackshot not found

** Stackshot Succeeded ** Bytes Traced 506986 (Uncompressed 1181648) **
```

and, in other captures:

```
missing stackshot buffer or size
resampled threads with truncated backtraces from 0 pids
```

They describe different collectors:

- `Stackshot Succeeded` is the primary stackshot, compressed into the artifact.
  The bytes are there. Decode them.
- The exclaves line is a secondary collector that could not find its buffer.
  Exclaves are a separate execution environment, so its stackshot is separate.
- `from 0 pids` means process enumeration came back empty. Thread backtraces can
  exist while process attribution does not.

Consequences, in order of importance:

1. Do not conclude you have no backtrace. Decode the compressed stackshot first.
2. Do not trust process names or pids from a 0-pid capture. The name may be
   missing or wrong.
3. Do trust registers, `caller`, `pc` and `esr`. They come from the trap frame,
   not from stackshot.

## Step 1: freeze the build

A beta will be unsigned eventually, possibly soon.

- disable automatic updates
- keep the phone offline when you are not testing
- record the build string everywhere: offset DB section key, artifact folder
  names, run log
- accept now that you cannot downgrade, and plan for the device to end up on a
  newer build

## Step 2: collect the whole incident

Panic artifacts are split. Pull all siblings, not one file:

```
panic-full-<date>.ips
panic-<date>.ips
.panic
```

`pymobiledevice3` or `libimobiledevice` can copy the crash directory. Script it
so each boot costs one command, and name the folder by build plus UTC timestamp.

## Step 3: decode the compressed stackshot

Use a tool that expands the stackshot rather than grepping `panicString`:

```
ipsw panic <artifact>
```

You are looking for frames below the `panic()` caller. The caller of the
function that panicked is usually the code that detected the bad state, not the
code that created it.

## Step 4: fingerprint the site

```
build/panicdump --symbols <syms>.txt <artifact>
```

Record:

- `caller` offset from `kernel_text_base`, stable across KASLR
- `pc` and `lr` offsets
- ESR decode: EC, and FSC for a data abort
- which registers hold kernel text pointers, kernel VAs, or small values

On the shipped 27.0.1 artifact the report prints:

```
caller  0xfffffe00461651f8  +0x44291f8 from text base
pc      0xfffffe004345b188  +0x171f188 from text base
esr     0x0000000096000046  EC=0x25 (data abort, same EL) FSC=0x06 (translation fault, level 2)
```

With `--symbols`, each of those addresses gains one symbol candidate per slide
in the log, labelled like `[0x3ad30000] _function+0x123`. Compare the
candidates against the frames around them instead of trusting the first one.

A wild, non-canonical `far` with a translation fault reads as "something
dereferenced a corrupted value". A permission fault on a valid-looking address
suggests a different bug: wrong object, wrong offset, or a lifetime problem.

## Step 5: marker experiment, which proves value control

This is the most informative single experiment available.

1. Pick a value that will not occur naturally: `0x53524357DEADBEEF` (ASCII
   `SCRW` plus a canary).
2. Spray it in the shape your bug consumes: same allocation class, same size,
   same count as your working trigger.
3. Run one attempt. `poc_pac_probe` writes the parameters and the marker to its
   breadcrumb log before calling the trigger.
4. Reboot, pull the artifact, then run
   `build/panicdump --marker 0x53524357deadbeef --symbols <syms> <artifact>`.
5. Read the verdict:
   - marker in a register or in `far`: you control the faulting value. Go to H1
     and move the write onto a non-signed field.
   - no marker: either the value was transformed (arithmetic, tagging, partial
     overwrite) or you never controlled it. Repeat with `--marker-mask` to ignore
     low bits, and with a second spray shape.

Do not change two things between runs. Three markers with one shape beats one
marker with three shapes, because only the first isolates the variable.

## Step 6: bisect one parameter at a time

`poc_pac_probe --plan` prints a matrix, and each line is one boot.

For each run record parameters, caller offset, marker hit, ESR and FSC, and
whether the device survived. Append to `research/runs.md`, one row per boot.

You are looking for a deterministic relationship: change `size` by 0x40 and
`far` moves by 0x40, or the fault changes from translation to permission. That
relationship is what turns a crash into controllable corruption.

## Step 7: symbolicate properly

You need a symbol list for your exact build. Options, in order of preference:

1. an `ipsw` or `jtool2` symbol dump of the matching kernelcache
2. a `System.map`-style list from a debug or virtual target of the same XNU line
3. a hand-built list of the few functions around your caller offset

Symbol lists are static kernelcache addresses, the kind `nm` or `ipsw` print,
not runtime addresses from the log. `panicdump` subtracts a candidate slide
before looking one up, which is why the candidate labels matter.

Format is flexible (`0xaddr name` or `name 0xaddr`):

```
0xfffffff0079b3000 _panic_pac_failure
0xfffffff0079b3500 _caller_after_pac_check
```

The numbers above are illustrative, because they belong to the redacted PAC
fixture, not to your build. The first column is the symbol's static start, not
the caller address from the log.

## Step 8: diff the fix out of a later build

This is Phase 1.5 in `ROADMAP.md`, and the short version is:

1. confirm the component actually changed, by byte comparison
2. map your caller onto both lists:
   `build/panicdiff <artifact>.ips old.syms new.syms`
   It tries every slide in the log, prefers a symbol name that exists in both
   builds, and prints every candidate. Read the chosen slide and the verdict
   before trusting any single mapping.
3. `build/symdiff old.syms new.syms --limit 100`
4. disassemble around your caller's function in both builds
5. write the root cause in one paragraph

Knowing the root cause tells you whether the bug is parameterised (H1 viable) or
a design assumption (H1 dead). It also makes the bug report worth reading.

## Step 9: better traces than the device can give

- Corellium or a vphone-style VM: same bug class, debug kernel, symbols,
  breakpoints, no boots lost. Reproduce the class, then port the offsets.
- Apple Security Research Device: a debug kernel with symbols on real silicon,
  which is exactly what this phase wants. Worth applying for even if it takes
  months.
- More instrumentation, not more boots: add logging before each stage and read
  it from the syslog after reboot, together with the breadcrumb WAL.

## Checklist

- [ ] build frozen and recorded
- [ ] whole incident collected, all siblings
- [ ] stackshot decoded, not just `panicString`
- [ ] caller offset recorded
- [ ] all reported slides recorded and compared
- [ ] ESR EC and FSC decoded
- [ ] PAC key and register noted, if present
- [ ] marker experiment run, verdict recorded
- [ ] bisect matrix started, one variable per boot
- [ ] symbol list built for the exact build
- [ ] fix located in a later kernelcache
- [ ] root cause paragraph written
