# scrw-lab

Research scaffolding for turning a crash-only iOS kernel bug into a System Core
Read/Write primitive, and for studying the mitigations that decide whether that
is possible on a given phone.

> ### Educational research only
>
> - Use a spare device you own. Not your daily driver, and not anyone else's.
> - A kernel bug that panics can also corrupt data, brick the install, or put
>   the phone in a boot loop. Restoring needs a computer, a cable, and an IPSW
>   Apple still signs. You cannot downgrade. If the build your bug lives on is
>   unsigned by the time you need to restore, that bug is gone with it.
> - Everything here is for learning how the system works and for reporting
>   findings to Apple. There is no malicious-use path in this repository.
> - Publishing a working chain for a current iOS is a disclosure decision with
>   real consequences. Read `docs/ETHICS.md` before you post anything.

## What the project assumes about hardware

Nothing in the code is tied to one model or one build. The plan does depend on
the generation of the SoC, because that decides which mitigations you face:

| SoC generation | Examples | Kernel page-table protection | Heap tagging |
|---|---|---|---|
| A12, A13 | iPhone XS to 11 | PPL | none |
| A14 | iPhone 12 | PPL | none |
| A15 to A17 | iPhone 13 to 15 Pro | SPTM + TXM | none |
| A18 | iPhone 16 | SPTM + TXM | none |
| A19, A19 Pro, M5 | iPhone 17 lineup, iPhone Air, iPad M5 | SPTM + TXM | EMTE (memory integrity enforcement) |

Two consequences shape the plan:

1. On SPTM hardware, a data-only primitive is the realistic target. A page-table
   primitive needs an SPTM bypass, and there is no public one on release builds
   at 17.4 or later. Titan did reach 17.4 beta 3, and was closed in beta 4.
   Dopamine's release notes put it plainly: SPTM devices are supported to 27.0
   betas on Corellium, and real devices only to 17.3.1 on releases.
2. PAC is why a corrupted pointer panics, and every useful strategy in this
   repo avoids it rather than defeating it: route around authentication instead
   of trying to produce a valid MAC.

EMTE is the one mitigation that is genuinely absent before A19. On an older SoC
a stray 8-byte write does not trip a tag check. It still has to survive typed
allocation and it still must avoid signed fields.

EMTE does not replace PAC. The shipped 27.0.1 fixture is an iPhone 17 Pro, which
is A19 Pro and therefore MIE hardware, and it still died on a data-address PAC
failure. Tags catch mismatched memory; PAC catches a pointer whose signature
does not validate.

## Two panic shapes, both real

The parser and tests are built on artifacts, not invented field values:

| Fixture | What it is | Why it is here |
|---|---|---|
| `tests/fixtures/panic_real_27_0_1_ave.ips` | Published 27.0.1 panic artifact for iPhone18,1 (iPhone 17 Pro, A19 Pro, T8150), with the large process map elided and the panic fields verbatim | Real `Kernel data abort`, real register block, real SPTM and kext lines, and a stackshot section that contradicts itself |
| `tests/fixtures/panic_pac_template.ips` | The standard 27.x PAC panic wording, with product and build redacted | Shows the exact string and register a PAC trap produces |

The second one matters because of one line:

```
panic(cpu 1 caller 0xfffffff0449b3478): PAC failure from kernel with DA key while authing x16 at pc 0xfffffff0449b3478
```

That is a data-address key failing on a data pointer held in x16. The kernel
never jumped anywhere: it loaded a pointer from memory, tried to authenticate
it, and the value did not match its PAC. Something corrupted a field that holds
a signed pointer.

That single observation is why the project aims at data-only corruption. It also
gives the report a concrete verdict: find the object, then shift the corruption
onto a field the kernel does not authenticate.

The first fixture supplies the rest of the real-world detail: kernel text at
`0xfffffe0041d3c000` (a different VA layout from the older `0xfffffff0...`
range), an `AppleAVE2` frame in the trace, SPTM version `SPTM-820.0.22`, and an
`otherString` that reports both `Exclaves panic stackshot not found` and
`Stackshot Succeeded` with 506986 bytes traced.

## Status

Working today:

- `scrw_cread` / `scrw_cwrite` policy layer with bounds checks, overflow
  checks, an allowlist, write arming, chunking, statistics and self-tests
- a backend vtable, a fail-closed device stub, and an in-memory loopback backend
  used by the tests
- a tolerant panic parser for JSON `.ips` and plain `.panic`, including
  registers, caller, all three slides and bases, fileset UUID, inline frames,
  PAC key and register, SPTM version, kext in trace, ESR decoding, and the
  stackshot contradictions
- slide-aware symbolication: for each reported slide the report shows a
  candidate symbol instead of pretending one slide fits every frame
- `panicdump`, which turns a panic into a caller offset, a PAC reading, a marker
  verdict and a next experiment
- `symdiff`, which groups symbol deltas to locate patched neighbourhoods
- `panicdiff`, which maps a caller onto an old and a new symbol dump, tries
  every reported slide, prints each candidate, and separates stable, shifted
  and removed functions
- a PAC lab and an instrumented, bisectable trigger harness for the device
- 192 host assertions, no device required

Not here, on purpose: a vulnerability, offsets for any build, an exploit chain,
or an SPTM bypass. Those are the research.

## Build and use

```sh
./scripts/build_host.sh test
```

No dependencies beyond a C11 compiler. On the phone:

```sh
./scripts/build_device.sh          # needs macOS, Xcode and a signing identity
```

Analyse an artifact:

```sh
# with a symbol list you built for that exact kernelcache
build/panicdump --marker 0x53524357deadbeef \
                --symbols build/syms-<build>.txt \
                <artifact>.ips

# the two shipped fixtures, with no device and no symbols
build/panicdump tests/fixtures/panic_real_27_0_1_ave.ips
build/panicdump --marker 0x53524357 tests/fixtures/panic_pac_template.ips
```

Map a panic caller onto a later kernelcache, then diff the neighbourhood:

```sh
build/panicdiff <artifact>.ips build/syms-<old>.txt build/syms-<new>.txt
build/symdiff build/syms-<old>.txt build/syms-<new>.txt --limit 100
```

## Layout

```
include/            public headers: scrw.h, panic_log.h, offset_db.h, ...
src/                policy layer, panic parser/report, offset DB, breadcrumbs
src/device/         arm64e/iOS-only: pac_lab, poc_pac_probe
tools/              panicdump, panicdiff, symdiff
tests/              host assertions and two real panic fixtures
docs/               PLAN, ARCHITECTURE, ROADMAP, PANIC-TRIAGE, ETHICS
research/           verified findings, patched-project case studies, hypotheses
scripts/            host and device builds
```

## Reading order

1. `research/FINDINGS.md`: what is verified against primary sources, what was
   corrected, and which claims are still second-hand
2. `docs/PLAN.md`: case studies, what died and why, what survives on 27, new
   method hypotheses, research library
3. `docs/PANIC-TRIAGE.md`: how to read a real log field by field and what to do
   next
4. `docs/ARCHITECTURE.md`: modules, invariants, and how to add a backend
5. `docs/ROADMAP.md`: phases with exit criteria

## Credits

The case studies reference work by GenericCoding, varik, 0xjohnny, opa334,
alfiecg24, staturnzz, TheRealClarity, forcequitOS, 34306, vvirei333,
IvanIVGrozny, and the Fugu15/Dopamine lineage. This project borrows their
methods, not their bugs, and none of them are affiliated with it.
