# Plan: from a PAC panic to a System Core primitive

This document is the research half of the project. It assumes you have read the
disclaimer in `README.md`.

---

## 1. What SCRW is, and what it can be on SPTM hardware

System Core is Apple's term for XNU plus its kernel extensions. SCRW is an
arbitrary read/write primitive over that address space: `cread(addr)` and
`cwrite(addr, bytes)`.

On an SPTM-era phone running iOS 27, four mechanisms stand between a
memory-corruption bug and that primitive:

| Mechanism | What it protects | Status |
|---|---|---|
| PAC | control flow and selected data pointers: return addresses, function pointers, vtable entries, signed fields | present on arm64e; keys are secret, per-key and per-diversifier |
| SPTM + TXM | page tables and executable-mapping policy | present from A15; replaces PPL |
| KIP | kernel text integrity at boot | present; text is not writable, ever |
| kalloc_type | heap: allocations are segregated by type | present since iOS 15 |

And one that is absent on most hardware, which matters:

| Mechanism | What it detects | Status |
|---|---|---|
| EMTE (MTE tags) | heap out-of-bounds and use-after-free by tag mismatch | A19 and M5 only |

That last row is the good news for older phones. A stray 8-byte write on an A15
does not trip a tag check the way it would on an A19. It still has to survive
kalloc_type segregation, and it still must not land on a signed pointer.

### The honest shape of the goal

```
  crash-only bug
      |  (phase 3: prove value or offset control)
      v
  controlled memory corruption
      |  (phase 4: stop corrupting signed pointers)
      v
  data-only kernel R/W          <-- SCRW, the realistic target
      |  (phase 8: separate, much harder problem)
      v
  SPTM/TXM cooperation -> page tables, executable mappings, unsigned code
```

The last arrow is not part of this project. Without an SPTM bypass it does not
happen, and there is no public SPTM bypass on release builds at 17.4 or later.
Titan covered 17.4 betas 1 to 3, and was closed in beta 4. Anyone who says a
data-only bug "becomes a jailbreak" is skipping the hardest step.

Define success at the data-only line. A stable `cread`/`cwrite`, a clean
write-up, and a patch diff that explains your own bug is a good outcome. It is
better than most published "jailbreak progress" threads.

### Reading an address out of a panic

A log carries three independent slides, and they are not interchangeable. The
`Kernel` and `Kernel text exec` slides are computed from the kernelcache
header, not from the segment they name: subtract one from a text address and
you get the static header, not the static address of that code.
`research/FINDINGS.md` works through the arithmetic.

Two numbers are useful, and they answer different questions:

- `caller - Kernel text base` is the stable fingerprint. It survives KASLR and
  is what you compare across boots and builds.
- `caller - <one of the reported slides>` is a candidate static address for a
  symbol dump. No single slide is guaranteed right for every frame, so try each
  and keep the mapping whose surrounding frames resolve coherently.

`panicdump` prints a candidate per slide and labels the slide it used. Treat a
candidate as evidence, not as an answer.

---

## 2. Two ladders that look alike and are not

`0xjohnnydev/cryptsn0w` is worth studying, and worth being precise about,
because the distinction decides what you do next.

| | Signing ladder (`cryptsn0w`) | Memory ladder (a kernel bug) |
|---|---|---|
| Bug | server-side TSS/Cryptex authorization: the signing service issued a ticket for a device-personalized cryptex plus a trust cache | kernel memory corruption reachable from your process |
| What you get | a trusted signed base, so code execution without any kernel exploit | a panic, and eventually a memory primitive |
| PAC and SPTM | irrelevant: nothing is bypassed, everything is signed | decisive: PAC traps you, SPTM bounds you |
| How it was fixed | server-side, announced 17 Oct 2026 | client-side, in a future build |
| Can you diff the fix | no, nothing changed on the device | yes, the fix is in the kernelcache |
| Can offsets bring it back | no, there is no local artifact to reverse | partially, the bug is in a binary you can disassemble |
| What transfers | the loader architecture, but only after you already have a trusted base | everything: trigger, panic, offsets |

CryptSn0w was an untethered jailbreak with no kernel exploit in it. That is why
it worked, and why the patch is unreachable: Apple stopped issuing the ticket.
Studying the repo teaches trust caches, cryptex layout and bootstrap design. It
teaches nothing about PAC, because it never touched PAC.

Practical consequence: stop looking for the memory-ladder bug in signing
projects, and stop looking for signing-style shortcuts in a memory bug.

---

## 3. Case studies

The rule for all of them: the bug is dead, the method may not be. Ask what the
fix says about where the next one lives, rather than whether this one can be
ported.

| Project | Primitive or bug | Why it died | What defeated it | Does the class survive on 27? |
|---|---|---|---|---|
| CryptSn0w (0xjohnnydev, GenericCoding) | TSS/Cryptex ticket leading to a personalized cryptex with a trust cache; signed base, no kernel exploit | Apple stopped issuing tickets; project announced obsolete on 17 Oct 2026 | server-side authorization fix | Not locally observable. TSS and personalization logic remain high-leverage, but they are invisible to binary diffing and cannot be studied from the phone. |
| pois0nSword (GenericCoding) | WebKit CVE-2025-43529 leading to WebContent r/w (addrof/fakeobj, then 64-bit r/w); userland PAC bypass CVE-2026-20700; dyld interposing for native calls | both CVEs fixed | WebKit UAF fixed in 26.2 and 18.7.3; dyld PAC bypass fixed in 26.3 and backported to 18.7.7 | Not kernel. The ladder (r/w, then native call, then dyld's own allocator installs the interpose table) is reusable methodology. Offsets, locks and the default-false embedder preference are build-bound. |
| DarkSword, darksword-kexploit, ClearSword | the in-the-wild kit used CVE-2025-43520, a XNU VFS race, for kernel privilege escalation on 18.4 to 18.7.1; the public kexploit repository is a separate artifact with 15.x offsets and a "scribble" r/w primitive | CVE-2025-43520 fixed in 18.7.2 and 26.1 | bounds and lifetime fix in the VFS path | VFS race and lifetime bugs remain fertile in principle. kalloc_type makes reclaim harder, SPTM makes the page-table follow-up unavailable, and the published offsets do not transfer. |
| Dopamine 3.0 (opa334) | the reference architecture: exploit, PPL/SPTM bypass, kRW, bootstrap | not applicable, it is the map | not applicable | Its release notes are the single most important fact here: SPTM devices to 27.0 betas on Corellium, real devices to 17.3.1, "due to lack of an SPTM bypass on >=17.4". Also the source of the performance discipline: batch, cache, never per-byte. |
| Titan (alfiecg24) | SPTM/PPL bypass 16.1 to 17.4b3, A14 to A17: AGX coprocessor ROP, then microPPL bypass, then AP page table with a self-referencing PTE | self-ref PTE fix (17.4b4), AGX instruction PAC (18.1b4), `ipc_port` data PAC (26) | three separate fixes, each closing one step | The SPTM-era phones in its range are supported on releases to 17.3.1, and Titan itself reaches 17.4 beta 3, which is the wall this project assumes. SPTM bypasses came from other processors (AGX), not from the AP kernel. It also needed `kalloc` and `kmap` secondary primitives to be useful. |
| momentarius (staturnzz, TheRealClarity) | A12/A13 PPL bypass, 16.6 to 18.7.1 and 26.0 to 26.0.1 | not patchable (design flaw, per opa334) | none | PPL, not SPTM, and A12/A13 only. Relevant as a lesson in what "unpatchable" looks like: a design assumption, not a missing check. |
| AVETemporalPoC (CVE-2026-112705) | AppleAVE2 kernel OOB write through VideoToolbox `NumberOfTemporalLayers = 16463`; 27.0.1, fixed 27.2 | bounds check added in the setter | fixed-offset constant fill: `far = 0x59`, PC at `+0xDA78`, no value control, DoS only | Best available "a crash is not a primitive" case study, and this repo ships its published 27.0.1 artifact as a fixture. On A19 it also faces EMTE. On A15 the absence of EMTE makes a constant fill more interesting, but this driver path is patched. |
| bad_query (forcequitOS) | sandbox escape 26.0 to 26.6.1 and 27.0b4 through MobileGestalt plus sandbox-extension query logic; grants container paths | still working on some builds per the author | authorization logic, not memory safety | Logic flaws in extension issuance still pay on 27. Use it as a reach multiplier: app sandbox to daemon containers to a much larger kernel surface. Not a kernel primitive. |
| usbliter8-fun (34306, forks by Xplo8E and Liter8) | SecureROM USB bug on A12/A13 (plus S4/S5), needs an RP2350 board; tethered custom firmware | hardware generation, and a court injunction | BootROM generation, and the tool is legally contested | Not applicable to SPTM phones. Useful as a reference for the endpoint: tfp0 patches and libkrw0-tfp0 show what a fully privileged primitive looks like from boot. |
| ABrake27 (vvirei333) | static AMFI diff of 27.0.1 (24A446) against 27.2b2, plus analysis of CVE-2025-43520 | methodology, not a bug | not applicable | The method to copy: diff two kernelcaches, isolate changed functions, reason about root cause. Its AMFI claim is explicitly static-only and unverified, so treat it as a hypothesis with a test. |
| iOS27.0.1-SPTM-Research (IvanIVGrozny) | SPTM TLB-invalidation race fix, 27.2b1 to 27.2b3, T8150 | fixed by a lock protocol | per-CPU gate, 24 new `dmb ish`, GMMU TLBI verification | Best public demonstration that SPTM fixes are protocol-shaped, not check-shaped. Also a negative reachability result: the AGX user client does not reach UAT mutation. |

### How the studied projects actually work

These notes come from reading the source, not the READMEs.

CryptSn0w. The loader never asks for a kernel primitive. `codex_exec_worker.c`
checks `csops(pid, CS_OPS_STATUS)` for `CS_DEBUGGED` (0x10000000) and needs
`jitterd` reachable through `bootstrap_look_up`, then uses `ptrace(PT_ATTACHEXC)`
followed by `PT_DETACH`. The dyld piece, `sbinject_dyld_bypass.c`, finds the
`mmap` and `fcntl` stubs by byte signature (`b0 18 80 d2 01 10 00 d4` and
`90 0b 80 d2 01 10 00 d4`), overwrites them with an absolute jump built from
four `movz x16` instructions plus `br x16`, answers success for
`F_ADDFILESIGS_RETURN` (setting `fs_file_start` to `0xffffffff`) and
`F_CHECK_LV`, and maps the payload anonymously before `mprotect` to RX. In other
words, it does not break code signing. It makes dyld's own validation path
return the answer it wants, inside a process that is already trusted.

pois0nSword. `do_chain.js` runs a UAF into addrof/fakeobj, uses a "scribble"
primitive, and lands on read64/write64. It disables GC through
`m_isSafeToCollect`, leaks the JavaScriptCore slide by walking `parseFloat` to
`JSFunction.m_executable` and then `NativeExecutable.m_function`, and uses a
39-bit address mask because PAC bits spill into bit 39. After the stage 4 park it
rebuilds addrof/fakeobj on top of read64/write64 so the chain survives. Native
calls are installed by interposing on `lsl::Vector.allocator`, which makes dyld's
own allocator write the interpose tuples. The PAC step is a confused deputy, not
a forgery.

Titan. The chain overwrites AGX `power` thread state, builds a ROP chain that
ends in `ERET`, and uses the microPPL hibernation context to swap `TTBR1_EL1` so
it can map an XNU page table and plant a self-referencing PTE. Each of those
steps needed a secondary primitive (`kalloc`, `kmap`) and a physical range that
excluded AGX pages. Apple closed the steps one at a time, in three different
components, which is a useful measure of what the next bypass costs.

AVETemporalPoC. The trigger sets `NumberOfTemporalLayers` to 16463 and the
driver writes a constant past a small allocation at a fixed offset. `far` is
0x59 and the PC sits at `+0xDA78`. There is offset control and no value control,
so the honest classification is DoS. The published artifact is also a good
example of a 27.x log: real kernel VAs at `0xfffffe...`, SPTM version and load
address inline, and a stackshot section that reports an exclaves buffer missing
while the primary stackshot succeeded.

ABrake27 and the SPTM research repo. Two methodology lessons: do not compare a
`.0.1` build against a beta and attribute two releases of change to one, and
count barriers rather than functions. The SPTM repo found 27.0.1 and 27.2b1
shipped a byte-identical SPTM, then found 27.2b3 added a per-CPU gate and took
the `dmb ish` count from 3 to 27. That is a faster signal than any function-level
diff.

---

## 4. Ten lessons that decide whether this project works

1. PAC is a tripwire, not a wall. A panic means something wrote a value into a
   slot the kernel authenticates. PAC did its job. The interesting question is
   which slot and what value, not how to forge a MAC.
2. Nobody breaks PAC. They route around it. Fugu15's `badRecovery`, Titan's AGX
   path and pois0nSword's dyld interpose all make a legitimate component sign or
   authenticate on their behalf. Expect that shape or none.
3. A crash is not a primitive. Value control, offset control and lifetime
   control are three separate properties. AVETemporal has offset control and
   nothing else, which is why it is a DoS.
4. Data-only beats control-flow on SPTM hardware. Every page-table trick costs
   an SPTM bypass you do not have. Every signed-pointer trick costs a PAC you
   cannot forge. Aim at lengths, flags, refcounts and data pointers.
5. kalloc_type changes heap strategy, not feasibility. Typed allocation removes
   the easy "reclaim with a different object" move for typed caches, and does
   nothing to untyped or legacy zones. Enumerate which is which before designing
   a spray.
6. The absence of EMTE before A19 is a real advantage. Do not import A19-era
   pessimism. Check your own SoC before assuming a tag check exists.
7. Server-side fixes are invisible to diffing. If a chain dies because a service
   stopped issuing something, no amount of kernelcache work helps. Recognise the
   shape early and stop.
8. Betas are time-limited material. A beta seed has extra assertions and
   logging, and it will be fixed. Freeze it and diff it against later builds
   while you still can. Your own bug's fix is in there.
9. Offsets are per build and must fail loudly. A silent wrong offset looks
   exactly like a working primitive until it panics. `offset_db_require` exists
   for this reason.
10. Attribution and disclosure are part of the work. The scene runs on credits,
    the vendor relationship runs on coordinated disclosure. Both are cheap to do
    right and expensive to do wrong.

---

## 5. New-method hypotheses

These are the research directions. Each has a test and a kill criterion, so you
can abandon it cheaply. None of them is a CVE and none is guaranteed.

### H1: field-shift the corruption you already have

Idea. The write lands on a signed pointer. Object layouts put signed pointers
next to ordinary fields. Shift the index, size or offset by 8 to 128 bytes so
the same corruption lands on a length, flags, refcount or data pointer.

Why it can work on 27. No mitigation cares about a corrupted `uint32_t`. You are
not defeating PAC, you are declining to engage it.

Test. Identify the object from the caller offset. Recover its layout from the
kernelcache. Vary the offset in 8-byte steps, one per boot, with the marker
sprayed. Look for "survived with an observable effect" instead of a panic.

Kill. If the write offset is not parameterised (a constant index into a fixed
array), this cannot work. Go to H2 or H3.

### H2: prove value control with a marker matrix

Idea. Spray a unique 64-bit value and check the panic registers for it.

Why it matters. "I control the value that reached the faulting slot" changes
everything downstream. It means H1 is available, and it means the bug is a write
primitive rather than a stale-pointer dereference.

Test. Three markers, three runs, one variable each. `panicdump --marker`.

Kill. The marker never appears after six well-formed runs with different spray
shapes. Then the corruption is indirect and you have a lifetime bug, not a write.

### H3: convert a constant write into a use-after-free

Idea. If the value is fixed (zero, one, a constant), aim it at a refcount or a
pointer that a later free path consults, forcing a premature free of an object
you can reclaim.

Why it can work. iOS has a long history of one bad write leading to a UAF and a
controlled reclaim. kalloc_type constrains which object, not whether the pattern
works.

Test. Map the object graph around the write target, find a free path whose
decision depends on a field you can hit, instrument with breadcrumbs.

Kill. No reachable free path consults an overwritable field.

### H4: reclaim into an untyped object with a pointer you control

Idea. After H3, reclaim the freed slot with an object that lives in an untyped
or weakly typed zone, contains a pointer and a length you control, and is
reachable from your process through an existing syscall.

Why it can work. The pipe and socket buffer pattern is the classic: corrupt the
buffer pointer, then read or write the fd for arbitrary kernel r/w. No page
tables involved.

Test. Enumerate candidate zones from a debug kernel (`zprint`-style), verify
which allocations use plain `kalloc` rather than `kalloc_type`.

Kill. Every reachable candidate is typed and size-segregated.

### H5: turn a sandbox escape into attack surface

Idea. A `bad_query`-class extension-issuance flaw gets you into daemon
containers. Daemons expose MIG and IOKit surfaces that an app or WebContent
sandbox never reaches.

Why it can work. Reachability is the scarcest resource in kernel research.
Moving from an app sandbox to a daemon context can multiply the candidate bugs.

Test. Enumerate the XPC and MIG methods of one privileged daemon reachable from
the new context, then fuzz the structured ones with a state machine.

Kill. No logic gap in your build, or the daemon's surface is entirely type
checked and small.

### H6: structured IOKit fuzzing, seeded by diffs

Idea. Use ABrake27-style diffs to find functions Apple recently touched, then
fuzz the external methods of the kext that owns them. Recent fixes cluster
around real bugs and show which parsers are weak.

Why it can work. IOKit external methods are the most consistently productive
kernel surface on iOS, and structured input reaches deeper than random bytes.

Test. Enumerate `IOExternalMethodDispatch` tables in the kext, then build a
harness that walks each selector with valid-ish structs and mutated scalars.

Kill. No reachable user client from your posture. The SPTM research repo's AGX
result is exactly this outcome, so respect it early.

### H7: SPTM-adjacent surfaces (low probability, do not bet on it)

Idea. SPTM and TXM have mailboxes, clients and policy paths. A bug there is
worth more than any AP-kernel bug.

Why it is probably not for you. Apple describes SPTM as a smaller attack surface
that does not rely on trusting the kernel. The one public reachability analysis
concludes that the AGX user client cannot reach UAT mutation, and the 27.2b3 fix
is a lock protocol across three functions rather than a missing check.

Test. Read the SPTM research repo's method (barrier census, string clusters,
device-tree properties) and reproduce it for your build. Do it as study, with no
expectation of a bug.

Kill. Any hint that reaching it requires another coprocessor compromise.

### H8: use the bug for something other than a jailbreak

Idea. A data-only kernel read is enough to answer real questions: verify
mitigation state, read trust-cache and code-signing data, inspect another
process's credentials, prove or disprove a security claim.

Why it matters. It gives the project a publishable result that does not depend
on an SPTM miracle, and it is the kind of finding a bounty programme rewards.

Test. Pick one question with a falsifiable answer and a non-destructive read
path. Measure, then write it up.

Kill. Not applicable. This one is always available.

### What not to spend time on

- Computing or brute-forcing a PAC. Keys are secret, the space is not
  searchable, and there is no published cryptanalysis.
- Porting Titan, DarkSword or CryptSn0w offsets. Different chip, different
  generation, or a dead service.
- Expecting a data bug to yield unsigned code execution. Executable mappings are
  TXM and SPTM policy, which is a separate project.
- WebContent to kernel chains on 27. The sandbox and the mitigations make the
  distance larger than it was on 26.
- Believing "missing stackshot" means you have no data. A real 27.0.1 log can
  report an exclaves buffer missing and a successful primary stackshot in the
  same artifact. See `PANIC-TRIAGE.md`.

---

## 6. Research library

Primary sources first. Everything else is commentary on these.

### Apple

| Resource | Why |
|---|---|
| Apple Platform Security, "Operating system integrity" | The authoritative statement of SPTM/TXM versus PPL, PAC keys and diversifiers, and KIP. Read the SoC generation you actually have. |
| Apple Security Research, "Memory Integrity Enforcement" (Sept 2025) | Explains kalloc_type's history, EMTE's scope (A19 and M5), and why typed allocation plus SPTM is designed to survive kernel compromise. Tells you which ideas are already dead. |
| Apple Security Research Device Program and Security Bounty | The sanctioned way to get a debug kernel with symbols. If the goal is learning, an SRD is worth more than any leaked offset table. |
| Apple support pages for each release | The CVE list is a patch-diff index: which component, which build, which class. |

### PAC, PPL and SPTM mechanics

| Resource | Why |
|---|---|
| Project Zero, "Examining Pointer Authentication on the iPhone XS" (2019) | Still the clearest explanation of what PAC signs, how keys and diversifiers work, and why forgery is not the attack. |
| `pinauten/Fugu15` (Linus Henze) | Canonical four-stage design: oobPCI (kRW), badRecovery (PAC), tlbFail (PPL), CoreTrust. Study how badRecovery bypasses PAC: a legitimate return path, not a forged MAC. |
| `alfiecg24/Titan` and alfiecg.uk write-ups | A real SPTM bypass, and three separate Apple fixes that killed it. The best available teacher for what an SPTM bypass costs. |
| `staturnzz/momentarius` | What an unpatchable PPL design flaw looks like, and why it still does not apply to SPTM phones. |
| `IvanIVGrozny/iOS27.0.1-SPTM-Research` | Current SPTM patch-diff methodology on 27.x: corpus discipline, barrier census, string clusters, reachability negative results. Read the tooling appendix. |
| varik.dev, "xnusp" series | Building a kernel-introspection CLI against a stripped kernelcache with tfp0 on a VM, including walking SPTM-protected page tables. What your tooling should grow into. |

### Exploit architecture and primitives

| Resource | Why |
|---|---|
| `opa334/Dopamine` | The architecture this project mirrors, plus the PPLRW performance notes: RPC-bound primitives need batching and caching. Release notes are more current than the README. |
| `opa334/darksword-kexploit` | A modern kernel exploit reimplemented cleanly in Objective-C. Good model for separating trigger, primitive and post-exploitation. |
| `felix-pb/kfd` | Physmap-based kRW on 16.x. Teaches the page-table-free primitive shape, and why it stops working once SPTM owns the tables. |
| `GenericCoding/pois0nSword` and varik.dev's write-up | Renderer r/w to native calls in WebContent: GC disabling, dyld interposing, the three locks 26.1 added. Methodology for the userland stage. |
| `ghh-jb/DarkSword`, `TheRealClarity/ClearSword` | Two takes on the same era's kernel bug. Useful for comparing primitive design and reliability engineering. |
| `forcequitOS/bad_query` | A current, small, readable sandbox-extension logic bug. Model for H5. |
| `MchinaMd57764/AVETemporalPoC-CVE-2026-112705` | A textbook crash-only bug with panic evidence. Model for documentation, and for what "no primitive" honestly looks like. |
| `vvirei333/ABrake27` | Binary-diff methodology and a worked AMFI case. Copy the method, verify the claims. |
| `34306/usbliter8-fun`, `Xplo8E/Liter8` | The boot-chain endpoint: tfp0 patches and device-tree work. Not applicable to SPTM phones, instructive about the destination. |
| `0xjohnnydev/cryptsn0w` | The signing ladder, documented and then closed. Read it to understand why a class of "jailbreak" never needed a kernel bug. |

### Tooling and environment

| Resource | Why |
|---|---|
| `blacktop/ipsw` | Extract, symbolicate and diff kernelcaches and kexts. The backbone of the patch-diff track. |
| `jtool2` | Mach-O and kernelcache inspection, symbol dumps for `symdiff`. |
| `ipsw kernel symbolicate` and `blacktop/symbolicator` | Recovers stripped XNU symbols from a release kernelcache by signature matching. Without this, a symbol dump is mostly kexts and the nearest-symbol answer for core XNU is wrong. |
| Field note on panic slides | https://gist.github.com/jeremedia/5d65033a0de2bb371242fac5add4472b documents the three-slide problem and the coherence method on macOS 26. |
| Jonathan Levin, *OS Internals* volumes I to III | The reference for XNU and IOKit object layout, which is what H1, H3 and H4 need. |
| Corellium, or a vphone-style VM | A debug kernel with symbols and a debugger. Reproduce the bug class there before spending boots on hardware. |
| `libimobiledevice`, `pymobiledevice3` | Pull panic artifacts and sysdiagnoses reliably, and script the collection loop so each boot costs one command. |

---

## 7. How this maps to the code

`docs/ARCHITECTURE.md` describes the modules. The short version: everything in
`src/` above `scrw_stub.c` is finished and tested. The research is the backend
and the hypotheses. `panicdump` and `symdiff` exist so that each boot produces a
decision, not a note.
