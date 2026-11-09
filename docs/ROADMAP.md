# Roadmap

Ordered so that every phase produces something useful even if the next one
fails. Effort is honest: phases 0 to 4 are weeks, phase 5 is months, and phases
6 and up may never finish. That is normal for this kind of work, which is why
each phase has its own exit criterion.

Replace `<build>` with the build your bug lives on, and `<product>` with your
device identifier. Nothing else in this document depends on a specific model.

---

## Phase 0: lab safety (half a day)

Goal: make losing the device survivable.

- [ ] Confirm a second device or a known-good restore path exists.
- [ ] Record the exact IPSW and build (`<build>`) and check whether Apple still
      signs it today. If not, stop treating the phone as recoverable.
- [ ] Disable auto-updates. Remove the SIM if you care about baseband state.
- [ ] Do a full backup and a test restore before you need it.
- [ ] Put the device in Developer Mode and confirm you can install and run your
      own binary.
- [ ] Set up artifact collection: `pymobiledevice3` or `libimobiledevice` pulls
      panic logs into a dated folder with one command.

Exit: you have restored this device once, on purpose, successfully.

Abort if: the build is unsigned and you have no second device. Then this is a
read-only research project.

---

## Phase 1: panic triage (1 to 2 days)

Goal: know exactly which artifact says what, and turn the panic into a
fingerprint.

- [ ] Collect the whole incident, not one `.ips`. Panics are split across
      `.ips`, `.panic` and `panic-full` siblings, and a note in one section can
      contradict the summary in another.
- [ ] Run `panicdump` on each artifact:
      `build/panicdump --symbols <syms> <artifact>`.
- [ ] Reconcile contradictions. A real 27.0.1 log can say
      `** Stackshot Succeeded ** Bytes Traced 506986` and also
      `Exclaves panic stackshot not found` in `otherString`. The primary trace
      exists; the secondary collector failed.
- [ ] Extract the caller offset: `caller - kernel_text_base`. Record it. A
      stable offset across runs means a stable site.
- [ ] Record all three slides, not just the text base. `KernelCache`,
      `Kernel` and `Kernel text exec` do not move together, and the last two
      are computed from the kernelcache header, not from the segment they name.
- [ ] Decode the compressed stackshot (`ipsw`, `kpdecode`) instead of reading
      `panicString` only.
- [ ] Build a symbol list for `<build>` and symbolicate `pc`, `lr` and `caller`.

Exit: one line in `research/artifacts.md`:
`<build> | caller +0xNNNNNN | pc +0xNNNNNN | EC/FSC | marker present?`

Abort if: the offset moves on every run with identical inputs. That is a race,
and Phase 2 changes shape: you need many samples, not a bisect.

---

## Phase 1.5: diff your own bug out of Apple (2 to 4 days, highest value)

Goal: read the fix to your own bug. This is the most efficient step in the plan.

A beta seed almost certainly has a fix in a later build.

- [ ] Download kernelcaches for later builds, for a comparable SoC. You cannot
      run them, you only need the binaries.
- [ ] Confirm the component is actually different before diffing. The SPTM
      research repo found 27.0.1 and 27.2b1 shipped a byte-identical SPTM, so
      checking first prevents attributing two releases of change to one.
- [ ] Dump symbols, then map the caller onto both lists:
      `build/panicdiff <artifact>.ips old.syms new.syms`. It tries every slide
      in the log, prints each candidate, and says whether the caller's function
      moved with the kernel, moved differently, or disappeared.
- [ ] `build/symdiff old.syms new.syms --limit 100`.
- [ ] Take the candidates and disassemble around your caller offset. Look for a
      new bounds check, a new refcount, a changed lock order, or a lifetime fix.
- [ ] Write the root cause in one paragraph in `research/patched/`.

Exit: you can name the check that was missing, and the function it was added to.

Why this comes before exploitation: the root cause tells you whether value and
offset control are plausible. It also tells you whether the bug is a missing
bounds check (good, parameterised) or a design assumption (bad, H1 is dead).

---

## Phase 2: reproducibility and bisect (3 to 7 days)

Goal: a trigger that panics reliably enough to compare runs.

- [ ] Port your trigger into `avet_trigger()` in `src/device/`.
- [ ] Verify the breadcrumb log is durable: `poc_pac_probe --self-check`, then
      reboot and check the file. If it is not durable, fix that first.
- [ ] Print the matrix with `--plan` and run one line per boot.
- [ ] After each run, pull the artifact and append to `research/runs.md`:
      params, caller offset, marker present, fault class.
- [ ] Stop when the caller offset is stable over three runs with the same
      parameters, and the panic rate is at least 80 percent.

Exit: a table where one parameter change produces one predictable change in the
panic.

Abort if: the panic rate stays below about 20 percent and the offset is
unstable. Then you have a race. Switch to sampling (100 or more runs,
distribution of offsets) before attempting any primitive work.

---

## Phase 3: crash to primitive classification (1 to 3 weeks)

Goal: decide which of the three controls you have.

| Control | How you prove it | What it unlocks |
|---|---|---|
| Value | spray a unique marker, find it in registers or `far` | H1 (field shift), H3 |
| Offset | vary index or size in 8-byte steps, watch `far` move predictably | aiming at a chosen field |
| Lifetime | corrupted data survives past free, behaviour changes with timing | H3 and H4 (UAF reclaim) |

- [ ] Run the marker matrix: 3 markers and 2 spray shapes, one per boot.
      `panicdump --marker 0x... --marker-mask 0x...`.
- [ ] If the marker appears, you have value control. Go to H1.
- [ ] If `far` moves by the step size you changed, you have offset control. Map
      the object layout and aim at a non-signed field.
- [ ] If neither, the corruption is indirect. Pivot to lifetime analysis: look
      for a free path that consults the corrupted field.

Exit: a written classification with evidence from at least three runs.

Decision gate: no value and no offset control after three weeks means stop
trying to weaponise this bug. Keep it as a DoS and a bug report, and move effort
to H5 or H6 (a new surface) or H8 (a read-only result).

---

## Phase 4: PAC strategy (3 to 5 days, parallel with Phase 3)

Goal: stop guessing about PAC.

- [ ] Run `pac_lab` on the device. Confirm that the same address with a
      different key or diversifier gives a different pointer, and that stripping
      gives the canonical address.
- [ ] Write down the strategy you are not pursuing: PAC forgery.
- [ ] Read the panic tail as data. `PAC failure from kernel with DA key while
      authing x16 at pc ...` is a data pointer, so H1 applies. An `IA` or `IB`
      failure is control-flow shaped, which is a much longer project.
- [ ] Choose one of the two real strategies:
      - Avoid (default): never corrupt a signed slot. Requires H1.
      - Confuse (hard): find a legitimate path that authenticates for you, such
        as an exception return, a thread-state restore, or a signed gadget. It
        needs a control-flow primitive and a lot of care.

Exit: a one-page note in `research/hypotheses/` naming the strategy and why.

---

## Phase 5: SCRW backend (months)

Goal: stable data-only kernel read/write, validated at every step.

Ladder, do not skip rungs:

1. [ ] `open()` proves the slide by reading `MH_MAGIC_64` at `kernel_text_base`.
2. [ ] Read a known kernel string (a `__TEXT,__cstring` you can verify from the
       kernelcache) and compare bytes.
3. [ ] Read a field whose value you can infer from userland: your process's pid
       in `proc`, your task's pid, a refcount you can perturb.
4. [ ] `scrw_selftest` green on at least 8 checks.
5. [ ] Write a counter you own, read it back, confirm no collateral damage.
6. [ ] Write a pointer-free field in an object you own, read back, survive.
7. [ ] Only now build a read-only structure walker (`proc` list, `task` list).
8. [ ] Add `kvtophys` only if you have a page-table story. On SPTM hardware you
       probably do not. Make it return `SCRW_E_NOTIMPL` and move on.

Exit: 1000 random in-window reads matching a reference dump, 100 writes with
read-back, and 10 consecutive boots without an unexpected panic.

Abort if: every candidate transport needs a page-table write. That means SPTM,
which means you need a bypass you do not have. Fall back to H8.

---

## Phase 6: stability and performance (2 to 4 weeks)

- [ ] Batch transfers (`max_io`) instead of per-byte calls. Measure with a
      counter, not a stopwatch.
- [ ] Cache structure offsets you resolve once (proc to task to vm_map chains).
- [ ] Add a watchdog: if a read returns implausible values twice, disable the
      primitive instead of retrying into a panic.
- [ ] Log a checksum of every read window and compare across boots to detect
      drift.
- [ ] Document the failure modes you observed, with the artifacts.

Exit: a primitive you would let another researcher run, with a written
failure-mode table.

---

## Phase 7: continuous patch-diff track (weekly, forever)

This is not a phase you finish. It is the habit that keeps the project alive.

Weekly loop:

1. New Apple build? Extract the kernelcache and the SPTM and kext components.
2. Check for byte-identical components first.
3. `symdiff` the symbol dumps, and run a barrier census on SPTM (`dmb ish`
   count).
4. For each candidate, write one paragraph of root cause and one hypothesis
   entry.
5. Update `research/patched/` with component, build pair, symptom, fix shape
   (check, lock, lifetime, policy) and whether a class survives.
6. Re-read your own bug's fix every time a build lands. If Apple changes the
   fix, you learn what they consider fragile.

Exit: none. Cadence is the deliverable.

---

## Phase 8: post-exploitation, narrowly (out of scope here)

Only after Phase 5:

- read-only: credentials, code-signing state, trust caches, entitlement checks
- data-only writes: flags that gate data, never executable mappings
- explicitly out: unsigned code execution, kernel text patches, page-table
  edits. Those need TXM and SPTM cooperation.

---

## Phase 9: write-up and disclosure (1 to 2 weeks)

- [ ] Write the bug up with the panic artifacts, the root cause from Phase 1.5,
      and the primitive classification.
- [ ] Report to Apple with a clear reproduction. A DoS with a root cause is a
      legitimate report.
- [ ] Coordinate before publishing. Do not publish a working chain for a current
      build.
- [ ] Credit every project whose method you used.

---

## Decision gates, in one table

| After | Question | If no |
|---|---|---|
| Phase 0 | can I restore this device? | read-only research only |
| Phase 1 | is the caller offset stable? | treat it as a race and sample, do not bisect |
| Phase 1.5 | can I find the fix upstream? | reverse the function locally instead |
| Phase 2 | is the trigger at least 80 percent reliable? | sample the distribution first |
| Phase 3 | do I control value or offset? | keep it as a DoS, move to H5, H6 or H8 |
| Phase 4 | is the corruption data-shaped? | it is a control-flow project, not this one |
| Phase 5 | does the transport avoid page tables? | no SPTM bypass, so stop at H8 |
