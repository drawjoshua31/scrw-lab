# Safety, law, and disclosure

## Read this first

This project is for education and authorised research on hardware you own. It is
not a jailbreak release, it contains no exploit, and it is not a path to using
anyone else's device.

## Device risk, concretely

| Risk | What it looks like | How to reduce it |
|---|---|---|
| Boot loop | the device restarts into a panic before it can be used | keep a restore plan and test on a spare |
| Data loss | corrupted filesystem, lost photos or keys, broken keychain state | full backup, and assume the device can be wiped |
| Irreversible OS state | no downgrade, and a newer build may not have your bug | freeze updates and record the build |
| SEP or baseband damage | mostly a boot-chain risk rather than a kext-bug risk, but real if you flash anything | do not flash custom firmware on your only device |
| Wasted months | a bug that was never parameterised | use the decision gates in `ROADMAP.md` |

A kernel panic is not a safe crash. The same corruption that traps on a signed
pointer can also corrupt a filesystem buffer, a keychain-related structure, or a
refcount that later frees something in use. Assume every run can destroy data.

## Legal and policy notes

- Jailbreaking a device you own is permitted in some jurisdictions (in the US,
  DMCA exemptions have covered phone jailbreaking) and contested in others.
  Check your local law. This document is not legal advice.
- Anti-circumvention and computer-misuse statutes vary widely. "I own the phone"
  is not a universal defence.
- Boot ROM material is especially sensitive. The `usbliter8` case saw a
  preliminary injunction over published SecureROM material. Do not republish
  such material.
- Do not use any of this against a device you do not own, or to access data you
  are not authorised to access. That is the line between research and offence.
- Vendor programmes (Apple Security Bounty, Security Research Device) are the
  sanctioned route, and they pay. Use them.

## Disclosure

If you find something real:

1. Report to Apple first. A reproducible panic with a root cause is a legitimate
   report even without a primitive.
2. Do not publish a working chain for a current build. Publish the class, the
   method, and the fix analysis after coordination.
3. Publish the negative results too. "This bug cannot be parameterised" and
   "this surface is not reachable from the app sandbox" are genuinely useful,
   and almost nobody writes them down.
4. Credit the lineage. If a technique came from Fugu15, Titan, Dopamine,
   DarkSword, `cryptsn0w`, or a blog post, say so. The scene is small and
   attribution is cheap.

## Scope boundaries for this repository

In scope:

- reading and writing kernel memory on your own device, for research
- analysing panic logs and kernelcaches
- documenting mitigations and patch diffs
- publishing tools that make other researchers' work reproducible

Out of scope, and not to be added:

- persistence, surveillance, or data exfiltration
- bypassing activation, iCloud locks, or other people's passcodes
- anything that targets a device you do not own
- distributing a weaponised chain for a currently signed iOS

## A note on the goal

If the goal is to learn how iOS works, the primitive is optional. The panic
triage, the patch diff, the object layout work and the negative results are the
education. Most people who claim to have "almost a jailbreak" have none of those
written down.
