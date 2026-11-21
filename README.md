# MT1939 UHD Reverse-Engineering Project

> ## ⚠️ WARNING — READ THIS FIRST ⚠️
>
> **This project modifies the firmware of an optical disc drive. Writing modified firmware to a drive can PERMANENTLY BRICK IT (turn it into a paperweight). It can also void your warranty and may be illegal in your jurisdiction.**
>
> - **Nothing here is tested on hardware.** The "candidate patched image" this repo can build has **never been flashed to a real drive**. It passes the firmware's internal integrity check (so a drive would *accept* it) — that is **not** the same as "it works" or "it is safe."
> - **These are research notes, not a how-to guide.** There are deliberately **no step-by-step flashing instructions** here.
> - **If you flash anything based on this, you do so entirely at your own risk.** The authors accept **no responsibility** for bricked drives, lost data, voided warranties, or legal consequences. Have a hardware SPI programmer (e.g. CH341A + SOIC-8 clip) and a known-good firmware backup *before* you ever consider writing to a drive.
> - **This is a hobby/learning project with an uncertain outcome.** It may never produce a working UHD-capable drive.
>
> If you don't fully understand the risks, **do not flash anything.** Just read.

---

## What this is

A hobby reverse-engineering project investigating **why an LG WH16NS40 Blu-ray drive built on the MediaTek MT1939 controller refuses to read 4K Ultra HD Blu-ray discs**, and whether a firmware change could fix it. The drive reads regular Blu-rays fine; it rejects UHD discs *before the OS ever sees them*.

The commonly repeated answer online is just "MT1939 can't do UHD, you need an MT1959 drive" — with **no public explanation of the actual mechanism.** This project set out to find the real reason, as a learning exercise. Even a well-documented "here is exactly where and why it stops" is the goal; a working drive is a bonus and is not guaranteed.

## What we've found so far

1. **Root cause (the novel part).** The refusal is a **firmware disc-identification bug, not a hardware limitation.** The drive measures a UHD disc's 3 data layers correctly, provisionally guesses "recordable BDXL" (like any 3-layer disc), and then a **shortcut in the firmware sends every ≥3-layer disc straight to a *recordable*-style disc-info read, skipping the "pressed vs. recordable" test** that normal discs go through. A pressed UHD disc has no recordable wobble-groove addressing, so that read fails → retries → "incompatible medium." Full addresses and the event-by-event trace are in [`FINDINGS.md`](FINDINGS.md).
2. **Firmware integrity = AES-128-CMAC.** Each firmware segment is protected by a 128-bit digest the drive verifies in hardware (and re-checks every boot). It is **AES-128-CMAC** under a **public, fixed integrity key** (identified from the community crate `mediatek-optical`, see Credits, and independently re-verified against our own firmware dump). Because the key is public, patched-segment digests can be regenerated — so a modified image can be made acceptable to the drive.
3. **A candidate patch (designed + assembled, UNTESTED).** A ~64-byte firmware routine that runs the drive's *own* pressed-vs-recordable test on 3-layer discs and reclassifies a pressed one as a 3-layer BD-ROM. It assembles, re-signs, and passes the integrity check. **Whether it actually enables UHD reads is unverified** — that can only be confirmed by flashing, which this project has not done.

## Scope & ethics (important)

This project is strictly about **interoperability / disc identification** — getting a drive the owner owns to *recognise and mount* a disc the owner owns.

**Explicitly out of scope, and not worked on here:** AACS / AACS 2.0, bus encryption, drive authentication/certificates, device or host keys, Volume IDs, decryption, or any "read the protected content without authorisation" path. Disc *decryption* is the business of licensed software (e.g. MakeMKV) under the user's own licence, for discs they own — this project does not touch it. **Do not use this work to circumvent copy protection or to pirate content.**

The repository intentionally **does not include** LG's copyrighted firmware binaries. To reproduce the analysis you must dump the firmware from **your own drive**.

## Repository layout

```
FINDINGS.md               Technical write-up: root cause, integrity scheme, candidate fix, addresses.
mt1939/
  re/                     Static-analysis tooling (Python, runs in Docker; see re/Dockerfile).
    fw.py                 Firmware disassembly/search helpers (Capstone).
    cmac.py               AES-128-CMAC verify + re-sign of the firmware integrity table.
    buildpatch.py         Assembles the candidate patched image (offline; writes to out/).
    segtable.py           Parses the firmware integrity/segment table.
    cmdtables.py, xref.py, digesttest.py, _aescore.py, run
  *.sh                    Drive dump/log helper scripts (require your own drive).
  dumps/   (gitignored)   Your own firmware dump goes here — NOT distributed.
  logs/    (gitignored)   Drive event/DRAM logs — NOT distributed.
  out/     (gitignored)   Build artifacts (reproducible from buildpatch.py).
```

## Reproducing the static analysis (no drive writes)

1. Dump your own drive's 2 MB firmware to `mt1939/dumps/dumpA_0-2M.bin` (read-only; see the notebook for the vendor READ BUFFER method, or use an SPI programmer).
2. Build the analysis container: `docker build -t mt1939-re mt1939/re`.
3. Run tools, e.g. verify the integrity table: `mt1939/re/run re/cmac.py`.

All analysis is **read-only** against a firmware dump. The build/patch tools only ever write to `mt1939/out/` — **they never touch a drive.**

## Credits

- **The AES-128-CMAC firmware-integrity scheme and public key** come from **[`mediatek-optical`](https://github.com/MattJackson/mediatek-optical) by MattJackson** (file `src/envelope/image/cmac.rs`). This project independently re-verified it against its own dump.
- Prior reverse-engineering of the same MT1939 controller: **[`coastermelt`](https://github.com/scanlime/coastermelt)** (scanlime) and **[`optical-disc-drive-re`](https://github.com/cyrozap/optical-disc-drive-re)** (cyrozap).
- The **MakeMKV community** forums for firmware/flashing context (LibreDrive, SDFtool Flasher, the UHD drives guide).

## License

See [`LICENSE`](LICENSE). Firmware binaries are **not** covered and are **not** included — they remain the copyright of their respective owner.
