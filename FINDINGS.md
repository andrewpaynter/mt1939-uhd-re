# MT1939 UHD Findings

A technical account of reverse-engineering why an LG WH16NS40 (MediaTek **MT1939** controller, firmware 1.00) refuses 4K Ultra HD Blu-ray discs — and how far that refusal can be pushed back. This includes a firmware patch that was **built, flashed, and run on real hardware** (fully recoverable), which fixes the drive's disc *classification*, plus a precise identification of the one remaining wall.

The short version: the common wisdom is "MT1939 can't do UHD, nobody knows why." We now know why — in instrumented detail — and we proved on hardware that a big part of it is a *firmware* decision, not a hardware one. The rest, actually reading the disc, did not move even after porting the UHD-specific settings of a UHD-capable MT1959 firmware (§6), which points to the chip itself.

> Addresses below are flash/CPU offsets in the 2 MB firmware image (code runs execute-in-place, so file offset = CPU address). The controller is 32-bit ARM, mostly Thumb. All static analysis is read-only against a dump from the drive; the one hardware write (the firmware flash) is described in §4 and was fully recoverable. **See the [WARNING in the README](README.md) before doing anything with this.**

## 1. Root cause: a firmware disc-identification bug

The drive physically measures a UHD disc's three data layers correctly. The refusal is in how the firmware **classifies** the disc:

- A provisional type is assigned from the measured **layer count** (voting classifier `0x1326E2`): 3 layers → **E8** ("BD-R XL triple layer"), as for *any* 3-layer disc.
- At **`0x68F96`** a **BDXL shortcut** fires: for any disc with `(type & 0xC8) == 0xC8` (≥3 layers) it jumps **straight to the recordable-style disc-ID decoder `0x10A10A`**, **skipping the pressed-vs-recordable test `0x134C9E`** that single/dual-layer discs go through.
- That pressed test computes a reflectivity ratio and reclassifies a disc as **pressed** (BD-ROM: `C0` single, `C4` dual) — but it has **no triple-layer (`C8`) case**, and its caller only lets `F0`/`F4` reach it.
- So a pressed 3-layer BD-ROM (a UHD "BD-100") stays typed **E8** and is read the **recordable** way — seeking disc-info by wobble/ADIP addresses a pressed disc doesn't have. Result: seek failures, retries, and SCSI sense **`02/30/00` "incompatible medium."**

This was confirmed by capturing the drive's own 128 KB internal event-log ring and diffing a working disc against a UHD disc, event by event.

## 2. Firmware integrity = AES-128-CMAC (and how we can re-sign)

Each firmware segment is protected by a 128-bit digest the drive verifies in hardware (register block `0x04063000`) during an update **and re-checks at every boot**. The digests live in a table at image offset **`0x10400`** (16 entries × 28 bytes: `{enabled, start, end, 16-byte digest}`).

The algorithm is **AES-128-CMAC** (RFC 4493, zero IV) under a **public, fixed integrity key** — not a secret, not an AACS key. The per-segment input is `image[start..=end]` with each 16-byte block byte-reversed, and the output digest byte-reversed before storage. This scheme was identified from the community crate [`mediatek-optical`](https://github.com/MattJackson/mediatek-optical) and then **independently re-verified** here — `re/cmac.py` reproduces all four stored digests exactly and can **re-sign** a modified image so the drive accepts it. This is what makes patching the firmware possible at all.

## 3. The classification fix (a small firmware patch)

Because only the shortcut path reaches identification with a 3-layer provisional type, a single hook suffices. `re/buildpatch.py` produces an image that:

- replaces the `bl 0x10A10A` at **`0x68FB2`** with a call to a ~64-byte routine in free space (`0x1A9C00`);
- the routine temporarily sets the type to `F4`, runs the drive's **own** pressed-test (`0x134C9E`), then **remaps the result**: `C4 → C8` (a pressed 3-layer BD-ROM) or `F4 → E8` (a genuine recordable BDXL disc — restored, no regression);
- calls the original decoder and returns.

The decoder, disc-info read, and per-media SCSI command tables already route `C8` like `C4` once the type byte is set, so no further edits are needed for identification. The image is re-signed (§2) and passes all four CMAC records.

## 4. Flashed and validated on real hardware

The patch was **flashed to the drive and run** (via `makemkvcon rawflash main` with the public integrity re-signing; the drive's pre-2020 firmware accepts cleartext images). Key results:

- **The modified firmware was accepted and booted.** The drive came up normally (not in recovery mode), and a read-back confirmed the live flash matched the patched image byte-for-byte with all CMAC records valid.
- **The boot block (`0x0–0xFFFF`) was never written** — the updater programs from offset `0x10000` by default — so the flash was fully recoverable throughout (see §5).
- **The classification fix works.** With a UHD disc (BD-100) inserted, the event log shows the fix execute end-to-end: the shortcut fires → our routine runs the reflectivity pressed-test → it correctly judges the disc **PRESSED** (measured ratio 0.64 < threshold 0.76) → the type is set to **C8** → and the drive takes the **BD-ROM disc-info read path**, exactly like a normal pressed disc.

In other words: stock firmware rejects a UHD disc outright at classification; the patched firmware **correctly identifies it as a pressed 3-layer BD-ROM and attempts to read it.** That half of the problem is firmware, and it's fixed.

## 5. The one remaining wall: reading *pressed* 33 GB/layer data

With classification fixed, the failure moves one layer deeper — to the physical disc-info read. On the UHD disc, the drive seeks to the correct disc-info location and issues the read, but the hardware "read-ready" status (`0x04206080` bit 14) never asserts (read routine `0x10377C` returns error), with tracking position errors at the disc-info zone. A side-by-side with a working 2-layer disc shows them identical up to the read command, then diverging: the working disc returns read-OK and decodes its disc-info; the UHD disc returns read-fail and retries.

The reason is a genuinely novel observation. Consider what the drive *can* read:

| | pressed (pits) | recordable (grooves) |
|---|---|---|
| **25 GB/layer** | ✅ standard BD-ROM | ✅ BD-R/RE |
| **33 GB/layer** | ❌ **UHD BD-ROM** | ✅ BDXL (BD-R/RE XL) |

A 4K UHD disc is the **only** medium that is both **pressed** and **33 GB/layer** — and that combination did not exist when the MT1939 was designed. The drive has 33 GB/layer read capability, but only in its **recordable** read path (which navigates by the wobble groove a pressed disc lacks, so it can't be reused for pressed media). Its **pressed-pit** read path was only ever tuned for 25 GB/layer.

The first hypothesis was a **missing read-channel/servo parameter set** for the pressed-33 GB combination rather than an optical limit: the laser resolves 33 GB/layer marks either way (reading BDXL requires it), so perhaps only the pressed-media equalizer/tracking configuration was never tuned for the denser pits. We tested the most concrete candidate parameter (a focus-mode bit the recordable path sets and the pressed path doesn't); it flashed and ran cleanly but did not change the outcome.

Those parameters live in **undocumented hardware registers** (servo/front-end blocks in the `0x04030000`/`0x040b0000`/`0x040c0000` ranges) with no public datasheet. With MT1939 firmware alone there was no well-motivated change left to try. §6 describes how the UHD-capable MT1959 firmware was then used as a stand-in for that datasheet, and what testing it showed.

## 6. Comparison with MT1959, and porting its UHD handling (v3a–v3g)

**Getting a reference.** LG's own WH16NS60 (MT1959) updaters are still published on LG's support site. Inside each `.exe`, a resource holds a ZIP with every 16-bit word byte-swapped; un-swapping it gives a **plaintext 2 MB MT1959 image** with the same layout and the same AES-CMAC integrity scheme as ours (`re/cmac.py` verifies all four of its records). Part of its code is a compressed overlay, which `re/mtkunpack.py` unpacks. This firmware is used **only for static comparison**; flashing MT1959 firmware onto an MT1939 drive would brick it.

**What the comparison shows.**
- **Same silicon interface.** Of ~1,400 hardware registers each firmware touches, 1,343 are shared. The low-level servo/front-end accessors are instruction-identical, and the disc-info block read is the same routine with the same read-ready check (MT1939 `0x10377C` ≡ MT1959 `0x851A2`). So whatever makes MT1959 succeed is set up *before* that read.
- **Explicit UHD media classes.** MT1959 tests for `(type>>2)==0x32` (C8–CB, pressed 3-layer) and `type==0xC7` (very likely UHD dual-layer, BD-66) at ~54 places. MT1939 has none of these tests.
- **UHD-specific behaviour on the identification path** (each one found, ported to MT1939, flashed and tested):

| Build | What it changed on MT1939 (only for pressed 3-layer discs) | Result on a UHD disc |
|---|---|---|
| v3a | Classify as a standard dual-layer BD-ROM (C4) instead of C8, approximating MT1959's "inner-zone mode", which treats a UHD's lead-in area like standard BD | Still no read |
| v3b | Probe the **data zone** (PSN 0x100000) instead of the disc-info zone, as MT1959 locks there first | **No lock anywhere on the disc**, so the problem isn't specific to the inner zone |
| v3c | MT1959's UHD spindle-speed row | No effect: that speed routine doesn't run during identification |
| v3d | Trace only: log spindle rpm and read clock at each read | MT1939 already spins and clocks a C8 disc exactly as MT1959 does a UHD disc (3100 rpm at the disc-info read, same ×23 clock formula) |
| v3e | Density-compensated rpm for the disc-info read | Change in force; still no read |
| v3f | MT1959's **dedicated pressed-UHD front-end profile** (MT1939 gave pressed 3-layer discs the recordable BD-R XL profile) | Values confirmed in force at every attempt; still no read |
| v3g | The rest: UHD values in the retry/search routine, a measurement setting, the servo-profile selector MT1959 uses for UHD, and its register bit changes | Every hook confirmed firing; still no read |

Every build was flashed the same recoverable way as §4 (boot block never written, live flash read back and verified), and each change was confirmed from the drive's own event log before its result was counted. Normal discs were unaffected throughout: every change is gated on the pressed 3-layer type.

**Also checked, not ported:** MT1959's UHD read-channel coefficient tables. Its UHD rows differ from its normal BD-ROM rows in only a few entries (none at the lowest speed setting), and they appear to be applied only after identification. Still unported: a layer-2 calibration call, a layer-order table and an alternate front-end branch. None of these looks like it would turn "no signal at all" into a successful read.

**Conclusion.** MT1939 now matches MT1959's UHD handling on everything found along the identification path, and it still never gets a readable signal from a pressed 33 GB/layer layer, anywhere on the disc. The most likely remaining explanation is the **silicon**: MT1959's read channel can resolve pressed 33 GB/layer pits and MT1939's can't, even with the same register settings. A missing setting we haven't found can't be ruled out, but there is no longer a concrete lead pointing to one.

**Answer to "why can't MT1939 do UHD":** classification is a firmware bug, and it's fixed here. Reading is blocked below every firmware setting MT1959 changes for UHD, which points to a hardware limit of the older chip.

## 7. Update & recovery (why flashing here was safe to attempt)

- `rawflash main` programs from offset **`0x10000`**, so the boot block (`0x0–0xFFFF`) is never written unless an "include boot block" bit is explicitly set (it isn't). The boot block is what makes recovery possible.
- The boot block independently verifies the main firmware's CMAC segments **at every boot** (routine `0x8E94`). If they fail, it refuses to run the bad firmware, reports "not ready," and stays in a recovery mode that advertises itself as `…WH16NS40 BOOT` and can re-program flash over the cable — all traced in the firmware (the boot block has its own flash-controller code at `0x4AC0`).
- So any bad *main*-firmware flash leaves the drive recoverable over SATA by re-flashing the stock image, as long as the boot block stays intact. A hardware SPI programmer remains the ultimate backstop and is strongly recommended before anyone attempts a write.

## 8. What's proven, and what's open

**Proven on hardware:** the AES-CMAC integrity crack and re-signing; that modified MT1939 firmware can be flashed, booted, and recovered (nine builds flashed over the course of the project); that the UHD *classification* failure is firmware and is fixable; and that porting MT1959's UHD settings for the identification path (front-end profile, speed, clock, servo profile and register changes) does **not** make the disc readable.

**Open:** whether the read wall is purely silicon (most likely, see §6) or a setting not yet found. Answering it definitively would need a datasheet, or a way to watch the read-channel signal directly.

**Scope:** this work is about disc *identification and reading* only. It does nothing with AACS/decryption, and it does not produce a working UHD rip. It is a research result, not a product.

## 9. Method & tooling

Static reverse engineering with Capstone in a container (`re/Dockerfile`); helpers in `mt1939/re/` (`fw.py` disassembly/search, `cmac.py` integrity verify + re-sign, `segtable.py` table parser, `buildpatch.py` the patched images + a small verified Thumb assembler, with one flag per experiment). For the MT1959 comparison: `mtkunpack.py` (overlay unpacker), `xmatch.py` (cross-firmware function matching), `mmio.py` (register census), `typechecks.py`/`uhdsites*.py` (disc-type branch census) and `veneers.py` (MT1959 stub resolution). The drive's internal event log was read read-only via vendor SCSI commands to instrument identification, before and after each experiment; `logparse.py` decodes it and `scratch/newrecs.py` counts key events between two captures. Several test builds added their own log records (event codes `3e01`–`3e07`) so each change could be confirmed as in force.

## 10. Credits & references

- **AES-128-CMAC firmware-integrity scheme + public key:** [`mediatek-optical`](https://github.com/MattJackson/mediatek-optical) by MattJackson (independently re-verified here).
- Prior reverse engineering of the MT1939 platform: [`coastermelt`](https://github.com/scanlime/coastermelt) (Micah Elizabeth Scott) and [`optical-disc-drive-re`](https://github.com/cyrozap/optical-disc-drive-re) (cyrozap).
- The MakeMKV community forums for LibreDrive / firmware-flashing context, and for the description of MediaTek's packed code-overlay format.
