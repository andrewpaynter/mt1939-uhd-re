# MT1939 UHD Findings

A technical summary of why an LG WH16NS40 (MediaTek **MT1939** controller, firmware 1.00) refuses 4K Ultra HD Blu-ray discs, and what a firmware fix would involve. All analysis is **static** against a 2 MB firmware image dumped from the drive (read-only); **nothing here was flashed or tested on hardware.** See the [WARNING in the README](README.md) before doing anything with this.

> Addresses below are flash/CPU offsets in the 2 MB image (code runs execute-in-place, so file offset = CPU address). The controller is 32-bit ARM, mostly Thumb.

## 1. Root cause: a firmware disc-identification bug, not a hardware limit

The drive physically measures a UHD disc's three data layers correctly. The failure is in how the firmware **classifies** the disc:

- A provisional type is assigned purely from the measured **layer count** (voting classifier `0x1326E2`): 3 layers → **E8** ("BD-R XL triple layer"), as for *any* 3-layer disc.
- At **`0x68F96`** a **BDXL shortcut** fires: for any disc with `(type & 0xC8) == 0xC8` (i.e. ≥3 layers) it jumps **straight to the recordable-style disc-ID decoder `0x10A10A`**, **skipping the pressed-vs-recordable test `0x134C9E`** that single/dual-layer discs go through.
- That pressed test (`0x134C9E`) computes a reflectivity ratio and, below a threshold, reclassifies a disc as **pressed** (BD-ROM: `C0` single, `C4` dual). It has **no triple-layer (`C8`) case** at all, and the caller only lets `F0`/`F4` reach it.
- So a pressed 3-layer BD-ROM (a UHD "BD-100") stays typed **E8** and is read the **recordable** way — seeking disc-info by wobble/ADIP addresses a pressed disc doesn't have. Result: seek failures, ~3,000 retries, and a final SCSI sense **`02/30/00` "incompatible medium."**

**This was confirmed by capturing the drive's own internal event log** (a 128 KB DRAM ring) for a working disc vs. a UHD disc and diffing them event-by-event. The working disc logs the pressed test (`1a76`), takes the ROM read path, and identifies fine; the UHD disc logs the shortcut (`0ddd`), never runs the pressed test, and dies in seek retries.

Nothing in this path points to a missing hardware capability — the optics/servo handle the three high-density layers (the drive writes 100 GB BDXL with the same layer count and density). It is three gaps in the **identification logic**.

## 2. Firmware integrity = AES-128-CMAC (public key)

Each firmware segment is protected by a 128-bit digest, verified by a hardware engine at register block `0x04063000` during a firmware update **and re-checked at every boot** by the boot block. The digests live in a table at image offset **`0x10400`** (16 entries × 28 bytes: `{enabled, start, end, 16-byte digest}`).

The algorithm is **AES-128-CMAC** (RFC 4493, zero IV) under a **public, fixed integrity key** — not a secret, not an AACS key, shared across MT1939/MT1959 firmware. Because the key is public, the digests can be **regenerated**, so a modified image can be made acceptable to the drive.

This scheme was **identified from the community crate [`mediatek-optical`](https://github.com/MattJackson/mediatek-optical) by MattJackson** (`src/envelope/image/cmac.rs`) and then **independently re-verified here** — `re/cmac.py` reproduces all four stored digests of a real dump exactly. The per-segment input is `image[start..=end]` with each 16-byte block byte-reversed, and the output digest is byte-reversed before storage.

Mapping this onto our own dump also matched every structural clue found by disassembly (16-byte blocks, 128-bit running state, a distinct last-block finalize = CMAC's K1 step, an AES-128 core whose key register at engine `+0x40` is written only by unrelated decryption code — hence no key-load in the hash path). An earlier conclusion in the lab notes — that the digest was "probably a silicon-locked custom hash, not recoverable statically" — was **wrong**; it had only tried a *zero* key and per-*word* byte swaps.

## 3. A candidate fix (designed + assembled, UNTESTED)

Because only the shortcut path reaches identification with a 3-layer provisional type, a single hook suffices. `re/buildpatch.py` produces a candidate image that:

- replaces the `bl 0x10A10A` at **`0x68FB2`** with a call to a ~64-byte routine placed in verified free space (`0x1A9C00`);
- the routine temporarily sets the type to `F4`, runs the drive's **own** pressed-test (`0x134C9E`), then **remaps the result**: `C4 → C8` (a pressed 3-layer BD-ROM) or `F4 → E8` (a genuine recordable BDXL disc — restored, so no regression);
- calls the original decoder and returns.

The decoder, disc-info read, and per-media SCSI command tables already route `C8` like `C4` once the type byte is set, so no further edits are needed for the common case. The resulting image is re-signed (`re/cmac.py::resign`) and **passes all four CMAC records** — meaning a drive would *accept and boot* it.

**"Integrity OK" is not "it works."** Whether the patch actually enables UHD reads is **unverified** and can only be confirmed by flashing. Static analysis has cleared the main concern — the reflectivity-measurement routine the patch calls (`0x102B52`) provably populates the buffer the pressed-test reads and already measures 3-layer discs natively — but two assumptions remain checkable only on hardware: whether the dual-layer reflectivity threshold suits a triple-layer disc, and a "long tail" of other code paths that branch on dual-vs-single with no triple case. **This project has not flashed anything.**

## 4. Update & recovery mechanics

- The updater stages a full 2 MB image into DRAM, verifies the CMAC table, then programs flash. It **does not** touch the boot block or the per-unit calibration region by default.
- The boot block carries an independent recovery identity (the drive advertises itself as `…BOOT` when main firmware is bad) and re-verifies the main firmware's CMACs every boot, so a bad *main*-firmware flash appears recoverable over the normal cable — **provided the boot block is left intact** (the candidate patch never touches it).
- Pre-2020 LG firmware accepts **cleartext** update images; an AES-128-ECB transport wrapper ("encrypted" upgrade images) was added in 2020+ firmware. (LG firmware dates are offset by +100 years, so the commonly cited "2120" cutoff is calendar year 2020.)

Even with all of the above, **a hardware SPI programmer as a last-resort recovery path, plus a verified known-good backup, are prerequisites before any write is ever attempted.** This repo does not provide flashing instructions.

## Method & tooling

Static reverse engineering with Capstone in a container (`re/Dockerfile`); helpers in `mt1939/re/` (`fw.py` disassembly/search, `cmac.py` integrity, `segtable.py` table parser, `buildpatch.py` the candidate image). The drive's internal event log was read read-only via vendor SCSI `READ BUFFER` commands to confirm the identification sequence.

## Credits & references

- **AES-128-CMAC integrity scheme + public key:** [`mediatek-optical`](https://github.com/MattJackson/mediatek-optical) by MattJackson (independently re-verified here).
- Prior MT1939 reverse engineering: [`coastermelt`](https://github.com/scanlime/coastermelt) (scanlime), [`optical-disc-drive-re`](https://github.com/cyrozap/optical-disc-drive-re) (cyrozap).
- MakeMKV community forums for LibreDrive / firmware-flashing context.
