# Changelog

All notable changes to apk-autopsy. Format: Keep a Changelog; dates UTC.
This project's versioning: 0.x while the schema-heuristics API is settling.

## [0.1.0] — 2026-10-28

### Added
- **`strings(apk, {filter})`** — dex string-pool mining without decompilation.
  Byte-scanner over `classes*.dex` with MUTF-8-aware run decoding (UTF-8 first,
  latin1 fallback per run — dex pools are MUTF-8; pure-latin1 decoding mangled
  non-ASCII keys on first dogfood).
- **`schemaScan(apk)`** — the flagship: reverse Room/SQLite/DataStore schema
  from APK alone. Returns `createTables[]` (full CREATE TABLE statements),
  `roomEntities[]`, `dataStoreKeys[]` (`.preferences_pb` files + camelCase
  domain-key heuristics), `dbFiles[]`, `domainStrings[]` (iptv/portal/xtream
  vocabulary hits). No root, no device needed — static APK analysis.
- **`decompile(apk, {dir, deobf, keep})`** — jadx wrapper; `--deobf` ON by
  default (that's the point), `--no-res --no-debug-info -j4` fast lane.
- **`smali(apk, {dir})`** — baksmali wrapper.
- **`grep(dir, pattern)`** — line-anchored search over decompiled
  `.java`/`.smali` trees, structured `GrepHit[]` back.
- **`tools()`** — dependency matrix for the polyglot CLIs (jadx, baksmali,
  dexdump, java) with paths; `pacman -S jadx` is the known-good lane (1.5.6-1
  verified on awrawr-pc).
- **CLI** `bin/apk-autopsy`: `tools | strings | schema | decompile | smali |
  grep` — every API surface scriptable.
- Bun-first, zero npm deps: `node:child_process` spawn + structured parsing.
  System package manager owns the JVM side; nothing vendored, nothing
  downloaded at runtime.

### Dogfood evidence (first real run — the reason this exists)
Reversed `com.nuvio.livetv` (54 MB APK, Hisense `wuyishan` TV) in ~40s:
- 14 CREATE TABLEs across `livetv_guide.db` / `livetv_on_demand.db` /
  `livetv_posters.db`: `stage`, `stage_channels`, `stage_info`, `stage_meta`,
  `programs`, `auto` (XMLTV map), `items`, `categories`, `meta` (k/v JSON
  store), `posters`, `poster_fix`, `prefixes`, `ExoPlayerVersions`.
- Xtream credential model found: **`PlaylistSource`** JSON with keys
  `xtreamServer`, `xtreamUsername`, `xtreamPassword`, `url`, `userAgent`,
  `useEmbeddedEpg`, `streamFormat`, `serverTimezone`, `logoSource`,
  `lastUpdatedMs`, `lastError` — org.json serialized (decompiled
  `qa/C4304v.java` model + `p047oa/C3462q2.java` codec).
- **Cross-app migration fact:** `com.nuvio.tv` and `com.nuvio.livetv` share the
  same core (both launch `com.nuvio.tv.MainActivity`); PlaylistSource JSON is
  wire-compatible → portal creds migrate 1:1 between the two apps.

### Fixed
- `schemaScan` crashed on `Buffer.matchAll` — dex bytes are now decoded to
  latin1 strings (byte-preserving) before regex scanning; byte-offset scanning
  in `strings()` kept byte-level with per-run UTF-8 decode.

### Doctrine
- Lives in the ranch as a **metá peer** (standalone repo, registered in
  `.meta-themes.yaml` + regenerated `.meta.yaml`) — never a git submodule
  (estate-repo-update doctrine).

## [Unreleased]
- `manifest(apk)` — aapt2 badging parse (permissions, activities, deep links).
- Deep-link crawler: enumerate exported VIEW handlers + custom schemes
  (found `nuvio://`, `playtorrio://`, `stremio://` in the wild this session).
- APK diff mode: `autopsy diff old.apk new.apk` → schema/string deltas.
- Optional sourcemap-ish rename map export from `--deobf` runs.
