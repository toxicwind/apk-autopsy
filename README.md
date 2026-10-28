# apk-autopsy 🧫

> Bun-first polyglot toolkit for **dex / APK autopsy**: string mining, schema
> reverse-engineering (Room / DataStore / SQLite), decompilation (jadx), and
> smali disassembly — with **Bun as the main driver** and the battle-tested
> JVM/native CLIs (`jadx`, `baksmali`, `dexdump`, `java`) as managed system deps.
>
> Part of [**the ranch**](https://github.com/toxicwind/ranch) via `android-fleet`
> lineage. Built 2026-10-28 during the Hisense TV IPTV schema reverse
> (`playtorrio` / `nuvio.livetv` Xtream portal extraction).

## Why

Reverse-engineering Android apps on this estate kept getting redone ad-hoc:
grep-the-dex-with-regex in throwaway cells, jadx runs with forgotten flags,
schema strings lost between sessions. This lib is the **one home** for it:

- **Bun API + CLI** — structured outputs, not screen-scraping.
- **Polyglot, honestly**: Java/ART bytecode tools stay native (`jadx`,
  `baksmali`, `dexdump`); Bun orchestrates, parses, caches.
- **Zero npm deps** — spawns system CLIs, parses their output.

## Deps (polyglot, auto-detected)

| Tool | Source | Required for |
|---|---|---|
| `jadx` ≥1.5 | `pacman -S jadx` (1.5.6-1 verified on awrawr-pc) | `decompile()`, `schemaScan()` |
| `baksmali` | android-tools / smali jar | `smali()` |
| `dexdump` | android-tools | `dump()` (quick header/field view) |
| `bun` | it's bun. | everything |

`autopsy.tools()` reports what's missing. Nothing downloads at runtime; the
host package manager owns the JVM side (no vendored 40MB jars in git).

## Use — API

```ts
import { autopsy } from "@android-fleet/apk-autopsy";

const a = autopsy({ workDir: "/tmp/apk-autopsy" });

// structured string mining (dex string pool, no decompile needed)
const strings = await a.strings("/tmp/app.apk", { filter: /xtream/i });
// → [{ dex: "classes4.dex", value: "xtreamServer", offset: 0x1a2b3 }]

// schema reverse: CREATE TABLE + Room entities + DataStore keys + db filenames
const schema = await a.schemaScan("/tmp/app.apk");
// → { createTables: [...], roomEntities: [...], dataStoreKeys: [...], dbFiles: [...] }

// full decompile (jadx, --deobf on by default)
const out = await a.decompile("/tmp/app.apk", { dir: "/tmp/app-src" });

// class-path search over decompiled sources
const hits = await a.grep(out, /xtream\w*(Server|User|Pass)/i);
// → [{ file: "sources/p066tb/C5116v8.java", line: 42, text: "..." }]
```

## Use — CLI

```bash
bun bin/apk-autopsy tools                     # dep matrix
bun bin/apk-autopsy strings app.apk -f xtream
bun bin/apk-autopsy schema app.apk            # schema reverse (the flagship)
bun bin/apk-autopsy decompile app.apk -o /tmp/src [--no-deobf]
bun bin/apk-autopsy grep /tmp/src 'CREATE TABLE'
```

## Provenance

- Distilled 2026-10-28 reversing `com.playtorrio.tv` (72 MB APK) and
  `com.nuvio.livetv` (54 MB) on the Hisense `wuyishan` TV:
  found `iptv_portals` DataStore route template + `xtreamServer/Username/Password`
  keys + `livetv_guide.db` / `livetv_on_demand.db` / `livetv_posters.db` + Room
  entities `tableChannel`/`tableByteChannel`/`tablePlaylistFromState` before
  this lib existed — that ad-hoc session is what it replaces.
- jadx 1.5.6 verified; `--deobf` + `-j4` flags are the fast lane
  (full nuvio classes4.dex ≈ 40s on awrawr-pc).

## Estate conventions

- Standalone **metá peer** repo (never `git submodule add` — see
  `estate-repo-update` skill). Registered in `ranch/.meta-themes.yaml`.
- Bun-forward; system CLIs via `spawn`; `Result`-style errors, fail loud.
