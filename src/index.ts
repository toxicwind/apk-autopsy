// apk-autopsy — Bun-first polyglot dex/APK autopsy toolkit.
// Java/native CLIs (jadx, baksmali, dexdump) do the bytecode work; Bun
// orchestrates, parses, and returns structured results. Zero npm deps.

import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm, mkdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export interface AutopsyOptions {
  /** scratch root for jadx/baksmali output (default: mkdtemp under /tmp) */
  workDir?: string;
  /** jadx parallel jobs (default 4) */
  jobs?: number;
}

export interface StringHit {
  dex: string;
  value: string;
  offset: number;
}

export interface SchemaScan {
  createTables: string[];
  roomEntities: string[];
  dataStoreKeys: string[];
  dbFiles: string[];
  /** raw string-pool hits matching iptv/portal/xtream/playlist/channel vocabulary */
  domainStrings: string[];
}

export interface GrepHit {
  file: string;
  line: number;
  text: string;
}

const TOOLS = ["jadx", "baksmali", "dexdump", "java"] as const;
export type Tool = (typeof TOOLS)[number];

async function which(bin: string): Promise<string | null> {
  const out = await sh(["which", bin]).catch(() => null);
  const p = out?.trim();
  return p && p.length > 0 ? p : null;
}

function sh(argv: string[], timeoutMs = 300_000): Promise<string> {
  return new Promise((res, rej) => {
    const p = spawn(argv[0], argv.slice(1), { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    const t = setTimeout(() => { p.kill("SIGKILL"); rej(new Error(`timeout: ${argv.join(" ")}`)); }, timeoutMs);
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", (e) => { clearTimeout(t); rej(e); });
    p.on("close", (code) => {
      clearTimeout(t);
      if (code === 0) res(out);
      else rej(new Error(`${argv[0]} rc=${code}: ${err.slice(-400)}`));
    });
  });
}

export function createAutopsy(opts: AutopsyOptions = {}) {
  const jobs = opts.jobs ?? 4;
  let workDirPromise: Promise<string> | null = null;
  const ensureWorkDir = () => {
    workDirPromise ??= (async () =>
      opts.workDir ? (mkdir(opts.workDir, { recursive: true }), resolve(opts.workDir)) : mkdtemp(join(tmpdir(), "apk-autopsy-")))();
    return workDirPromise;
  };

  return {
    /** dependency matrix: which polyglot CLIs are live */
    async tools(): Promise<Record<Tool, string | null>> {
      const found = await Promise.all(TOOLS.map(which));
      return Object.fromEntries(TOOLS.map((t, i) => [t, found[i]]));
    },

    /** mine the dex string pools without decompiling — fast schema/key discovery */
    async strings(apk: string, filter?: RegExp): Promise<StringHit[]> {
      const hits: StringHit[] = [];
      const wd = await ensureWorkDir();
      await sh(["unzip", "-o", "-q", apk, "classes*.dex", "-d", wd]).catch(() => { /* single-dex apks may use other names */ });
      const dexes = (await readdir(wd)).filter((f) => f.endsWith(".dex"));
      if (dexes.length === 0) throw new Error(`no .dex extracted from ${apk} to ${wd}`);
      for (const dex of dexes) {
        const data = await readFile(join(wd, dex));
        for (let i = 0; i < data.length - 4; i++) {
          // scan for printable ascii runs ≥4 (string pool payloads live here in MUTF-8)
          if (data[i] >= 0x20 && data[i] < 0x7f) {
            let j = i;
            while (j < data.length && data[j] >= 0x20 && data[j] < 0x7f) j++;
            if (j - i >= 4) {
              // dex string pools are MUTF-8: decode UTF-8 first (architect hint),
              // latin1 fallback keeps byte-runs visible when pool bytes are split.
              const buf = data.subarray(i, j);
              const value = buf.length === Buffer.byteLength(buf.toString("utf8"))
                ? buf.toString("utf8")
                : buf.toString("latin1");
              if (!filter || filter.test(value)) hits.push({ dex, value, offset: i });
            }
            i = j;
          }
        }
      }
      return hits;
    },

    /** schema reverse: Room entities, CREATE TABLE, DataStore keys, .db filenames */
    async schemaScan(apk: string): Promise<SchemaScan> {
      const wd = await ensureWorkDir();
      await sh(["unzip", "-o", "-q", apk, "classes*.dex", "-d", wd]);
      const dexes = (await readdir(wd)).filter((f) => f.endsWith(".dex"));
      const createTables = new Set<string>();
      const roomEntities = new Set<string>();
      const dataStoreKeys = new Set<string>();
      const dbFiles = new Set<string>();
      for (const dex of dexes) {
        const data = await readFile(join(wd, dex));
        const text = data.toString("latin1");
        for (const m of text.matchAll(/CREATE TABLE[^;\x00]{10,4000}/g)) createTables.add(m[0].replace(/\s+/g, " ").trim());
        for (const m of text.matchAll(/table(Byte)?Channel|tablePlaylistFromState|table\w+/g)) roomEntities.add(m[0]);
        for (const m of text.matchAll(/[\w-]{2,60}\.(?:db|sqlite3?)(?=\x00)/g)) dbFiles.add(m[0]);
        for (const m of text.matchAll(/[\w-]{2,60}\.preferences_pb/g)) dataStoreKeys.add(m[0]);
        // camelCase DataStore keys — heuristics on domain vocab, caller refines via strings()
        for (const m of text.matchAll(/(?:xtream|portal|iptv|playlist|guide|channel|epg)[A-Z]\w{2,40}/g)) dataStoreKeys.add(m[0]);
      }
      const domainStrings = [];
      for (const dex of dexes) {
        const data = await readFile(join(wd, dex));
        for (const m of data.toString("latin1").matchAll(/(?:xtream|portal|iptv|portals|m3u|epg|guide)[\w/{}.?=&:-]{0,80}/gi)) {
          domainStrings.push(m[0]);
        }
      }
      return {
        createTables: [...createTables],
        roomEntities: [...roomEntities].sort(),
        dataStoreKeys: [...dataStoreKeys].sort(),
        dbFiles: [...dbFiles],
        domainStrings: [...new Set(domainStrings)],
      };
    },

    /** full jadx decompile. deobfuscation ON by default (that's the point). */
    async decompile(apk: string, o: { dir?: string; deobf?: boolean; keep?: boolean } = {}): Promise<string> {
      const dir = resolve(o.dir ?? join(await ensureWorkDir(), "jadx-out"));
      const args = ["--no-res", "--no-debug-info", "-j", String(jobs)];
      if (o.deobf !== false) args.push("--deobf");
      args.push("-d", dir, apk);
      await sh(["jadx", ...args], 600_000);
      return dir;
    },

    /** smali disassembly via baksmali */
    async smali(apk: string, o: { dir?: string } = {}): Promise<string> {
      const dir = resolve(o.dir ?? join(await ensureWorkDir(), "smali-out"));
      await sh(["baksmali", "d", apk, "-o", dir], 600_000);
      return dir;
    },

    /** grep decompiled/extracted sources; returns line-anchored hits */
    async grep(dir: string, pattern: RegExp): Promise<GrepHit[]> {
      const hits: GrepHit[] = [];
      const walk = async (d: string): Promise<string[]> => {
        const entries = await readdir(d, { withFileTypes: true });
        const files = await Promise.all(entries.map((e) => {
          const p = join(d, e.name);
          return e.isDirectory() ? walk(p) : (p.endsWith(".java") || p.endsWith(".smali") ? [p] : []);
        }));
        return files.flat();
      };
      for (const f of await walk(resolve(dir))) {
        const src = await readFile(f, "utf8");
        const lines = src.split("\n");
        for (let i = 0; i < lines.length; i++) {
          if (pattern.test(lines[i])) hits.push({ file: f.replace(resolve(dir) + "/", ""), line: i + 1, text: lines[i].trim().slice(0, 300) });
        }
      }
      return hits;
    },

    /** scratch cleanup (skip with keep:true flows) */
    async cleanup(): Promise<void> {
      const wd = workDirPromise ? await workDirPromise : null;
      if (wd && wd.startsWith(tmpdir())) await rm(wd, { recursive: true, force: true });
    },
  };
}

export type Autopsy = ReturnType<typeof createAutopsy>;
export default createAutopsy;
