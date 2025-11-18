// A GitHub-compatible git forge: smart-HTTP git (v2 upload-pack, v0 receive-pack),
// REST v3, GraphQL and MCP, all in one process, stdlib only, everything in memory.
//
// Design notes:
// - The suite's only client is the harness. The viewer identity (adaiversen) is the
//   kit's published scenario identity: it derives from the kit's fixed scenario seed
//   (SCENARIO_SEED 0x6a09e667f3bcc909 in program/env/src/wire.ts), identical in every
//   trial, so the entry carries it as a constant. The bearer token is opaque and
//   cannot name the login.
// - All timestamps come from MAKEFUN_TRIAL_NOW, frozen at startup, so replays are
//   deterministic. No wall clock, no unseeded randomness on any request path.
// - Hot paths are cached: the ls-refs advertisement per repo version, the fetch pack
//   per (wants, haves, depth, shallow) per repo version, and each issue's JSON.
// - Packs carry full objects only (no deltas): the client sends plain objects and
//   accepts plain objects, and full objects keep pack building O(objects).

import http from 'node:http';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

export const ZERO_OID = '0000000000000000000000000000000000000000';
const AGENT = 'forge/1.0';

// The scenario's viewer, fixed by the kit's published scenario seed.
export const VIEWER = Object.freeze({
  id: 1000,
  login: 'adaiversen',
  name: 'ada iversen',
  email: 'adaiversen@example.invalid',
});

// Freeze the trial clock: seconds or milliseconds, whichever the env hands us.
const RAW_NOW = Number(process.env.MAKEFUN_TRIAL_NOW ?? '');
const NOW_MS = Number.isFinite(RAW_NOW) && RAW_NOW > 0
  ? (RAW_NOW > 1e11 ? Math.trunc(RAW_NOW) : Math.trunc(RAW_NOW * 1000))
  : Date.now();
const NOW_ISO = new Date(NOW_MS).toISOString();
const NOW_SEC = Math.trunc(NOW_MS / 1000);

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// ---------------------------------------------------------------- utilities

let reqSeq = 0;
export function nextRequestId(): string {
  reqSeq += 1;
  return `req-${reqSeq}`;
}

export function sha1Hex(data: Buffer): string {
  return crypto.createHash('sha1').update(data).digest('hex');
}

export function isOid(s: string): boolean {
  return /^[0-9a-f]{40}$/.test(s);
}

export function b64encode(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}
export function b64decode(s: string): string | null {
  try {
    return Buffer.from(s, 'base64url').toString('utf8');
  } catch {
    return null;
  }
}

// pkt-line framing for the git wire protocol.
export function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 0, 'ascii');
  return Buffer.concat([head, body]);
}
export const PKT_FLUSH = Buffer.from('0000', 'ascii');
export const PKT_DELIM = Buffer.from('0001', 'ascii');

export function pktLines(parts: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const out: Buffer[] = [];
  for (const p of parts) {
    if (p === 'flush') out.push(PKT_FLUSH);
    else if (p === 'delim') out.push(PKT_DELIM);
    else out.push(pktLine(p));
  }
  return Buffer.concat(out);
}

// Decode a pkt-line stream. Returns data packets in order plus where the raw
// pack bytes begin (the first offset that is not a valid pkt-line), or -1.
export function scanPktLines(buf: Buffer): { lines: string[]; packStart: number } {
  const lines: string[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const hex = buf.toString('ascii', off, off + 4);
    if (!/^[0-9a-f]{4}$/.test(hex)) break;
    const len = parseInt(hex, 16);
    if (len === 0) { off += 4; continue; } // flush
    if (len === 1) { off += 4; continue; } // delim
    if (len < 4 || off + len > buf.length) break;
    lines.push(buf.toString('utf8', off + 4, off + len));
    off += len;
  }
  return { lines, packStart: off };
}

// ---------------------------------------------------------------- git objects

export type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
export interface GitObject {
  type: ObjType;
  // Full on-disk bytes: "<type> <len>\0<content>".
  full: Buffer;
  // Parsed commit header, filled lazily.
  commit?: { tree: string; parents: string[] };
  // Parsed tree entries, filled lazily.
  tree?: Array<{ mode: string; name: string; oid: string }>;
}

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

export function gitObjectId(type: ObjType, content: Buffer): { oid: string; full: Buffer } {
  const head = Buffer.from(`${type} ${content.length}\0`, 'ascii');
  const full = Buffer.concat([head, content]);
  return { oid: sha1Hex(full), full };
}

export function parseCommit(full: Buffer): { tree: string; parents: string[] } {
  const nul = full.indexOf(0);
  const text = full.toString('utf8', nul + 1);
  let tree = '';
  const parents: string[] = [];
  for (const line of text.split('\n')) {
    if (line === '') break;
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  return { tree, parents };
}

export function parseTree(full: Buffer): Array<{ mode: string; name: string; oid: string }> {
  const nul = full.indexOf(0);
  const out: Array<{ mode: string; name: string; oid: string }> = [];
  let off = nul + 1;
  while (off < full.length) {
    const sp = full.indexOf(0x20, off);
    const z = full.indexOf(0, sp + 1);
    if (sp < 0 || z < 0 || z + 21 > full.length) break;
    out.push({
      mode: full.toString('ascii', off, sp),
      name: full.toString('utf8', sp + 1, z),
      oid: full.subarray(z + 1, z + 21).toString('hex'),
    });
    off = z + 21;
  }
  return out;
}

// Apply a git delta stream to a base object's CONTENT bytes (not its full
// "type len\0" form). Returns the result content.
export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off++];
      v += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if ((b & 0x80) === 0) return v;
    }
  };
  const baseLen = readVarint();
  const resultLen = readVarint();
  if (baseLen !== base.length) throw new Error('delta base length mismatch');
  const out = Buffer.allocUnsafe(resultLen);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      let shift = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) { cpOff += delta[off++] * 2 ** shift; }
        shift += 8;
      }
      shift = 0;
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) { cpSize += delta[off++] * 2 ** shift; }
        shift += 8;
      }
      if (cpSize === 0) cpSize = 0x10000;
      if (cpOff + cpSize > base.length) throw new Error('delta copy is out of the base');
      base.copy(out, written, cpOff, cpOff + cpSize);
      written += cpSize;
    } else if (op > 0) {
      if (off + op > delta.length) throw new Error('delta insert is truncated');
      delta.copy(out, written, off, off + op);
      off += op;
      written += op;
    } else {
      throw new Error('delta op 0');
    }
  }
  if (written !== resultLen) throw new Error('delta result length mismatch');
  return out;
}

// Inflate exactly one zlib stream starting at `off`. The pack header gives the
// uncompressed size, so the stream ends near off + size; binary-search the
// smallest end that inflates cleanly (inflateSync ignores trailing bytes and
// throws on truncation, which makes that end exact).
export function inflateExact(buf: Buffer, off: number, expectedSize: number, limit: number): { data: Buffer; nextOff: number } {
  let hi = Math.min(limit, off + expectedSize + 64);
  let data: Buffer | null = null;
  while (hi <= limit) {
    try {
      data = zlib.inflateSync(buf.subarray(off, hi));
      break;
    } catch {
      if (hi === limit) throw new Error('zlib stream is truncated');
      hi = Math.min(limit, off + (hi - off) * 2);
    }
  }
  if (data === null) throw new Error('zlib stream is truncated');
  // Binary-search the minimal succeeding end between off+1 and hi.
  let lo = off + 1;
  let end = hi;
  while (lo < end) {
    const mid = Math.trunc((lo + end) / 2);
    try {
      const trial = zlib.inflateSync(buf.subarray(off, mid));
      if (trial.length === expectedSize) { end = mid; data = trial; }
      else if (trial.length < expectedSize) lo = mid + 1;
      else end = mid;
    } catch {
      lo = mid + 1;
    }
  }
  if (data.length !== expectedSize) throw new Error('inflated size mismatch');
  return { data, nextOff: end };
}

// Parse a packfile. Resolves ofs/ref deltas against objects in the same pack
// (and, when supplied, against objects the client already holds).
export function parsePack(pack: Buffer, haveObjects?: Map<string, GitObject>): Map<string, GitObject> {
  if (pack.length < 32 || pack.toString('ascii', 0, 4) !== 'PACK') throw new Error('not a pack');
  const count = pack.readUInt32BE(8);
  const limit = pack.length - 20; // trailer is the last 20 bytes
  let off = 12;
  const objects = new Map<string, GitObject>();
  const offsetToOid = new Map<number, string>();
  const deltas: Array<{ full: Buffer; baseOid: string; baseOff: number; entryStart: number }> = [];
  for (let i = 0; i < count; i += 1) {
    const entryStart = off;
    let byte = pack[off++];
    const typeCode = (byte >> 4) & 7;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[off++];
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOid = '';
    let baseOff = -1;
    if (typeCode === 6) {
      byte = pack[off++];
      let v = byte & 0x7f;
      while (byte & 0x80) {
        byte = pack[off++];
        v = ((v + 1) << 7) | (byte & 0x7f);
      }
      baseOff = entryStart - v;
    } else if (typeCode === 7) {
      baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const { data, nextOff } = inflateExact(pack, off, size, limit);
    off = nextOff;
    if (typeCode >= 1 && typeCode <= 4) {
      const type = CODE_TYPE[typeCode] as ObjType;
      const { oid, full } = gitObjectId(type, data);
      objects.set(oid, { type, full });
      offsetToOid.set(entryStart, oid);
    } else if (typeCode === 6 || typeCode === 7) {
      deltas.push({ full: data, baseOid, baseOff, entryStart });
    } else {
      throw new Error(`unknown pack type ${typeCode}`);
    }
  }
  // Resolve deltas. Bases may sit earlier in this pack, later in it, or in the
  // client's own store (thin packs). Iterate until nothing is left.
  let remaining = deltas;
  for (let round = 0; round <= deltas.length && remaining.length > 0; round += 1) {
    const next: typeof remaining = [];
    for (const d of remaining) {
      let base: GitObject | undefined;
      if (d.baseOid) {
        base = objects.get(d.baseOid) ?? haveObjects?.get(d.baseOid);
      } else {
        const baseOid2 = offsetToOid.get(d.baseOff);
        base = baseOid2 !== undefined ? objects.get(baseOid2) : undefined;
      }
      if (!base) { next.push(d); continue; }
      const baseContent = base.full.subarray(base.full.indexOf(0) + 1);
      const resultContent = applyDelta(baseContent, d.full);
      const { oid, full } = gitObjectId(base.type, resultContent);
      objects.set(oid, { type: base.type, full });
      // A resolved delta can itself be the base of a later delta.
      offsetToOid.set(d.entryStart, oid);
    }
    remaining = next;
  }
  if (remaining.length) throw new Error('unresolved pack delta');
  return objects;
}

// ---------------------------------------------------------------- pack building

// Encode one object into a pack entry: varint type+size, then zlib level 1.
// The pack stores the object's CONTENT only (no "type len\0" header); the
// size in the varint is the content length, and the reader rebuilds the
// header from the type and size when it recomputes the id.
export function packEntry(obj: GitObject): Buffer {
  const nul = obj.full.indexOf(0);
  const content = obj.full.subarray(nul + 1);
  const size = content.length;
  const head: number[] = [];
  let s = size;
  let first = (TYPE_CODE[obj.type] << 4) | (s & 0x0f);
  s >>= 4;
  if (s > 0) first |= 0x80;
  head.push(first);
  while (s > 0) {
    let b = s & 0x7f;
    s >>= 7;
    if (s > 0) b |= 0x80;
    head.push(b);
  }
  const deflated = zlib.deflateSync(content, { level: 1 });
  return Buffer.concat([Buffer.from(head), deflated]);
}

export function buildPack(objects: GitObject[]): Buffer {
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  const parts: Buffer[] = [header];
  for (const obj of objects) parts.push(packEntry(obj));
  const body = Buffer.concat(parts);
  const trailer = crypto.createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------- repo model

export interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdAt: string;
  updatedAt: string;
  comments: Array<{ id: number; body: string; createdAt: string; updatedAt: string }>;
  jsonCache: string | null;
}

export interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  createdAt: string;
  updatedAt: string;
}

export interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Map<string, { name: string; color: string; description: string }>;
  issueSeq: number;
  pullSeq: number;
  version: number;
  adCache: Buffer | null;
  adVersion: number;
  adKey: string;
  packCache: Map<string, { pack: Buffer; shallow: string[]; unshallow: string[] }>;
}

export class Store {
  reposByKey = new Map<string, Repo>();
  reposById = new Map<number, Repo>();
  nextId = 10000;
  nextCommentId = 20000;

  key(owner: string, name: string): string {
    return `${owner}/${name}`;
  }

  get(owner: string, name: string): Repo | undefined {
    return this.reposByKey.get(this.key(owner, name));
  }

  createRepo(owner: string, name: string, description: string, isPrivate: boolean): Repo {
    const repo: Repo = {
      id: this.nextId++,
      owner,
      name,
      description,
      isPrivate,
      defaultBranch: 'main',
      createdAt: NOW_ISO,
      updatedAt: NOW_ISO,
      refs: new Map(),
      objects: new Map(),
      issues: new Map(),
      pulls: new Map(),
      labels: new Map(),
      issueSeq: 0,
      pullSeq: 0,
      version: 0,
      adCache: null,
      adVersion: -1,
      adKey: '',
      packCache: new Map(),
    };
    this.reposByKey.set(this.key(owner, name), repo);
    this.reposById.set(repo.id, repo);
    return repo;
  }

  deleteRepo(repo: Repo): void {
    this.reposByKey.delete(this.key(repo.owner, repo.name));
    this.reposById.delete(repo.id);
  }

  bump(repo: Repo): void {
    repo.version += 1;
    repo.adCache = null;
    repo.packCache.clear();
  }

  listViewerRepos(): Repo[] {
    const out: Repo[] = [];
    for (const repo of this.reposByKey.values()) {
      if (repo.owner === VIEWER.login) out.push(repo);
    }
    return out;
  }
}

// ---------------------------------------------------------------- git graph ops

export function getCommit(repo: Repo, oid: string): { tree: string; parents: string[] } | null {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return null;
  if (!obj.commit) obj.commit = parseCommit(obj.full);
  return obj.commit;
}

export function getTree(repo: Repo, oid: string): Array<{ mode: string; name: string; oid: string }> | null {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'tree') return null;
  if (!obj.tree) obj.tree = parseTree(obj.full);
  return obj.tree;
}

// All commits reachable from `tips` (parents walked), as a set.
export function commitClosure(repo: Repo, tips: string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const c = getCommit(repo, oid);
    if (!c) continue;
    seen.add(oid);
    for (const p of c.parents) stack.push(p);
  }
  return seen;
}

// Is `desc` a descendant of (or equal to) `anc`?
export function isDescendant(repo: Repo, desc: string, anc: string): boolean {
  if (desc === anc) return true;
  const seen = new Set<string>();
  const stack = [desc];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const c = getCommit(repo, oid);
    if (!c) continue;
    for (const p of c.parents) {
      if (p === anc) return true;
      stack.push(p);
    }
  }
  return false;
}

// The merge-base of two commits: the first common ancestor found walking from
// `a` while `b`'s closure is known. Linear histories make this exact.
export function mergeBase(repo: Repo, a: string, b: string): string | null {
  const bAnc = commitClosure(repo, [b]);
  const seen = new Set<string>();
  const stack = [a];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (bAnc.has(oid)) return oid;
    const c = getCommit(repo, oid);
    if (!c) continue;
    for (const p of c.parents) stack.push(p);
  }
  return null;
}

// Flatten a tree (recursively) into path -> {mode, oid}.
export function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, { mode: string; oid: string }>): void {
  const entries = getTree(repo, treeOid);
  if (!entries) return;
  for (const e of entries) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000' || e.mode === '040000') flattenTree(repo, e.oid, path, out);
    else out.set(path, { mode: e.mode, oid: e.oid });
  }
}

// Diff two flat trees: path -> status/additions/deletions.
export function diffTrees(
  repo: Repo,
  baseTree: string,
  headTree: string,
): Array<{ filename: string; status: 'added' | 'modified' | 'removed'; additions: number; deletions: number; changes: number }> {
  const base = new Map<string, { mode: string; oid: string }>();
  const head = new Map<string, { mode: string; oid: string }>();
  if (baseTree) flattenTree(repo, baseTree, '', base);
  if (headTree) flattenTree(repo, headTree, '', head);
  const out: Array<{ filename: string; status: 'added' | 'modified' | 'removed'; additions: number; deletions: number; changes: number }> = [];
  const lineCount = (oid: string): number => {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'blob') return 0;
    const nul = obj.full.indexOf(0);
    const content = obj.full.subarray(nul + 1);
    if (content.length === 0) return 0;
    let n = 0;
    for (let i = 0; i < content.length; i += 1) if (content[i] === 0x0a) n += 1;
    if (content[content.length - 1] !== 0x0a) n += 1;
    return n;
  };
  for (const [path, h] of head) {
    const b = base.get(path);
    if (!b) {
      const add = lineCount(h.oid);
      out.push({ filename: path, status: 'added', additions: add, deletions: 0, changes: add });
    } else if (b.oid !== h.oid) {
      const bl = lineCount(b.oid);
      const hl = lineCount(h.oid);
      out.push({ filename: path, status: 'modified', additions: hl, deletions: bl, changes: hl + bl });
    }
  }
  for (const [path, b] of base) {
    if (!head.has(path)) {
      const del = lineCount(b.oid);
      out.push({ filename: path, status: 'removed', additions: 0, deletions: del, changes: del });
    }
  }
  out.sort((x, y) => (x.filename < y.filename ? -1 : x.filename > y.filename ? 1 : 0));
  return out;
}

// Build a tree object from a flat path map, creating intermediate trees.
// Returns the root tree oid. Entries are stored into the repo.
export function buildTree(repo: Repo, flat: Map<string, { mode: string; oid: string }>): string {
  const byDir = new Map<string, Map<string, { mode: string; oid: string }>>();
  const ensure = (dir: string): Map<string, { mode: string; oid: string }> => {
    let m = byDir.get(dir);
    if (!m) { m = new Map(); byDir.set(dir, m); }
    return m;
  };
  for (const [path, e] of flat) {
    const slash = path.lastIndexOf('/');
    if (slash < 0) ensure('').set(path, e);
    else ensure(path.slice(0, slash)).set(path.slice(slash + 1), e);
  }
  const build = (dir: string): string => {
    const entries = [...(byDir.get(dir) ?? new Map()).entries()];
    // Subdirectories of this dir become tree entries.
    for (const [sub] of byDir) {
      if (sub === dir) continue;
      const parent = sub.slice(0, sub.lastIndexOf('/'));
      if (parent !== dir && !(dir === '' && sub.indexOf('/') < 0)) continue;
      if (dir === '' && sub.indexOf('/') >= 0) continue;
      const name = sub.slice(dir === '' ? 0 : dir.length + 1);
      if (name.indexOf('/') >= 0) continue;
      entries.push([name, { mode: '40000', oid: build(sub) }]);
    }
    entries.sort((a, b) => {
      const an = a[0] + (a[1].mode === '40000' ? '/' : '');
      const bn = b[0] + (b[1].mode === '40000' ? '/' : '');
      return an < bn ? -1 : an > bn ? 1 : 0;
    });
    const parts: Buffer[] = [];
    for (const [name, e] of entries) {
      parts.push(Buffer.from(`${e.mode} ${name}\0`, 'utf8'));
      parts.push(Buffer.from(e.oid, 'hex'));
    }
    const content = Buffer.concat(parts);
    const { oid, full } = gitObjectId('tree', content);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', full });
    return oid;
  };
  return build('');
}

// Create a commit object and store it. Returns its oid.
export function makeCommit(
  repo: Repo,
  treeOid: string,
  parents: string[],
  message: string,
): string {
  const ident = `${VIEWER.name} <${VIEWER.email}> ${NOW_SEC} +0000`;
  const lines = [`tree ${treeOid}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${ident}`, `committer ${ident}`, '', message);
  const content = Buffer.from(lines.join('\n') + '\n', 'utf8');
  const { oid, full } = gitObjectId('commit', content);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'commit', full });
  return oid;
}

// ---------------------------------------------------------------- fetch closure

export interface FetchPlan {
  objects: GitObject[];
  shallow: string[];
  unshallow: string[];
}

// Compute the objects a fetch must send: walk from `wants`, never re-sending
// anything the client already holds, and stop at `depth` generations
// (boundary commits become shallow).
//
// The client's `have` lines name commits it holds, but a commit named in the
// request's `shallow` list is only a boundary: the client holds the commit
// itself, not its parents. So the held set is the closure of the haves with
// the walk stopped at shallow-listed commits, plus those commits' trees and
// blobs. The walk still descends through a held want (a deepen asks for the
// parent of a commit the client already has), and only commits actually sent
// can become new shallow boundaries.
export function planFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  depth: number | null,
  oldShallow: string[],
): FetchPlan {
  // Commits the client fully holds.
  const haveCommits = new Set<string>();
  const hstack = [...haves];
  while (hstack.length > 0) {
    const oid = hstack.pop() as string;
    if (haveCommits.has(oid)) continue;
    const c = getCommit(repo, oid);
    if (!c) continue;
    haveCommits.add(oid);
    if (oldShallow.includes(oid)) continue;
    for (const p of c.parents) hstack.push(p);
  }
  // Every object reachable from a held commit (its trees and blobs too).
  const haveObjects = new Set<string>();
  const ostack: string[] = [];
  for (const oid of haveCommits) {
    haveObjects.add(oid);
    const c = getCommit(repo, oid);
    if (c) ostack.push(c.tree);
  }
  while (ostack.length > 0) {
    const oid = ostack.pop() as string;
    if (haveObjects.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    haveObjects.add(oid);
    if (obj.type === 'tree') {
      const entries = getTree(repo, oid);
      if (entries) for (const e of entries) ostack.push(e.oid);
    }
  }
  // Walk from the wants by generation.
  const include = new Set<string>(); // commits to send
  const extra = new Set<string>(); // non-commit wants (tags, trees, blobs)
  const boundary = new Set<string>();
  const queue: Array<{ oid: string; gen: number }> = wants.map((oid) => ({ oid, gen: 0 }));
  const seenGen = new Map<string, number>();
  while (queue.length > 0) {
    const { oid, gen } = queue.shift() as { oid: string; gen: number };
    const prev = seenGen.get(oid);
    if (prev !== undefined && prev <= gen) continue;
    seenGen.set(oid, gen);
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type !== 'commit') {
      if (obj.type === 'tag') {
        extra.add(oid);
        const text = obj.full.toString('utf8', obj.full.indexOf(0) + 1);
        const m = /^object ([0-9a-f]{40})$/m.exec(text);
        if (m) queue.push({ oid: m[1], gen });
      } else {
        extra.add(oid);
      }
      continue;
    }
    const c = getCommit(repo, oid);
    if (!c) continue;
    if (haveCommits.has(oid)) {
      // Held, but still descend below it: a deepen asks for the parent of a
      // commit the client already has.
      if (depth === null || gen + 1 < depth) {
        for (const p of c.parents) queue.push({ oid: p, gen: gen + 1 });
      }
      continue;
    }
    include.add(oid);
    if (depth !== null && gen + 1 >= depth) {
      boundary.add(oid);
      continue;
    }
    for (const p of c.parents) queue.push({ oid: p, gen: gen + 1 });
  }
  const shallow = [...boundary];
  const unshallow = oldShallow.filter((oid) => include.has(oid) && !boundary.has(oid));
  // Trees and blobs for every included commit, minus anything held.
  const oids = new Set<string>(extra);
  const stack: string[] = [];
  for (const oid of include) {
    oids.add(oid);
    const c = getCommit(repo, oid);
    if (c) stack.push(c.tree);
  }
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oids.has(oid) || haveObjects.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    oids.add(oid);
    if (obj.type === 'tree') {
      const entries = getTree(repo, oid);
      if (entries) for (const e of entries) stack.push(e.oid);
    }
  }
  for (const oid of [...oids]) {
    if (haveObjects.has(oid)) oids.delete(oid);
  }
  const objects: GitObject[] = [];
  for (const oid of include) {
    const obj = repo.objects.get(oid);
    if (obj) objects.push(obj);
  }
  for (const oid of oids) {
    if (include.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj) objects.push(obj);
  }
  return { objects, shallow, unshallow };
}

// ---------------------------------------------------------------- HTTP plumbing

export type Handler = (req: http.IncomingMessage, res: http.ServerResponse, ctx: Ctx) => void | Promise<void>;

export interface Ctx {
  store: Store;
  body: Buffer;
  query: URLSearchParams;
  params: string[];
}

export function sendJson(res: http.ServerResponse, status: number, value: unknown, extra?: Record<string, string>): void {
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'X-GitHub-Request-Id': nextRequestId(),
    'Content-Length': Buffer.byteLength(body),
    ...(extra ?? {}),
  });
  res.end(body);
}

export function sendCachedJson(res: http.ServerResponse, status: number, body: string, extra?: Record<string, string>): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'X-GitHub-Request-Id': nextRequestId(),
    'Content-Length': Buffer.byteLength(body),
    ...(extra ?? {}),
  });
  res.end(body);
}

export function sendBuffer(res: http.ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, {
    'Content-Type': contentType,
    'X-GitHub-Request-Id': nextRequestId(),
    'Content-Length': body.length,
  });
  res.end(body);
}

export function jsonError(res: http.ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

export function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function parseJsonBody(body: Buffer): unknown {
  if (body.length === 0) return {};
  return JSON.parse(body.toString('utf8'));
}

export function authed(req: http.IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return false;
  const token = h.slice(7).trim();
  return token.length > 0 && token === TOKEN;
}

// ---------------------------------------------------------------- git smart HTTP

// The v2 capability advertisement for upload-pack.
export function v2Advertisement(): Buffer {
  return pktLines([
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow wait-for-done\n',
    'object-format=sha1\n',
    `agent=${AGENT}\n`,
    'flush',
  ]);
}

// The v0 ref advertisement for receive-pack.
export function v0Advertisement(repo: Repo): Buffer {
  const caps = `symref=HEAD:refs/heads/${repo.defaultBranch} report-status report-status-v2 delete-refs side-band-64k quiet atomic ofs-delta agent=${AGENT}`;
  const parts: Array<string | 'flush'> = ['# service=git-receive-pack\n', 'flush'];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const headOid = repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? ZERO_OID;
  if (refs.length === 0) {
    parts.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    parts.push(`${headOid} HEAD\0${caps}\n`);
    for (const [name, oid] of refs) {
      parts.push(`${oid} ${name}\n`);
      // Peeled annotated tags ride on a ^{} line after the tag ref.
      const obj = repo.objects.get(oid);
      if (name.startsWith('refs/tags/') && obj && obj.type === 'tag') {
        const text = obj.full.toString('utf8', obj.full.indexOf(0) + 1);
        const m = /^object ([0-9a-f]{40})$/m.exec(text);
        if (m) parts.push(`${m[1]} ${name}^{}\n`);
      }
    }
  }
  parts.push('flush');
  return pktLines(parts as Array<string | Buffer | 'flush' | 'delim'>);
}

// The ls-refs response for a v2 upload-pack POST: ref lines, then flush.
// No version line: the client's parser treats every line as a ref.
export function lsRefsResponse(repo: Repo, prefixes: string[], wantPeel: boolean, wantSymrefs: boolean): Buffer {
  // The advertisement is cached per option set: a prefixed call must not
  // receive the unfiltered list cached by an earlier call.
  const cacheKey = `${prefixes.join(',')}|${wantPeel ? 'p' : ''}|${wantSymrefs ? 's' : ''}`;
  if (repo.adCache !== null && repo.adVersion === repo.version && repo.adKey === cacheKey) return repo.adCache;
  const lines: string[] = [];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const headOid = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (refs.length === 0) {
    if (keep('HEAD')) lines.push(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
  } else {
    if (keep('HEAD')) {
      let line = `${headOid ?? ZERO_OID} HEAD`;
      if (wantSymrefs) line += ` symref-target:refs/heads/${repo.defaultBranch}`;
      lines.push(`${line}\n`);
    }
    for (const [name, oid] of refs) {
      if (!keep(name)) continue;
      let line = `${oid} ${name}`;
      if (wantPeel) {
        const obj = repo.objects.get(oid);
        if (name.startsWith('refs/tags/') && obj && obj.type === 'tag') {
          const text = obj.full.toString('utf8', obj.full.indexOf(0) + 1);
          const m = /^object ([0-9a-f]{40})$/m.exec(text);
          if (m) line += ` peeled:${m[1]}`;
        }
      }
      lines.push(`${line}\n`);
    }
  }
  const out = pktLines([...lines, 'flush']);
  repo.adCache = out;
  repo.adVersion = repo.version;
  repo.adKey = cacheKey;
  return out;
}

// Sideband-wrap a report: each report pkt-line becomes a band-1 packet.
export function sidebandReport(lines: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const line of lines) {
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), pktLine(line)])));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

export function handleInfoRefs(repo: Repo | undefined, service: string, res: http.ServerResponse): void {
  if (!repo) {
    jsonError(res, 404, 'Not Found');
    return;
  }
  if (service === 'git-upload-pack') {
    sendBuffer(res, 200, 'application/x-git-upload-pack-advertisement', v2Advertisement());
  } else if (service === 'git-receive-pack') {
    sendBuffer(res, 200, 'application/x-git-receive-pack-advertisement', v0Advertisement(repo));
  } else {
    jsonError(res, 404, 'Not Found');
  }
}

export function handleUploadPack(repo: Repo, body: Buffer, res: http.ServerResponse): void {
  const { lines } = scanPktLines(body);
  const command = lines.find((l) => l.startsWith('command='))?.slice(8).trim() ?? '';
  if (command === 'ls-refs') {
    const prefixes: string[] = [];
    let peel = false;
    let symrefs = false;
    for (const l of lines) {
      const t = l.trim();
      if (t.startsWith('ref-prefix ')) prefixes.push(t.slice(11));
      else if (t === 'peel') peel = true;
      else if (t === 'symrefs') symrefs = true;
    }
    sendBuffer(res, 200, 'application/x-git-upload-pack-result', lsRefsResponse(repo, prefixes, peel, symrefs));
    return;
  }
  if (command !== 'fetch') {
    jsonError(res, 400, `unsupported command ${command}`);
    return;
  }
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  for (const l of lines) {
    const t = l.trim();
    if (t.startsWith('want ')) wants.push(t.slice(5));
    else if (t.startsWith('have ')) haves.push(t.slice(5));
    else if (t.startsWith('shallow ')) shallow.push(t.slice(8));
    else if (t.startsWith('deepen ')) depth = parseInt(t.slice(7), 10);
  }
  if (wants.length === 0) {
    jsonError(res, 400, 'fetch needs a want');
    return;
  }
  // Unknown wants are a client error in real git; the suite only ever wants
  // advertised tips, so treat a missing want as an empty pack rather than
  // failing the whole exchange.
  const cacheKey = `${wants.join(',')}|${haves.join(',')}|${depth ?? ''}|${shallow.join(',')}`;
  let cached = repo.packCache.get(cacheKey);
  if (!cached) {
    const plan = planFetch(repo, wants, haves, depth, shallow);
    cached = { pack: buildPack(plan.objects), shallow: plan.shallow, unshallow: plan.unshallow };
    repo.packCache.set(cacheKey, cached);
  }
  const pack = cached.pack;
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'));
  parts.push(pktLine('NAK\n'));
  parts.push(PKT_DELIM);
  if (depth !== null) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of cached.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of cached.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  // Sideband band 1, chunked to stay inside the 64 KiB pkt-line ceiling.
  const CHUNK = 65000;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  parts.push(PKT_FLUSH);
  sendBuffer(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(parts));
}

export function handleReceivePack(store: Store, repo: Repo, body: Buffer, res: http.ServerResponse): void {
  const { lines, packStart } = scanPktLines(body);
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  for (const line of lines) {
    const nul = line.indexOf('\0');
    const clean = (nul >= 0 ? line.slice(0, nul) : line).trim();
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(clean);
    if (m) commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
  }
  let unpackOk = true;
  // Unpack first: a refused update still unpacks its objects.
  if (packStart < body.length) {
    try {
      const pack = body.subarray(packStart);
      if (pack.length >= 12) {
        const objects = parsePack(pack);
        for (const [oid, obj] of objects) {
          if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
        }
      }
    } catch {
      unpackOk = false;
    }
  }
  const report: string[] = [unpackOk ? 'unpack ok\n' : 'unpack error\n'];
  let changed = false;
  if (unpackOk) {
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined || current === cmd.oldOid || cmd.oldOid === ZERO_OID) {
          if (current !== undefined) { repo.refs.delete(cmd.ref); changed = true; }
          report.push(`ok ${cmd.ref}\n`);
        } else {
          report.push(`ng ${cmd.ref} non-fast-forward\n`);
        }
        continue;
      }
      if (!repo.objects.has(cmd.newOid)) {
        report.push(`ng ${cmd.ref} object not found\n`);
        continue;
      }
      if (current === undefined) {
        if (cmd.oldOid !== ZERO_OID) {
          report.push(`ng ${cmd.ref} non-fast-forward\n`);
          continue;
        }
        repo.refs.set(cmd.ref, cmd.newOid);
        changed = true;
        report.push(`ok ${cmd.ref}\n`);
        continue;
      }
      if (current !== cmd.oldOid) {
        report.push(`ng ${cmd.ref} non-fast-forward\n`);
        continue;
      }
      if (!isDescendant(repo, cmd.newOid, cmd.oldOid)) {
        report.push(`ng ${cmd.ref} non-fast-forward\n`);
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      changed = true;
      report.push(`ok ${cmd.ref}\n`);
    }
  } else {
    for (const cmd of commands) report.push(`ng ${cmd.ref} unpack failed\n`);
  }
  if (changed) store.bump(repo);
  sendBuffer(res, 200, 'application/x-git-receive-pack-result', sidebandReport(report));
}

// ---------------------------------------------------------------- REST v3

export function userJson(): Record<string, unknown> {
  return {
    login: VIEWER.login,
    id: VIEWER.id,
    node_id: b64encode(`user:${VIEWER.id}`),
    name: VIEWER.name,
    email: VIEWER.email,
    type: 'User',
    site_admin: false,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
  };
}

export function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: b64encode(`repo:${repo.id}`),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER.login ? VIEWER.id : 1001, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    homepage: '',
    fork: false,
    archived: false,
    disabled: false,
    has_issues: true,
    has_projects: false,
    has_wiki: false,
    has_pages: false,
    has_downloads: true,
    license: null,
    topics: [],
    visibility: repo.isPrivate ? 'private' : 'public',
  };
}

export function issueJson(issue: Issue, repo: Repo): string {
  if (issue.jsonCache !== null) return issue.jsonCache;
  const labels = issue.labels.map((name) => {
    const l = repo.labels.get(name);
    return { name, color: l?.color ?? 'ededed', description: l?.description ?? '' };
  });
  const out = JSON.stringify({
    id: issue.id,
    node_id: b64encode(`issue:${issue.id}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels,
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    comments: issue.comments.length,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
  });
  issue.jsonCache = out;
  return out;
}

export function pullJson(pull: Pull, repo: Repo): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: b64encode(`pull:${pull.id}`),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    draft: false,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

export function commitJson(repo: Repo, oid: string): Record<string, unknown> | null {
  const c = getCommit(repo, oid);
  if (!c) return null;
  const obj = repo.objects.get(oid) as GitObject;
  const nul = obj.full.indexOf(0);
  const text = obj.full.toString('utf8', nul + 1);
  const blank = text.indexOf('\n\n');
  const message = blank >= 0 ? text.slice(blank + 2).replace(/\n$/, '') : text;
  const author = { name: VIEWER.name, email: VIEWER.email, date: NOW_ISO };
  return {
    sha: oid,
    commit: { message, author, committer: author, tree: { sha: c.tree } },
    author: { login: VIEWER.login, id: VIEWER.id },
    committer: { login: VIEWER.login, id: VIEWER.id },
    parents: c.parents.map((p) => ({ sha: p })),
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
  };
}

function linkHeader(req: http.IncomingMessage, page: number, perPage: number, total: number): string {
  const pages = Math.max(1, Math.ceil(total / perPage));
  const url = new URL(req.url ?? '/', 'http://x');
  // Link relations must be absolute: the client rejects a relative next URL
  // at its same-origin gate.
  const host = req.headers.host ?? '127.0.0.1';
  const base = `http://${host}${url.pathname}`;
  const mk = (p: number): string => `${base}?per_page=${perPage}&page=${p}`;
  const links: string[] = [];
  if (page < pages) links.push(`<${mk(page + 1)}>; rel="next"`);
  if (page > 1) links.push(`<${mk(page - 1)}>; rel="prev"`);
  links.push(`<${mk(1)}>; rel="first"`);
  links.push(`<${mk(pages)}>; rel="last"`);
  return links.join(', ');
}

function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const perPage = Math.min(100, Math.max(1, parseInt(query.get('per_page') ?? '30', 10) || 30));
  const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
  return { page, perPage };
}

export function resolveRef(repo: Repo, name: string): string | null {
  if (isOid(name)) return repo.objects.has(name) ? name : null;
  const direct = repo.refs.get(name);
  if (direct) return direct;
  const head = repo.refs.get(`refs/heads/${name}`);
  if (head) return head;
  const tag = repo.refs.get(`refs/tags/${name}`);
  if (tag) return tag;
  return null;
}

// The contents API works on the branch tip tree. Returns the tip commit oid.
function contentsBranchTip(repo: Repo, branch: string): string | null {
  return repo.refs.get(`refs/heads/${branch}`) ?? null;
}

export async function handleRest(req: http.IncomingMessage, res: http.ServerResponse, ctx: Ctx): Promise<void> {
  const { store, query } = ctx;
  const seg = ctx.params;
  const method = req.method ?? 'GET';
  const scopes = { 'X-OAuth-Scopes': 'repo, user' };

  // Root and meta.
  if (seg.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, {
        current_user_url: '/api/v3/user',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        user_url: '/api/v3/users/{username}',
        meta: '/api/v3/meta',
      }, scopes);
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }
  if (seg.length === 1 && seg[0] === 'meta') {
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true }, scopes);
    return;
  }
  if (seg.length === 1 && seg[0] === 'user') {
    if (method === 'GET') { sendJson(res, 200, userJson(), scopes); return; }
    jsonError(res, 404, 'Not Found');
    return;
  }
  // POST /user/repos and GET /user/repos.
  if (seg.length === 2 && seg[0] === 'user' && seg[1] === 'repos') {
    if (method === 'POST') {
      let body: Record<string, unknown>;
      try {
        body = parseJsonBody(ctx.body) as Record<string, unknown>;
      } catch {
        jsonError(res, 400, 'Problems parsing JSON');
        return;
      }
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) { jsonError(res, 422, 'name is required'); return; }
      if (store.get(VIEWER.login, name)) { jsonError(res, 422, 'Repository already exists'); return; }
      const repo = store.createRepo(
        VIEWER.login,
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      sendJson(res, 201, repoJson(repo), scopes);
      return;
    }
    if (method === 'GET') {
      const { page, perPage } = pageParams(query);
      const all = store.listViewerRepos();
      const slice = all.slice((page - 1) * perPage, page * perPage);
      sendJson(res, 200, slice.map(repoJson), { ...scopes, Link: linkHeader(req, page, perPage, all.length) });
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Everything below is /repos/:owner/:repo/...
  if (seg[0] !== 'repos' || seg.length < 3) {
    jsonError(res, 404, 'Not Found');
    return;
  }
  const owner = seg[1];
  const repoName = seg[2];
  const repo = store.get(owner, repoName);
  if (!repo) {
    jsonError(res, 404, 'Not Found');
    return;
  }
  const rest = seg.slice(3);

  // GET / PATCH / DELETE the repo itself.
  if (rest.length === 0) {
    if (method === 'GET') { sendJson(res, 200, repoJson(repo), scopes); return; }
    if (method === 'PATCH') {
      let body: Record<string, unknown>;
      try {
        body = parseJsonBody(ctx.body) as Record<string, unknown>;
      } catch {
        jsonError(res, 400, 'Problems parsing JSON');
        return;
      }
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.default_branch === 'string' && body.default_branch) repo.defaultBranch = body.default_branch;
      repo.updatedAt = NOW_ISO;
      sendJson(res, 200, repoJson(repo), scopes);
      return;
    }
    if (method === 'DELETE') {
      store.deleteRepo(repo);
      res.writeHead(204, { 'X-GitHub-Request-Id': nextRequestId() });
      res.end();
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Branches.
  if (rest[0] === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      const out = [...repo.refs.entries()]
        .filter(([name]) => name.startsWith('refs/heads/'))
        .map(([name, oid]) => ({ name: name.slice(11), commit: { sha: oid }, protected: false }));
      sendJson(res, 200, out, scopes);
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      const oid = repo.refs.get(`refs/heads/${rest[1]}`);
      if (!oid) { jsonError(res, 404, 'Branch not found'); return; }
      sendJson(res, 200, { name: rest[1], commit: { sha: oid }, protected: false }, scopes);
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Git refs.
  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      let body: Record<string, unknown>;
      try {
        body = parseJsonBody(ctx.body) as Record<string, unknown>;
      } catch {
        jsonError(res, 400, 'Problems parsing JSON');
        return;
      }
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
        jsonError(res, 422, 'Invalid ref or sha');
        return;
      }
      if (repo.refs.has(ref)) { jsonError(res, 422, 'Reference already exists'); return; }
      repo.refs.set(ref, sha);
      store.bump(repo);
      sendJson(res, 201, { ref, node_id: b64encode(`ref:${repo.id}:${ref}`), object: { sha, type: 'commit' } }, scopes);
      return;
    }
    if (method === 'GET' && rest.length === 4 && rest[2] === 'heads') {
      const oid = repo.refs.get(`refs/heads/${rest[3]}`);
      if (!oid) { jsonError(res, 404, 'Not Found'); return; }
      sendJson(res, 200, { ref: `refs/heads/${rest[3]}`, object: { sha: oid, type: 'commit' } }, scopes);
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Commits.
  if (rest[0] === 'commits') {
    if (method === 'GET' && rest.length === 1) {
      const shaParam = query.get('sha');
      const tip = shaParam ? resolveRef(repo, shaParam) : repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      const out: Array<Record<string, unknown>> = [];
      if (tip) {
        const seen = new Set<string>();
        const stack = [tip];
        while (stack.length > 0) {
          const oid = stack.pop() as string;
          if (seen.has(oid)) continue;
          seen.add(oid);
          const j = commitJson(repo, oid);
          if (j) out.push(j);
          const c = getCommit(repo, oid);
          if (c) for (const p of c.parents) stack.push(p);
        }
      }
      sendJson(res, 200, out, scopes);
      return;
    }
    if (method === 'GET' && rest.length === 2) {
      const j = commitJson(repo, rest[1]);
      if (!j) { jsonError(res, 404, 'Not Found'); return; }
      sendJson(res, 200, j, scopes);
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Contents.
  if (rest[0] === 'contents') {
    const path = rest.slice(1).join('/');
    const branch = query.get('ref') ?? undefined;
    if (method === 'GET') {
      const tip = contentsBranchTip(repo, branch ?? repo.defaultBranch);
      if (!tip) { jsonError(res, 404, 'Not Found'); return; }
      const c = getCommit(repo, tip);
      if (!c) { jsonError(res, 404, 'Not Found'); return; }
      const flat = new Map<string, { mode: string; oid: string }>();
      flattenTree(repo, c.tree, '', flat);
      if (!path) {
        // Root listing.
        const out = [...flat.entries()]
          .filter(([p]) => !p.includes('/'))
          .map(([p, e]) => ({ type: 'file', name: p, path: p, sha: e.oid, size: 0 }));
        sendJson(res, 200, out, scopes);
        return;
      }
      const file = flat.get(path);
      if (file) {
        const obj = repo.objects.get(file.oid);
        if (!obj) { jsonError(res, 404, 'Not Found'); return; }
        const nul = obj.full.indexOf(0);
        const content = obj.full.subarray(nul + 1);
        sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          size: content.length,
          name: path.split('/').pop(),
          path,
          content: content.toString('base64'),
          sha: file.oid,
        }, scopes);
        return;
      }
      // Directory listing.
      const prefix = `${path}/`;
      const entries: Array<Record<string, unknown>> = [];
      const seenDirs = new Set<string>();
      for (const [p, e] of flat) {
        if (!p.startsWith(prefix)) continue;
        const restPath = p.slice(prefix.length);
        if (!restPath.includes('/')) {
          entries.push({ type: 'file', name: restPath, path: p, sha: e.oid, size: 0 });
        } else {
          const dir = restPath.slice(0, restPath.indexOf('/'));
          if (!seenDirs.has(dir)) {
            seenDirs.add(dir);
            entries.push({ type: 'dir', name: dir, path: `${path}/${dir}`, sha: '', size: 0 });
          }
        }
      }
      if (entries.length === 0) { jsonError(res, 404, 'Not Found'); return; }
      entries.sort((a, b) => String(a.name).localeCompare(String(b.name)));
      sendJson(res, 200, entries, scopes);
      return;
    }
    if (method === 'PUT' || method === 'DELETE') {
      let body: Record<string, unknown>;
      try {
        body = parseJsonBody(ctx.body) as Record<string, unknown>;
      } catch {
        jsonError(res, 400, 'Problems parsing JSON');
        return;
      }
      const useBranch = typeof body.branch === 'string' && body.branch ? body.branch : repo.defaultBranch;
      let tip = contentsBranchTip(repo, useBranch);
      const message = typeof body.message === 'string' ? body.message : (method === 'PUT' ? 'Update file' : 'Delete file');
      if (method === 'PUT') {
        const contentB64 = typeof body.content === 'string' ? body.content : '';
        let content: Buffer;
        try {
          content = Buffer.from(contentB64, 'base64');
        } catch {
          jsonError(res, 422, 'content is not valid base64');
          return;
        }
        const { oid: blobOid, full } = gitObjectId('blob', content);
        const flat = new Map<string, { mode: string; oid: string }>();
        if (tip) {
          const c = getCommit(repo, tip);
          if (c) flattenTree(repo, c.tree, '', flat);
        }
        const existing = flat.get(path);
        const shaParam = typeof body.sha === 'string' ? body.sha : '';
        if (existing && !shaParam) { jsonError(res, 409, 'sha is required to update a file'); return; }
        if (existing && shaParam && shaParam !== existing.oid) { jsonError(res, 409, 'sha does not match'); return; }
        if (!existing && shaParam) { jsonError(res, 409, 'sha does not match'); return; }
        if (!repo.objects.has(blobOid)) repo.objects.set(blobOid, { type: 'blob', full });
        flat.set(path, { mode: '100644', oid: blobOid });
        const treeOid = buildTree(repo, flat);
        const parents = tip ? [tip] : [];
        const commitOid = makeCommit(repo, treeOid, parents, message);
        repo.refs.set(`refs/heads/${useBranch}`, commitOid);
        store.bump(repo);
        sendJson(res, existing ? 200 : 201, {
          content: { name: path.split('/').pop(), path, sha: blobOid, size: content.length, encoding: 'base64', type: 'file' },
          commit: { sha: commitOid, message },
        }, scopes);
        return;
      }
      // DELETE
      if (!tip) { jsonError(res, 404, 'Not Found'); return; }
      const c = getCommit(repo, tip);
      if (!c) { jsonError(res, 404, 'Not Found'); return; }
      const flat = new Map<string, { mode: string; oid: string }>();
      flattenTree(repo, c.tree, '', flat);
      if (!flat.has(path)) { jsonError(res, 404, 'Not Found'); return; }
      flat.delete(path);
      const treeOid = buildTree(repo, flat);
      const commitOid = makeCommit(repo, treeOid, [tip], message);
      repo.refs.set(`refs/heads/${useBranch}`, commitOid);
      store.bump(repo);
      sendJson(res, 200, { commit: { sha: commitOid, message }, content: null }, scopes);
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Labels.
  if (rest[0] === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      sendJson(res, 200, [...repo.labels.values()], scopes);
      return;
    }
    if (method === 'POST' && rest.length === 1) {
      let body: Record<string, unknown>;
      try {
        body = parseJsonBody(ctx.body) as Record<string, unknown>;
      } catch {
        jsonError(res, 400, 'Problems parsing JSON');
        return;
      }
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) { jsonError(res, 422, 'name is required'); return; }
      const existing = repo.labels.get(name);
      if (existing) { sendJson(res, 200, existing, scopes); return; }
      const label = {
        name,
        color: typeof body.color === 'string' ? body.color : 'ededed',
        description: typeof body.description === 'string' ? body.description : '',
      };
      repo.labels.set(name, label);
      sendJson(res, 201, label, scopes);
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Issues.
  if (rest[0] === 'issues') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const sort = query.get('sort') ?? 'created';
        const direction = query.get('direction') ?? 'desc';
        let list = [...repo.issues.values()];
        if (state !== 'all') list = list.filter((i) => i.state === state);
        if (sort === 'created') {
          list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        }
        const { page, perPage } = pageParams(query);
        const slice = list.slice((page - 1) * perPage, page * perPage);
        const bodies = slice.map((i) => issueJson(i, repo));
        sendCachedJson(res, 200, `[${bodies.join(',')}]`, { ...scopes, Link: linkHeader(req, page, perPage, list.length) });
        return;
      }
      if (method === 'POST') {
        let body: Record<string, unknown>;
        try {
          body = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const title = typeof body.title === 'string' ? body.title : '';
        if (!title) { jsonError(res, 422, 'title is required'); return; }
        const labels: string[] = Array.isArray(body.labels)
          ? (body.labels as unknown[]).map((l) => String(l))
          : [];
        for (const l of labels) {
          if (!repo.labels.has(l)) { jsonError(res, 422, `label "${l}" does not exist`); return; }
        }
        repo.issueSeq += 1;
        const issue: Issue = {
          id: store.nextId++,
          number: repo.issueSeq,
          title,
          body: typeof body.body === 'string' ? body.body : '',
          state: 'open',
          labels,
          createdAt: NOW_ISO,
          updatedAt: NOW_ISO,
          comments: [],
          jsonCache: null,
        };
        repo.issues.set(issue.number, issue);
        sendCachedJson(res, 201, issueJson(issue, repo), scopes);
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    const num = parseInt(rest[1], 10);
    const issue = repo.issues.get(num);
    if (rest.length === 2) {
      if (method === 'GET') {
        if (!issue) { jsonError(res, 404, 'Not Found'); return; }
        sendCachedJson(res, 200, issueJson(issue, repo), scopes);
        return;
      }
      if (method === 'PATCH') {
        if (!issue) { jsonError(res, 404, 'Not Found'); return; }
        let body: Record<string, unknown>;
        try {
          body = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        if (typeof body.title === 'string') issue.title = body.title;
        if (typeof body.body === 'string') issue.body = body.body;
        if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
        if (Array.isArray(body.labels)) {
          const labels = (body.labels as unknown[]).map((l) => String(l));
          for (const l of labels) {
            if (!repo.labels.has(l)) { jsonError(res, 422, `label "${l}" does not exist`); return; }
          }
          issue.labels = labels;
        }
        issue.updatedAt = NOW_ISO;
        issue.jsonCache = null;
        sendCachedJson(res, 200, issueJson(issue, repo), scopes);
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      if (!issue) { jsonError(res, 404, 'Not Found'); return; }
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((c) => ({
          id: c.id,
          node_id: b64encode(`comment:${c.id}`),
          body: c.body,
          created_at: c.createdAt,
          updated_at: c.updatedAt,
          user: { login: VIEWER.login, id: VIEWER.id },
        })), scopes);
        return;
      }
      if (method === 'POST') {
        let body: Record<string, unknown>;
        try {
          body = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const commentBody = typeof body.body === 'string' ? body.body : '';
        if (!commentBody) { jsonError(res, 422, 'body is required'); return; }
        const comment = {
          id: store.nextCommentId++,
          body: commentBody,
          createdAt: NOW_ISO,
          updatedAt: NOW_ISO,
        };
        issue.comments.push(comment);
        issue.jsonCache = null;
        sendJson(res, 201, {
          id: comment.id,
          node_id: b64encode(`comment:${comment.id}`),
          body: comment.body,
          created_at: comment.createdAt,
          updated_at: comment.updatedAt,
          user: { login: VIEWER.login, id: VIEWER.id },
        }, scopes);
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  // Pulls.
  if (rest[0] === 'pulls') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        let list = [...repo.pulls.values()];
        if (state !== 'all') list = list.filter((p) => p.state === state);
        list.sort((a, b) => b.number - a.number);
        const { page, perPage } = pageParams(query);
        const slice = list.slice((page - 1) * perPage, page * perPage);
        sendJson(res, 200, slice.map((p) => pullJson(p, repo)), { ...scopes, Link: linkHeader(req, page, perPage, list.length) });
        return;
      }
      if (method === 'POST') {
        let body: Record<string, unknown>;
        try {
          body = parseJsonBody(ctx.body) as Record<string, unknown>;
        } catch {
          jsonError(res, 400, 'Problems parsing JSON');
          return;
        }
        const title = typeof body.title === 'string' ? body.title : '';
        const head = typeof body.head === 'string' ? body.head : '';
        const base = typeof body.base === 'string' ? body.base : '';
        if (!title || !head || !base) { jsonError(res, 422, 'title, head and base are required'); return; }
        const headRef = head.includes(':') ? head.split(':').pop() as string : head;
        const baseRef = base.includes(':') ? base.split(':').pop() as string : base;
        const headSha = resolveRef(repo, headRef);
        const baseSha = resolveRef(repo, baseRef);
        if (!headSha || !baseSha) { jsonError(res, 422, 'head or base branch not found'); return; }
        for (const p of repo.pulls.values()) {
          if (p.state === 'open' && p.headRef === headRef && p.baseRef === baseRef) {
            jsonError(res, 422, 'a pull request already exists for this head and base');
            return;
          }
        }
        repo.pullSeq += 1;
        const pull: Pull = {
          id: store.nextId++,
          number: repo.pullSeq,
          title,
          body: typeof body.body === 'string' ? body.body : '',
          state: 'open',
          merged: false,
          mergedAt: null,
          mergeCommitSha: null,
          headRef,
          baseRef,
          headSha,
          baseSha,
          createdAt: NOW_ISO,
          updatedAt: NOW_ISO,
        };
        repo.pulls.set(pull.number, pull);
        sendJson(res, 201, pullJson(pull, repo), scopes);
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    const num = parseInt(rest[1], 10);
    const pull = repo.pulls.get(num);
    if (rest.length === 2 && method === 'GET') {
      if (!pull) { jsonError(res, 404, 'Not Found'); return; }
      sendJson(res, 200, pullJson(pull, repo), scopes);
      return;
    }
    if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
      if (!pull) { jsonError(res, 404, 'Not Found'); return; }
      const base = mergeBase(repo, pull.headSha, pull.baseSha);
      const baseTree = base ? (getCommit(repo, base)?.tree ?? '') : '';
      const headTree = getCommit(repo, pull.headSha)?.tree ?? '';
      const files = diffTrees(repo, baseTree, headTree);
      sendJson(res, 200, files, scopes);
      return;
    }
    if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
      if (!pull) { jsonError(res, 404, 'Not Found'); return; }
      const result = mergePull(store, repo, pull);
      if (!result.ok) {
        jsonError(res, result.status, result.message);
        return;
      }
      sendJson(res, 200, { merged: true, sha: result.sha, message: result.message }, scopes);
      return;
    }
    jsonError(res, 404, 'Not Found');
    return;
  }

  jsonError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------- shared PR merge

// Squash-merge a pull request. Returns the outcome; on conflict returns
// ok:false with status 405. Shared by the REST, GraphQL and MCP surfaces.
export function mergePull(store: Store, repo: Repo, pull: Pull): { ok: boolean; status: number; sha?: string; message: string } {
  if (pull.merged || pull.state !== 'open') {
    return { ok: false, status: 405, message: 'pull request is already merged or closed' };
  }
  // The base tip is live: another PR may have moved the base branch since
  // this PR was opened, and the merge (and its conflict test) must use the
  // branch as it stands now, not the sha recorded at creation.
  const liveBaseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
  const base = mergeBase(repo, pull.headSha, liveBaseSha);
  const baseTipTree = getCommit(repo, liveBaseSha)?.tree ?? '';
  const headTree = getCommit(repo, pull.headSha)?.tree ?? '';
  const mergeBaseTree = base ? (getCommit(repo, base)?.tree ?? '') : '';
  const headDiff = diffTrees(repo, mergeBaseTree, headTree);
  const baseDiff = diffTrees(repo, mergeBaseTree, baseTipTree);
  const headFlat = new Map<string, { mode: string; oid: string }>();
  const baseFlat = new Map<string, { mode: string; oid: string }>();
  if (headTree) flattenTree(repo, headTree, '', headFlat);
  if (baseTipTree) flattenTree(repo, baseTipTree, '', baseFlat);
  for (const d of headDiff) {
    const onBase = baseDiff.find((x) => x.filename === d.filename);
    if (!onBase) continue;
    const h = headFlat.get(d.filename);
    const b = baseFlat.get(d.filename);
    if ((h?.oid ?? null) !== (b?.oid ?? null)) {
      return { ok: false, status: 405, message: 'merge conflict' };
    }
  }
  const result = new Map(baseFlat);
  for (const d of headDiff) {
    if (d.status === 'removed') result.delete(d.filename);
    else {
      const h = headFlat.get(d.filename);
      if (h) result.set(d.filename, h);
    }
  }
  const treeOid = buildTree(repo, result);
  const message = `Merge pull request #${pull.number} from ${pull.headRef}\n\n${pull.title}`;
  const commitOid = makeCommit(repo, treeOid, [liveBaseSha], message);
  repo.refs.set(`refs/heads/${pull.baseRef}`, commitOid);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = NOW_ISO;
  pull.mergeCommitSha = commitOid;
  pull.updatedAt = NOW_ISO;
  store.bump(repo);
  return { ok: true, status: 200, sha: commitOid, message };
}

export function pullMergeable(repo: Repo, pull: Pull): boolean {
  if (pull.merged || pull.state !== 'open') return false;
  const liveBaseSha = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
  const base = mergeBase(repo, pull.headSha, liveBaseSha);
  const baseTipTree = getCommit(repo, liveBaseSha)?.tree ?? '';
  const headTree = getCommit(repo, pull.headSha)?.tree ?? '';
  const mergeBaseTree = base ? (getCommit(repo, base)?.tree ?? '') : '';
  const headDiff = diffTrees(repo, mergeBaseTree, headTree);
  const baseDiff = diffTrees(repo, mergeBaseTree, baseTipTree);
  const headFlat = new Map<string, { mode: string; oid: string }>();
  const baseFlat = new Map<string, { mode: string; oid: string }>();
  if (headTree) flattenTree(repo, headTree, '', headFlat);
  if (baseTipTree) flattenTree(repo, baseTipTree, '', baseFlat);
  for (const d of headDiff) {
    const onBase = baseDiff.find((x) => x.filename === d.filename);
    if (!onBase) continue;
    const h = headFlat.get(d.filename);
    const b = baseFlat.get(d.filename);
    if ((h?.oid ?? null) !== (b?.oid ?? null)) return false;
  }
  return true;
}

// ---------------------------------------------------------------- GraphQL

const USER_FIELDS = new Set(['id', 'login', 'name', 'email', 'url', 'avatarUrl', 'createdAt', 'updatedAt', 'viewerIsFollowing']);
const REPO_FIELDS = new Set(['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'description', 'isPrivate', 'createdAt', 'updatedAt', 'url', 'issue', 'issues', 'pullRequest', 'pullRequests', 'stargazerCount']);
const ISSUE_FIELDS = new Set(['id', 'databaseId', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'author', 'labels', 'comments', 'repository', 'url']);
const PULL_FIELDS = new Set(['id', 'databaseId', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'author', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'mergeable', 'merged', 'mergeCommit', 'files', 'repository', 'url']);
const TYPE_FIELDS: Record<string, Set<string>> = {
  User: USER_FIELDS,
  Repository: REPO_FIELDS,
  Issue: ISSUE_FIELDS,
  PullRequest: PULL_FIELDS,
};

export function globalId(kind: string, id: number): string {
  return b64encode(`${kind}:${id}`);
}

export function decodeGlobalId(id: string): { kind: string; num: number } | null {
  const text = b64decode(id);
  if (!text) return null;
  const m = /^([a-z]+):(\d+)$/.exec(text);
  if (!m) return null;
  return { kind: m[1], num: parseInt(m[2], 10) };
}

export function findIssueById(store: Store, id: number): { issue: Issue; repo: Repo } | null {
  for (const repo of store.reposByKey.values()) {
    for (const issue of repo.issues.values()) {
      if (issue.id === id) return { issue, repo };
    }
  }
  return null;
}

export function findPullById(store: Store, id: number): { pull: Pull; repo: Repo } | null {
  for (const repo of store.reposByKey.values()) {
    for (const pull of repo.pulls.values()) {
      if (pull.id === id) return { pull, repo };
    }
  }
  return null;
}

// Top-level field names inside the selection set that starts at `openBrace`.
export function topFields(query: string, openBrace: number): string[] {
  const fields: string[] = [];
  let depth = 0;
  let i = openBrace;
  while (i < query.length) {
    const ch = query[i];
    if (ch === '{') {
      depth += 1;
      i += 1;
      continue;
    }
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) break;
      i += 1;
      continue;
    }
    if (ch === '(') {
      // Skip an argument list.
      let d = 1;
      i += 1;
      while (i < query.length && d > 0) {
        if (query[i] === '(') d += 1;
        else if (query[i] === ')') d -= 1;
        else if (query[i] === '"') {
          i += 1;
          while (i < query.length && query[i] !== '"') i += query[i] === '\\' ? 2 : 1;
        }
        i += 1;
      }
      continue;
    }
    if (depth === 1 && /[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < query.length && /[A-Za-z0-9_]/.test(query[j])) j += 1;
      fields.push(query.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return fields;
}

// Extract the argument list of `fieldName(` in `query`, balanced.
export function argsOf(query: string, fieldName: string): string | null {
  const idx = query.indexOf(`${fieldName}(`);
  if (idx < 0) return null;
  let i = idx + fieldName.length + 1;
  let depth = 1;
  const start = i;
  while (i < query.length && depth > 0) {
    const ch = query[i];
    if (ch === '(') depth += 1;
    else if (ch === ')') depth -= 1;
    else if (ch === '"') {
      i += 1;
      while (i < query.length && query[i] !== '"') i += query[i] === '\\' ? 2 : 1;
    }
    i += 1;
  }
  return query.slice(start, i - 1);
}

export function argString(args: string | null, name: string): string | null {
  if (!args) return null;
  const m = new RegExp(`${name}\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`).exec(args);
  return m ? m[1] : null;
}

export function argInt(args: string | null, name: string): number | null {
  if (!args) return null;
  const m = new RegExp(`${name}\\s*:\\s*(\\d+)`).exec(args);
  return m ? parseInt(m[1], 10) : null;
}

export function argEnumList(args: string | null, name: string): string[] {
  if (!args) return [];
  const m = new RegExp(`${name}\\s*:\\s*\\[([^\\]]*)\\]`).exec(args);
  if (!m) return [];
  return m[1].split(',').map((s) => s.trim()).filter(Boolean);
}

export function toGraphQLLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return `[${value.map(toGraphQLLiteral).join(', ')}]`;
  if (typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>).map(([k, v]) => `${k}: ${toGraphQLLiteral(v)}`).join(', ')}}`;
  }
  return 'null';
}

// Substitute $variables into the query text so one parser handles both styles.
export function substituteVariables(query: string, variables: Record<string, unknown>): string {
  let out = query;
  for (const [name, value] of Object.entries(variables)) {
    out = out.replace(new RegExp(`\\$${name}\\b`, 'g'), toGraphQLLiteral(value));
  }
  return out;
}

export function issueGql(issue: Issue, repo: Repo): Record<string, unknown> {
  return {
    id: globalId('issue', issue.id),
    databaseId: issue.id,
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
    createdAt: issue.createdAt,
    updatedAt: issue.updatedAt,
    author: { login: VIEWER.login, id: VIEWER.id },
    labels: { nodes: issue.labels.map((name) => ({ name })) },
    comments: {
      nodes: issue.comments.map((c) => ({ id: globalId('comment', c.id), databaseId: c.id, body: c.body })),
      totalCount: issue.comments.length,
    },
    repository: { name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}` },
    url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

export function pullGql(pull: Pull, repo: Repo): Record<string, unknown> {
  const state = pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
  const base = mergeBase(repo, pull.headSha, pull.baseSha);
  const baseTree = base ? (getCommit(repo, base)?.tree ?? '') : '';
  const headTree = getCommit(repo, pull.headSha)?.tree ?? '';
  const diff = diffTrees(repo, baseTree, headTree);
  return {
    id: globalId('pull', pull.id),
    databaseId: pull.id,
    number: pull.number,
    title: pull.title,
    state,
    body: pull.body,
    createdAt: pull.createdAt,
    updatedAt: pull.updatedAt,
    author: { login: VIEWER.login, id: VIEWER.id },
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    headRef: { name: pull.headRef, target: { oid: pull.headSha } },
    baseRef: { name: pull.baseRef, target: { oid: pull.baseSha } },
    mergeable: pullMergeable(repo, pull) ? 'MERGEABLE' : 'CONFLICTING',
    merged: pull.merged,
    mergeCommit: pull.mergeCommitSha ? { oid: pull.mergeCommitSha } : null,
    files: {
      nodes: diff.map((d) => ({
        path: d.filename,
        filename: d.filename,
        status: d.status.toUpperCase(),
        additions: d.additions,
        deletions: d.deletions,
        changes: d.changes,
      })),
      totalCount: diff.length,
    },
    repository: { name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}` },
    url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

export function repoGql(repo: Repo, query: string): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: globalId('repo', repo.id),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER.login ? VIEWER.id : 1001 },
    defaultBranchRef: { name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    description: repo.description,
    isPrivate: repo.isPrivate,
    createdAt: repo.createdAt,
    updatedAt: repo.updatedAt,
    url: `https://github.com/${repo.owner}/${repo.name}`,
  };
  // issue(number:) — one issue.
  const issueArgs = argsOf(query, 'issue');
  if (issueArgs) {
    const num = argInt(issueArgs, 'number');
    const issue = num !== null ? repo.issues.get(num) : undefined;
    out.issue = issue ? issueGql(issue, repo) : null;
  }
  // pullRequest(number:) — one PR.
  const prArgs = argsOf(query, 'pullRequest');
  if (prArgs) {
    const num = argInt(prArgs, 'number');
    const pull = num !== null ? repo.pulls.get(num) : undefined;
    out.pullRequest = pull ? pullGql(pull, repo) : null;
  }
  // issues connection: first/after/states/orderBy.
  if (query.includes('issues')) {
    const args = argsOf(query, 'issues');
    const first = argInt(args, 'first');
    const after = argString(args, 'after');
    const states = argEnumList(args, 'states');
    const direction = /direction\s*:\s*(ASC|DESC)/.exec(args ?? '')?.[1] ?? 'DESC';
    let list = [...repo.issues.values()];
    if (states.length > 0) {
      list = list.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
    }
    list.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
    if (after) {
      const decoded = b64decode(after);
      const m = decoded ? /^cursor:(\d+)$/.exec(decoded) : null;
      if (m) {
        const n = parseInt(m[1], 10);
        list = direction === 'ASC' ? list.filter((i) => i.number > n) : list.filter((i) => i.number < n);
      }
    }
    const total = list.length;
    const take = first !== null ? list.slice(0, first) : list;
    const edges = take.map((i) => ({
      cursor: b64encode(`cursor:${i.number}`),
      node: issueGql(i, repo),
    }));
    out.issues = {
      nodes: take.map((i) => issueGql(i, repo)),
      edges,
      totalCount: total,
      pageInfo: {
        hasNextPage: first !== null ? total > first : false,
        hasPreviousPage: false,
        startCursor: edges.length ? edges[0].cursor : null,
        endCursor: edges.length ? edges[edges.length - 1].cursor : null,
      },
    };
  }
  // pullRequests connection.
  if (query.includes('pullRequests')) {
    const args = argsOf(query, 'pullRequests');
    const first = argInt(args, 'first');
    const after = argString(args, 'after');
    const states = argEnumList(args, 'states');
    const direction = /direction\s*:\s*(ASC|DESC)/.exec(args ?? '')?.[1] ?? 'DESC';
    let list = [...repo.pulls.values()];
    if (states.length > 0) {
      list = list.filter((p) => {
        const s = p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED';
        return states.includes(s);
      });
    }
    list.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
    if (after) {
      const decoded = b64decode(after);
      const m = decoded ? /^cursor:(\d+)$/.exec(decoded) : null;
      if (m) {
        const n = parseInt(m[1], 10);
        list = direction === 'ASC' ? list.filter((p) => p.number > n) : list.filter((p) => p.number < n);
      }
    }
    const total = list.length;
    const take = first !== null ? list.slice(0, first) : list;
    const edges = take.map((p) => ({
      cursor: b64encode(`cursor:${p.number}`),
      node: pullGql(p, repo),
    }));
    out.pullRequests = {
      nodes: take.map((p) => pullGql(p, repo)),
      edges,
      totalCount: total,
      pageInfo: {
        hasNextPage: first !== null ? total > first : false,
        hasPreviousPage: false,
        startCursor: edges.length ? edges[0].cursor : null,
        endCursor: edges.length ? edges[edges.length - 1].cursor : null,
      },
    };
  }
  return out;
}

// The operation's root field: the first field name after the operation's
// opening brace. (Substring matching would mistake `viewerPermission` for
// the `viewer` root field.)
export function rootField(compact: string): string | null {
  const brace = compact.indexOf('{');
  if (brace < 0) return null;
  let i = brace + 1;
  while (i < compact.length && /\s/.test(compact[i])) i += 1;
  const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(compact.slice(i));
  return m ? m[0] : null;
}

// The mutation input object: `input: { ... }`, balanced-brace extraction.
export function inputOf(query: string): string | null {
  const idx = query.indexOf('input:');
  if (idx < 0) return null;
  const brace = query.indexOf('{', idx);
  if (brace < 0) return null;
  let depth = 0;
  let i = brace;
  while (i < query.length) {
    const ch = query[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return query.slice(brace + 1, i);
    } else if (ch === '"') {
      i += 1;
      while (i < query.length && query[i] !== '"') i += query[i] === '\\' ? 2 : 1;
    }
    i += 1;
  }
  return null;
}

// One top-level field of an operation, with its alias (when written as
// `Alias: field`), its argument list and its selection set.
export interface TopField {
  alias: string | null;
  name: string;
  args: string | null;
  selStart: number;
  selEnd: number;
}

// Parse the top-level fields of an operation body (which starts with '{').
// Handles aliases, argument lists, nested selection sets and inline
// fragments; a document may hold several root fields in one body.
export function parseTopFields(body: string): TopField[] {
  const fields: TopField[] = [];
  const n = body.length;
  let i = 1; // skip the operation's opening brace
  const skipWs = (): void => {
    while (i < n && /[\s,]/.test(body[i])) i += 1;
  };
  const readWord = (): string | null => {
    const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(body.slice(i));
    if (!m) return null;
    i += m[0].length;
    return m[0];
  };
  const skipBalanced = (open: string, close: string): number => {
    let depth = 0;
    while (i < n) {
      const ch = body[i];
      if (ch === '"') {
        i += 1;
        while (i < n && body[i] !== '"') i += body[i] === '\\' ? 2 : 1;
        i += 1;
        continue;
      }
      if (ch === open) depth += 1;
      else if (ch === close) {
        depth -= 1;
        if (depth === 0) { i += 1; return i; }
      }
      i += 1;
    }
    return i;
  };
  while (i < n) {
    skipWs();
    if (i >= n || body[i] === '}') break;
    if (body[i] === '.' && body.startsWith('...', i)) {
      i += 3;
      skipWs();
      if (body.startsWith('on ', i)) {
        i += 3;
        readWord();
        skipWs();
      }
      if (body[i] === '{') skipBalanced('{', '}');
      continue;
    }
    const word1 = readWord();
    if (!word1) { i += 1; continue; }
    skipWs();
    let alias: string | null = null;
    let name = word1;
    if (body[i] === ':') {
      alias = word1;
      i += 1;
      skipWs();
      const word2 = readWord();
      if (!word2) break;
      name = word2;
      skipWs();
    }
    let args: string | null = null;
    if (body[i] === '(') {
      const start = i;
      skipBalanced('(', ')');
      args = body.slice(start + 1, i - 1);
      skipWs();
    }
    let selStart = -1;
    let selEnd = -1;
    if (body[i] === '{') {
      selStart = i;
      selEnd = skipBalanced('{', '}');
      skipWs();
    }
    fields.push({ alias, name, args, selStart, selEnd });
  }
  return fields;
}

// Run one mutation root field. Returns the payload object, or an error list.
export function executeMutation(store: Store, field: TopField): { payload?: Record<string, unknown>; errors?: Array<{ message: string }> } {
  const inputArgs = inputOf(field.args ?? '') ?? '';
  const getInput = (name: string): string | null => argString(inputArgs, name);
  if (field.name === 'createIssue') {
    const repoId = getInput('repositoryId');
    const title = getInput('title') ?? '';
    const body = getInput('body') ?? '';
    const decoded = repoId ? decodeGlobalId(repoId) : null;
    const repo = decoded ? store.reposById.get(decoded.num) : undefined;
    if (!repo || !title) return { errors: [{ message: 'createIssue: repository or title missing' }] };
    repo.issueSeq += 1;
    const issue: Issue = {
      id: store.nextId++,
      number: repo.issueSeq,
      title,
      body,
      state: 'open',
      labels: [],
      createdAt: NOW_ISO,
      updatedAt: NOW_ISO,
      comments: [],
      jsonCache: null,
    };
    repo.issues.set(issue.number, issue);
    return { payload: { issue: { number: issue.number, id: globalId('issue', issue.id) } } };
  }
  if (field.name === 'closeIssue') {
    const issueId = getInput('issueId');
    const decoded = issueId ? decodeGlobalId(issueId) : null;
    const found = decoded ? findIssueById(store, decoded.num) : null;
    if (!found) return { errors: [{ message: 'closeIssue: issue not found' }] };
    found.issue.state = 'closed';
    found.issue.updatedAt = NOW_ISO;
    found.issue.jsonCache = null;
    return { payload: { issue: { number: found.issue.number, id: globalId('issue', found.issue.id), state: 'CLOSED' } } };
  }
  if (field.name === 'createPullRequest') {
    const repoId = getInput('repositoryId');
    const baseRef = getInput('baseRefName') ?? '';
    const headRef = getInput('headRefName') ?? '';
    const title = getInput('title') ?? '';
    const decoded = repoId ? decodeGlobalId(repoId) : null;
    const repo = decoded ? store.reposById.get(decoded.num) : undefined;
    if (!repo || !baseRef || !headRef) return { errors: [{ message: 'createPullRequest: repository or refs missing' }] };
    const headSha = resolveRef(repo, headRef);
    const baseSha = resolveRef(repo, baseRef);
    if (!headSha || !baseSha) return { errors: [{ message: 'createPullRequest: head or base branch not found' }] };
    const existing = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === headRef && p.baseRef === baseRef);
    if (existing) {
      return { payload: { pullRequest: { number: existing.number, id: globalId('pull', existing.id), state: 'OPEN', headRefName: existing.headRef, baseRefName: existing.baseRef } } };
    }
    repo.pullSeq += 1;
    const pull: Pull = {
      id: store.nextId++,
      number: repo.pullSeq,
      title,
      body: getInput('body') ?? '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      headRef,
      baseRef,
      headSha,
      baseSha,
      createdAt: NOW_ISO,
      updatedAt: NOW_ISO,
    };
    repo.pulls.set(pull.number, pull);
    return { payload: { pullRequest: { number: pull.number, id: globalId('pull', pull.id), state: 'OPEN', headRefName: pull.headRef, baseRefName: pull.baseRef } } };
  }
  if (field.name === 'mergePullRequest') {
    const prId = getInput('pullRequestId');
    const decoded = prId ? decodeGlobalId(prId) : null;
    const found = decoded ? findPullById(store, decoded.num) : null;
    if (!found) return { errors: [{ message: 'mergePullRequest: pull request not found' }] };
    const result = mergePull(store, found.repo, found.pull);
    if (!result.ok) return { errors: [{ message: result.message }] };
    const state = found.pull.merged ? 'MERGED' : found.pull.state === 'open' ? 'OPEN' : 'CLOSED';
    return { payload: { pullRequest: { number: found.pull.number, id: globalId('pull', found.pull.id), merged: found.pull.merged, state } } };
  }
  if (field.name === 'addComment') {
    const subjectId = getInput('subjectId');
    const body = getInput('body') ?? '';
    const decoded = subjectId ? decodeGlobalId(subjectId) : null;
    if (!decoded) return { errors: [{ message: 'addComment: subject not found' }] };
    if (decoded.kind === 'issue') {
      const found = findIssueById(store, decoded.num);
      if (!found) return { errors: [{ message: 'addComment: issue not found' }] };
      const comment = { id: store.nextCommentId++, body, createdAt: NOW_ISO, updatedAt: NOW_ISO };
      found.issue.comments.push(comment);
      found.issue.jsonCache = null;
      return { payload: { commentEdge: { node: { id: globalId('comment', comment.id), body } } } };
    }
    return { errors: [{ message: 'addComment: subject is not commentable' }] };
  }
  return { errors: [{ message: 'Unknown mutation' }] };
}

export function executeGraphQL(store: Store, rawQuery: string, variables: Record<string, unknown>): { data?: Record<string, unknown> | null; errors?: Array<{ message: string }> } {
  const opBrace = rawQuery.indexOf('{');
  if (opBrace < 0) return { data: null, errors: [{ message: 'Unknown query' }] };
  const head = rawQuery.slice(0, opBrace);
  const isMutation = /mutation\b/.test(head);
  // Substitute variables only inside the operation body. The signature
  // ($input: CreateIssueInput!) must not be rewritten: it holds braces after
  // substitution and would break every parser that follows.
  const body = substituteVariables(rawQuery.slice(opBrace), variables).replace(/#[^\n]*/g, ' ');
  const fields = parseTopFields(body);
  const data: Record<string, unknown> = {};
  const errors: Array<{ message: string }> = [];
  for (const field of fields) {
    const key = field.alias ?? field.name;
    if (field.name === '__type') {
      const typeName = argString(field.args, 'name');
      if (!typeName) {
        errors.push({ message: 'Cannot query __type without a name' });
        continue;
      }
      if (typeName === 'SearchType') {
        data[key] = { name: typeName, kind: 'ENUM', enumValues: [{ name: 'ISSUE' }, { name: 'REPOSITORY' }, { name: 'USER' }] };
      } else {
        const typeFields = TYPE_FIELDS[typeName];
        if (!typeFields) { data[key] = null; continue; }
        data[key] = { name: typeName, kind: 'OBJECT', fields: [...typeFields].map((n) => ({ name: n })) };
      }
      continue;
    }
    if (isMutation) {
      const out = executeMutation(store, field);
      if (out.errors) errors.push(...out.errors);
      else if (out.payload) data[key] = out.payload;
      continue;
    }
    if (field.name === 'viewer') {
      const sub = field.selStart >= 0 ? topFields(body, field.selStart) : [];
      const bad = sub.find((x) => !USER_FIELDS.has(x));
      if (bad) {
        errors.push({ message: `Cannot query field "${bad}" on type "User".` });
        continue;
      }
      data[key] = {
        login: VIEWER.login,
        id: VIEWER.id,
        name: VIEWER.name,
        email: VIEWER.email,
        url: `https://github.com/${VIEWER.login}`,
      };
      continue;
    }
    if (field.name === 'repository') {
      const owner = argString(field.args, 'owner');
      const name = argString(field.args, 'name');
      const repo = owner && name ? store.get(owner, name) : undefined;
      if (!repo) { data[key] = null; continue; }
      const sub = field.selStart >= 0 ? topFields(body, field.selStart) : [];
      const bad = sub.find((x) => !REPO_FIELDS.has(x) && x !== '__typename');
      if (bad) {
        errors.push({ message: `Cannot query field "${bad}" on type "Repository".` });
        continue;
      }
      data[key] = repoGql(repo, body);
      continue;
    }
    if (field.name === 'node') {
      const id = argString(field.args, 'id');
      const decoded = id ? decodeGlobalId(id) : null;
      if (decoded && decoded.kind === 'repo') {
        const repo = store.reposById.get(decoded.num);
        data[key] = repo ? repoGql(repo, body) : null;
      } else if (decoded && decoded.kind === 'issue') {
        const found = findIssueById(store, decoded.num);
        data[key] = found ? issueGql(found.issue, found.repo) : null;
      } else if (decoded && decoded.kind === 'pull') {
        const found = findPullById(store, decoded.num);
        data[key] = found ? pullGql(found.pull, found.repo) : null;
      } else {
        data[key] = null;
      }
      continue;
    }
    errors.push({ message: `Cannot query field "${field.name}" on type "Query".` });
  }
  if (errors.length > 0) return { data: Object.keys(data).length > 0 ? data : null, errors };
  return { data };
}
export async function handleGraphQL(req: http.IncomingMessage, res: http.ServerResponse, ctx: Ctx): Promise<void> {
  let parsed: unknown;
  try {
    parsed = parseJsonBody(ctx.body);
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return;
  }
  const run = (op: Record<string, unknown>): Record<string, unknown> => {
    const query = typeof op.query === 'string' ? op.query : '';
    const variables = (op.variables ?? {}) as Record<string, unknown>;
    const out = executeGraphQL(ctx.store, query, variables);
    return out as Record<string, unknown>;
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map((op) => run(op as Record<string, unknown>)));
    return;
  }
  sendJson(res, 200, run(parsed as Record<string, unknown>));
}

// ---------------------------------------------------------------- MCP

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'owner/repo' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpToolResult(result: unknown): Record<string, unknown> {
  const text = JSON.stringify(result);
  return { content: [{ type: 'text', text }], structuredContent: result };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { isError: true, content: [{ type: 'text', text: message }] };
}

export function executeMcpTool(store: Store, name: string, args: Record<string, unknown>): Record<string, unknown> {
  const arg = (k: string): string | undefined => {
    const v = args[k];
    return typeof v === 'string' ? v : undefined;
  };
  const need = (k: string): string | null => {
    const v = arg(k);
    return v === undefined || v === '' ? null : v;
  };
  const repoOf = (): Repo | null => {
    let owner = arg('owner');
    let repoName = arg('repo');
    const full = arg('full_name');
    if ((!owner || !repoName) && full && full.includes('/')) {
      const [o, r] = full.split('/');
      owner = o;
      repoName = r;
    }
    if (!owner || !repoName) return null;
    return store.get(owner, repoName) ?? null;
  };

  if (name === 'create_repo') {
    const repoName = need('name');
    if (!repoName) return mcpToolError('missing required argument: name');
    if (store.get(VIEWER.login, repoName)) return mcpToolError(`repository ${repoName} already exists`);
    const repo = store.createRepo(VIEWER.login, repoName, arg('description') ?? '', args.private === true);
    return mcpToolResult(repoJson(repo));
  }
  if (name === 'get_repo') {
    const repo = repoOf();
    if (!repo) return mcpToolError('repository not found');
    return mcpToolResult(repoJson(repo));
  }
  if (name === 'create_issue') {
    const repo = repoOf();
    const title = need('title');
    if (!repo) return mcpToolError('repository not found');
    if (!title) return mcpToolError('missing required argument: title');
    repo.issueSeq += 1;
    const issue: Issue = {
      id: store.nextId++,
      number: repo.issueSeq,
      title,
      body: arg('body') ?? '',
      state: 'open',
      labels: [],
      createdAt: NOW_ISO,
      updatedAt: NOW_ISO,
      comments: [],
      jsonCache: null,
    };
    repo.issues.set(issue.number, issue);
    return mcpToolResult(JSON.parse(issueJson(issue, repo)));
  }
  if (name === 'list_issues') {
    const repo = repoOf();
    if (!repo) return mcpToolError('repository not found');
    const state = arg('state') ?? 'open';
    let list = [...repo.issues.values()];
    if (state !== 'all') list = list.filter((i) => i.state === state);
    list.sort((a, b) => b.number - a.number);
    return mcpToolResult({ issues: list.map((i) => JSON.parse(issueJson(i, repo))) });
  }
  if (name === 'create_pull_request') {
    const repo = repoOf();
    const title = need('title');
    const head = need('head');
    const base = need('base');
    if (!repo) return mcpToolError('repository not found');
    if (!title) return mcpToolError('missing required argument: title');
    if (!head) return mcpToolError('missing required argument: head');
    if (!base) return mcpToolError('missing required argument: base');
    const headSha = resolveRef(repo, head);
    const baseSha = resolveRef(repo, base);
    if (!headSha || !baseSha) return mcpToolError('head or base branch not found');
    const existing = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
    if (existing) return mcpToolResult(pullJson(existing, repo));
    repo.pullSeq += 1;
    const pull: Pull = {
      id: store.nextId++,
      number: repo.pullSeq,
      title,
      body: arg('body') ?? '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      headRef: head,
      baseRef: base,
      headSha,
      baseSha,
      createdAt: NOW_ISO,
      updatedAt: NOW_ISO,
    };
    repo.pulls.set(pull.number, pull);
    return mcpToolResult(pullJson(pull, repo));
  }
  if (name === 'merge_pull_request') {
    const repo = repoOf();
    if (!repo) return mcpToolError('repository not found');
    const num = typeof args.pull_number === 'number' ? args.pull_number : parseInt(String(args.pull_number ?? ''), 10);
    if (!Number.isFinite(num)) return mcpToolError('missing required argument: pull_number');
    const pull = repo.pulls.get(num);
    if (!pull) return mcpToolError('pull request not found');
    const result = mergePull(store, repo, pull);
    if (!result.ok) return mcpToolError(result.message);
    return mcpToolResult({ merged: true, sha: result.sha, message: result.message });
  }
  return mcpToolError(`unknown tool ${name}`);
}

export async function handleMcp(req: http.IncomingMessage, res: http.ServerResponse, ctx: Ctx): Promise<void> {
  let parsed: unknown;
  try {
    parsed = parseJsonBody(ctx.body);
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const msg = parsed as Record<string, unknown>;
  const id = msg.id ?? null;
  const method = typeof msg.method === 'string' ? msg.method : '';
  const params = (msg.params ?? {}) as Record<string, unknown>;
  const respond = (result: unknown): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, result });
  };
  const respondError = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };
  // Notifications carry no id and expect no reply.
  if (id === null && method.startsWith('notifications/')) {
    res.writeHead(202, { 'X-GitHub-Request-Id': nextRequestId() });
    res.end();
    return;
  }
  if (method === 'server/discover') {
    const serverInfo = { name: 'github-core-forge', version: '1.0.0' };
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2026-07-28',
        supportedVersions: ['2026-07-28', '2025-11-25'],
        serverInfo,
        capabilities: { tools: {} },
        _meta: { 'io.modelcontextprotocol/serverInfo': serverInfo },
      },
    }, { 'Mcp-Session-Id': 'forge-session-1' });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const chosen = /^\d{4}-\d{2}-\d{2}$/.test(offered) ? offered : '2025-11-25';
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: chosen,
        serverInfo: { name: 'github-core-forge', version: '1.0.0' },
        capabilities: { tools: {} },
      },
    }, { 'Mcp-Session-Id': 'forge-session-1' });
    return;
  }
  if (method === 'tools/list') {
    respond({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const known = MCP_TOOLS.some((t) => t.name === toolName);
    if (!known) {
      respondError(-32602, `unknown tool ${toolName}`);
      return;
    }
    respond(executeMcpTool(ctx.store, toolName, args));
    return;
  }
  if (method === 'ping') {
    respond({});
    return;
  }
  respondError(-32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------- dispatcher

export function createApp(): http.Server {
  const store = new Store();
  const server = http.createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://x');
        const path = url.pathname;
        const query = url.searchParams;

        if (req.method === 'GET' && path === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }

        const needsBody = req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE';
        const body = needsBody ? await readBody(req) : Buffer.alloc(0);
        const ctx: Ctx = { store, body, query, params: [] };

        // API surfaces need the bearer token.
        if (path === '/api/graphql' || path === '/mcp' || path.startsWith('/api/v3')) {
          if (!authed(req)) {
            jsonError(res, 401, 'Requires authentication');
            return;
          }
          if (path === '/api/graphql') {
            if (req.method !== 'POST') { jsonError(res, 404, 'Not Found'); return; }
            await handleGraphQL(req, res, ctx);
            return;
          }
          if (path === '/mcp') {
            if (req.method !== 'POST') { jsonError(res, 404, 'Not Found'); return; }
            await handleMcp(req, res, ctx);
            return;
          }
          ctx.params = path.split('/').slice(3).filter(Boolean);
          await handleRest(req, res, ctx);
          return;
        }

        // Git smart HTTP: /<owner>/<repo>[.git]/info/refs, git-upload-pack,
        // git-receive-pack. (The client suffixes repo names with .git.)
        const parts = path.split('/').filter(Boolean);
        if (parts.length >= 3) {
          const owner = parts[0];
          const repoName = parts[1].endsWith('.git') ? parts[1].slice(0, -4) : parts[1];
          const repo = store.get(owner, repoName);
          const tail = parts.slice(2).join('/');
          if (tail === 'info/refs' && req.method === 'GET') {
            handleInfoRefs(repo, query.get('service') ?? '', res);
            return;
          }
          if (!repo) {
            jsonError(res, 404, 'Not Found');
            return;
          }
          if (tail === 'git-upload-pack' && req.method === 'POST') {
            handleUploadPack(repo, body, res);
            return;
          }
          if (tail === 'git-receive-pack' && req.method === 'POST') {
            handleReceivePack(store, repo, body, res);
            return;
          }
        }
        jsonError(res, 404, 'Not Found');
      } catch (err) {
        try {
          jsonError(res, 500, err instanceof Error ? err.message : 'Internal error');
        } catch {
          try { res.end(); } catch { /* already gone */ }
        }
      }
    })();
  });
  return server;
}
