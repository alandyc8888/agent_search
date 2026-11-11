// Read-only legacy identity loading. No creation, migration, repair, chmod or network.
import fs from 'node:fs';
import { importX25519Private, exportX25519Private } from '@a2n/protocol';

const MAX_IDENTITY_BYTES = 16 * 1024;
function readIdentityJson(file: string): unknown {
  let fd: number | undefined;
  const bytes = Buffer.alloc(MAX_IDENTITY_BYTES + 1);
  try {
    const before = fs.lstatSync(file);
    const valid = (s: fs.Stats) => s.isFile() && !s.isSymbolicLink() && s.nlink === 1 &&
      (s.mode & 0o777) === 0o600 && typeof process.getuid === 'function' && s.uid === process.getuid();
    if (!valid(before) || before.size > MAX_IDENTITY_BYTES) throw Error();
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const opened = fs.fstatSync(fd);
    if (!valid(opened) || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > MAX_IDENTITY_BYTES) throw Error();
    let size = 0, count: number;
    do { count = fs.readSync(fd, bytes, size, bytes.length - size, null); size += count; }
    while (count > 0 && size < bytes.length);
    const after = fs.fstatSync(fd);
    if (size > MAX_IDENTITY_BYTES || !valid(after) || after.dev !== opened.dev || after.ino !== opened.ino ||
        after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) throw Error();
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size))) as unknown;
  } catch {
    throw Error('identity_file_invalid');
  } finally {
    bytes.fill(0);
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** The returned X bytes are owned by the caller; clear after use. Ed material is not normalized. */
export async function loadProviderIdentity(file: string): Promise<{ privateKey: string; xPrivateKey: Uint8Array; xPub: Uint8Array }> {
  const value = readIdentityJson(file);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('identity_file_invalid');
  const key = value as Record<string, unknown>;
  if (typeof key.privateKey !== 'string' || typeof key.xPrivateKey !== 'string') throw Error('identity_file_invalid');
  const imported = Object.hasOwn(key, 'xPub')
    ? await importX25519Private(key.xPrivateKey, key.xPub)
    : await importX25519Private(key.xPrivateKey);
  return { privateKey: key.privateKey, xPrivateKey: await exportX25519Private(imported.privateKey), xPub: imported.publicKey };
}
