// Local key-pin preview only: not publisher authority, registration admission or a network client.
import { base58 } from '@scure/base';
import { ed25519 } from '@noble/curves/ed25519.js';
import { importX25519Private } from './hpke-x25519.ts';
import { parseProofJson, proofInvalid, proofRecord } from './strict-json.ts';
import { b64Proof, checkChallenge, checkProofContext, computeXResponse, decodeProofBinary, exactProofBytes,
  proofHandle, proofHpkeInfo, proofHpkeSuite, proofJcsBytes, proofNow, proofOrigin,
  registrationHeader, registrationSigningInput } from './provider-proof-internal.ts';

/** Ed25519 multicodec only. Encoding a key does not prove possession or origin authority. */
export function encodeProviderDidKey(edPub32: unknown): string {
  const bytes = exactProofBytes(edPub32, 32);
  return 'did:key:z' + base58.encode(new Uint8Array([0xed, 0x01, ...bytes]));
}
export function decodeProviderDidKey(identifier: unknown): Uint8Array {
  try {
    if (typeof identifier !== 'string' || identifier.length > 160 || !/^[\x21-\x7e]+$/.test(identifier)) return proofInvalid();
    const [did, fragment, extra] = identifier.split('#');
    if (extra !== undefined || !/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/.test(did)) return proofInvalid();
    const fingerprint = did.slice(8);
    if (fragment !== undefined && fragment !== fingerprint) return proofInvalid();
    const raw = base58.decode(fingerprint.slice(1));
    if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01 || 'z' + base58.encode(raw) !== fingerprint) return proofInvalid();
    return Uint8Array.from(raw.subarray(2));
  } catch { return proofInvalid(); }
}

/** Explicit public allowlist: never pass an internal sender return object here. */
export function encodePublicRegistrationChallenge(publicPart: unknown): Uint8Array {
  try { return proofJcsBytes(checkChallenge(publicPart)); } catch { return proofInvalid(); }
}

export interface AnswerRegistrationOptions {
  expectedOrigin: string;
  localEdSeed32: Uint8Array;
  localXPrivateKey: Uint8Array;
  clientNow: number;
}
/** All local keys/config must be supplied independently of the untrusted challenge. No IO. */
export async function answerRegistrationChallenge(publicChallengeBytes: unknown, options: AnswerRegistrationOptions): Promise<Uint8Array> {
  let edSeed: Uint8Array | undefined, xRaw: Uint8Array | undefined, secret: Uint8Array | undefined, response: Uint8Array | undefined;
  try {
    // Perform reflection, parsing and all owned snapshots before the first await.
    const o = proofRecord(options, ['expectedOrigin', 'localEdSeed32', 'localXPrivateKey', 'clientNow']);
    const origin = proofOrigin(o.expectedOrigin), now = proofNow(o.clientNow);
    const p = checkChallenge(parseProofJson(publicChallengeBytes));
    edSeed = exactProofBytes(o.localEdSeed32, 32);
    xRaw = exactProofBytes(o.localXPrivateKey, 32);
    checkProofContext(p.transcript, origin, now);
    const localEdPub = ed25519.getPublicKey(edSeed);
    // Exact public bytes also bind the full fingerprint, not only its truncated handle.
    if (b64Proof(localEdPub) !== p.transcript.edPub || proofHandle(localEdPub) !== p.transcript.handle) return proofInvalid();
    const { privateKey, publicKey } = await importX25519Private(xRaw);
    if (b64Proof(publicKey) !== p.transcript.xPub) return proofInvalid();
    const suite = proofHpkeSuite();
    const plain = await suite.open({ recipientKey: privateKey,
      enc: decodeProofBinary(p.enc, 32).buffer as ArrayBuffer,
      info: proofHpkeInfo(p.transcript).buffer as ArrayBuffer },
    decodeProofBinary(p.ciphertext, 48).buffer as ArrayBuffer, proofJcsBytes(p.transcript).buffer as ArrayBuffer);
    // This buffer is returned to us by the library; best-effort cleanup on success and errors.
    secret = new Uint8Array(plain);
    if (secret.length !== 32) return proofInvalid();
    response = computeXResponse(p.transcript, secret);
    const xResponse = b64Proof(response), header = registrationHeader(p.transcript.handle);
    const signature = `${header}..${b64Proof(ed25519.sign(registrationSigningInput(header, p, xResponse), edSeed))}`;
    return proofJcsBytes({ challengeId: p.transcript.challengeId, xResponse, signature });
  } catch { return proofInvalid(); }
  finally { edSeed?.fill(0); xRaw?.fill(0); secret?.fill(0); response?.fill(0); }
}
