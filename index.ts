import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';

// Verify this with EIP-2333: https://eips.ethereum.org/EIPS/eip-2333

// bls12-381 r
const blsR = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;

function numberToBytesBE(n: bigint, len: number) {
  return hexToBytes(n.toString(16).padStart(len * 2, '0'));
}

// Octet Stream to Integer
function os2ip(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result <<= 8n;
    result += BigInt(bytes[i]);
  }
  return result;
}

// Integer to Octet Stream
function i2osp(value: number, length: number): Uint8Array {
  if (value < 0 || value >= 1n << BigInt(8 * length)) {
    throw new Error(`bad I2OSP call: value=${value} length=${length}`);
  }
  const res = Array.from({ length }).fill(0) as number[];
  for (let i = length - 1; i >= 0; i--) {
    res[i] = value & 0xff;
    value >>>= 8;
  }
  return new Uint8Array(res);
}

function ikmToLamportSK(ikm: Uint8Array, salt: Uint8Array) {
  const okm = hkdf(sha256, ikm, salt, undefined, 32 * 255);
  return Array.from({ length: 255 }, (_, i) => okm.slice(i * 32, (i + 1) * 32));
}

function assertUint32(index: number) {
  if (!Number.isSafeInteger(index) || index < 0 || index > 2 ** 32 - 1) {
    throw new TypeError('Expected valid uint32 number');
  }
}

function parentSKToLamportPK(parentSK: Uint8Array, index: number) {
  if (!(parentSK instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
  assertUint32(index);
  const salt = i2osp(index, 4);
  const ikm = parentSK;
  const lamport0 = ikmToLamportSK(ikm, salt);
  const notIkm = ikm.map((byte) => ~byte);
  const lamport1 = ikmToLamportSK(notIkm, salt);
  const lamportPK = lamport0.concat(lamport1).map((part) => sha256(part));
  return sha256(concatBytes(...lamportPK));
}

export function hkdfModR(ikm: Uint8Array, keyInfo = new Uint8Array()) {
  let salt = utf8ToBytes('BLS-SIG-KEYGEN-SALT-');
  let SK = 0n;
  const input = concatBytes(ikm, Uint8Array.from([0x00]));
  const label = concatBytes(keyInfo, Uint8Array.from([0x00, 0x30]));
  while (SK === 0n) {
    salt = sha256(salt);
    const okm = hkdf(sha256, input, salt, label, 48);
    SK = os2ip(okm) % blsR;
  }
  return numberToBytesBE(SK, 32);
}

export function deriveMaster(seed: Uint8Array): Uint8Array {
  return hkdfModR(seed);
}

export function deriveChild(parentKey: Uint8Array, index: number): Uint8Array {
  return hkdfModR(parentSKToLamportPK(parentKey, index));
}

export function deriveSeedTree(seed: Uint8Array, path: string): Uint8Array {
  if (typeof path !== 'string') throw new Error('Derivation path must be string');
  const indices = path.split('/');
  if (indices.shift() !== 'm') throw new Error('First character of path must be "m"');
  let sk = deriveMaster(seed);
  const nodes = indices.map((i) => Number.parseInt(i));
  nodes.forEach((node) => {
    sk = deriveChild(sk, node);
  });
  return sk;
}

export const EIP2334_KEY_TYPES = ['withdrawal', 'signing'] as const;
export type EIP2334KeyType = typeof EIP2334_KEY_TYPES[number];
export function deriveEIP2334Key(seed: Uint8Array, type: EIP2334KeyType, index: number) {
  if (!(seed instanceof Uint8Array)) throw new Error('Valid seed expected');
  if (!EIP2334_KEY_TYPES.includes(type)) throw new Error('Valid keystore type expected');
  assertUint32(index);
  // EIP-2334 specifies following derivation paths:
  // m/12381/3600/0/0   for withdrawal
  // m/12381/3600/0/0/0 for signing
  const path = `m/12381/3600/${index}/0${type === 'signing' ? '/0' : ''}`;
  return { key: deriveSeedTree(seed, path), path };
}
