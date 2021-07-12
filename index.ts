import {hash as sha256, hkdf} from "fast-sha256";

// Verify this with EIP-2333: https://eips.ethereum.org/EIPS/eip-2333

// bls12-381 r
const blsR = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex);
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex');
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    array[i] = Number.parseInt(hex.slice(j, j + 2), 16);
  }
  return array;
}

function numberToHex(num: number | bigint): string {
  const hex = num.toString(16);
  return hex.length & 1 ? `0${hex}` : hex;
}

function numberToBytesPadded(num: bigint, length = 32) {
  const hex = numberToHex(num).padStart(length * 2, '0');
  return hexToBytes(hex).reverse();
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

function utf8ToBytes(str: string) {
  return new TextEncoder().encode(str);
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  if (arrays.length === 1) return arrays[0];
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result;
}

function ikmToLamportSK(ikm: Uint8Array, salt: Uint8Array) {
  const okm = hkdf(ikm, salt, undefined, 32 * 255);
  return Array.from({ length: 255 }, (_, i) => okm.slice(i * 32, (i + 1) * 32));
}

function parentSKToLamportPK(parentSK: Uint8Array, index: number) {
  if (!(parentSK instanceof Uint8Array)) throw new TypeError('Expected Uint8Array');
  if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 32) {
    throw new TypeError('Expected positive number');
  }
  const salt = i2osp(index, 4);
  const ikm = parentSK;
  const lamport0 = ikmToLamportSK(ikm, salt);
  const notIkm = ikm.map((byte) => ~byte);
  const lamport1 = ikmToLamportSK(notIkm, salt);
  const lamportPK = lamport0.concat(lamport1).map((part) => sha256(part));
  return sha256(concatBytes(...lamportPK));
}

export function hkdfModR(ikm: Uint8Array, keyInfo = new Uint8Array()) {
  let salt = utf8ToBytes("BLS-SIG-KEYGEN-SALT-");
  let SK = 0n;
  const input = concatBytes(ikm, Uint8Array.from([0x00]));
  const label = concatBytes(keyInfo, Uint8Array.from([0x00, 0x30]));
  while (SK === 0n) {
    salt = sha256(salt);
    const okm = hkdf(input, salt, label, 48);
    SK = os2ip(okm) % blsR;
  }
  return numberToBytesPadded(SK);
}

export function deriveMaster(seed: Uint8Array): Uint8Array {
  return hkdfModR(seed);
}

export function deriveChild(parentKey: Uint8Array, index: number): Uint8Array {
  return hkdfModR(parentSKToLamportPK(parentKey, index));
}

export function deriveSeedTree(seed: Uint8Array, path: string) {
  if (typeof path !== 'string') throw new Error('Derivation path must be string');
  const indices = path.split('/');
  if (indices.shift() !== 'm') throw new Error('First character of path must be "m"');
  const nodes = indices.map(i => Number.parseInt(i));
  let sk = deriveMaster(seed);
  for (const node of nodes) {
    sk = deriveChild(sk, node);
  }
  return sk;
}
