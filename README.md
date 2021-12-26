# bls12-381-keygen

Minimal BLS12-381 Key Generation compatible with [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333).
Can be used to generate EIP-2334 keys for ETH beacon chain.

Has only one tiny dependency on `@noble/hashes` for SHA256 and HKDF.

If you're looking for actual implementation of the elliptic curve,
use module [noble-bls12-381](https://github.com/paulmillr/noble-bls12-381).
The bls12-381-keygen only generates private keys, by EIP-2333 specification.

Check out live demo in iancoleman's [eip2333-tool](https://iancoleman.io/eip2333/)

## Usage

Node.js and browser:

> npm install bls12-381-keygen

The API is the following:

```typescript
function deriveMaster(seed: Uint8Array): Uint8Array;
function deriveChild(parentKey: Uint8Array, index: number): Uint8Array;
function deriveSeedTree(seed: Uint8Array, path: string): Uint8Array;
const EIP2334_KEY_TYPES: readonly ["withdrawal", "signing"];
type EIP2334KeyType = typeof EIP2334_KEY_TYPES[number];
function deriveEIP2334Key(seed: Uint8Array, type: EIP2334KeyType, index: number): {
  key: Uint8Array;
  path: string;
};
```

Usage example:

```ts
import { deriveEIP2334Key, deriveSeedTree } from 'bls12-381-keygen';

const seed = (new Uint8Array(32)).fill(7); // must be random
deriveEIP2334Key(seed, 'withdrawal', 6);

// Those two are equal
const signKey1a = deriveEIP2334Key(seed, 'signing', 0);
const signKey1b = deriveSeedTree(seed, 'm/12381/3600/0/0/0');

// To generate mnemonics for EIP-2334 keystores
import { entropyToMnemonic, mnemonicToSeedSync } from 'micro-bip39';
import { wordlist } from 'micro-bip39/wordlists/english';
// bytes = some random sequence
const mnSeed = mnemonicToSeedSync(entropyToMnemonic(bytes, wordlist));
deriveEIP2334Key(mnSeed, 'signing', index);

// To generate BLS12-381 public key, use @noble crypto
import { getPublicKey } from '@noble/bls12-381';
getPublicKey(signKey1a);
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
