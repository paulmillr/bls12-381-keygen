# bls12-381-keygen

BLS12-381 Key Generation compatible with [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333).

If you're looking for actual implementation of the elliptic curve,
use module [noble-bls12-381](https://github.com/paulmillr/noble-bls12-381).
The bls12-381-keygen only generates private keys, by EIP-2333 specification.

Just one small dependency on SHA256.

## Usage

Node.js and browser:

> npm install bls12-381-keygen

- `deriveMaster` takes `Uint8Array` and returns `Uint8Array`
- `deriveChild` takes `Uint8Array, number` and returns `Uint8Array`

```js
import { deriveMaster, deriveChild } from 'bls12-381-keygen';
const master = deriveMaster(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
const child = deriveChild(master, 0); // 0 is numeric index
```

## Generating BIP32 seeds for ETH2

```js
import { getPublicKey } from '@noble/bls12-381';
import { deriveSeedTree } from 'bls12-381-keygen';
import { entropyToMnemonic, mnemonicToSeedSync } from 'micro-bip39';
import { wordlist } from 'micro-bip39/wordlists/english';

function eth2PrivFromBytes(bytes, path = 'm/12381/3600/0/0/0') {
  const mnemonic = entropyToMnemonic(bytes, wordlist);
  const seed = mnemonicToSeedSync(mnemonic);
  return deriveSeedTree(seed, path);
}

function eth2PubFromBytes(bytes, path) {
  return getPublicKey(eth2PrivFromBytes(bytes, path));
}
```

## Users

The project is used in iancoleman's [eip2333-tool](https://iancoleman.io/eip2333/)

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
