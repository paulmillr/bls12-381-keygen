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
const {deriveMaster, deriveChild} = require('bls12-381-keygen');
const master = deriveMaster(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
const child = deriveChild(master, 0); // 0 is numeric index
```

## Generating BIP32 seeds for ETH2

```js
const bls = require('noble-bls12-381');
const keygen = require('bls12-381-keygen');
const bip39 = require('bip39');
function eth2PrivFromBytes(bytes, path = 'm/12381/3600/0/0/0') {
  const mnemonic = bip39.entropyToMnemonic(bytes);
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  return keygen.deriveSeedTree(seed, path);
}
function eth2PubFromBytes(bytes, path) {
  return bls.getPublicKey(eth2PrivFromBytes(bytes, path));
}
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
