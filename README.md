# bls12-381-keygen

BLS12-381 Key Generation compatible with [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333).

If you're looking for actual implementation of the elliptic curve,
use module [noble-bls12-381](https://github.com/paulmillr/noble-bls12-381).
The bls12-381-keygen only generates private keys, by EIP-2333 specification.

No dependencies.

## Usage

Node.js and browser:

> npm install bls12-381-keygen

```js
import {deriveMaster, deriveChild} from 'bls12-381-keygen';
const master = deriveMaster(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
const child = deriveChild(master, 0); // 0 is numeric index
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
