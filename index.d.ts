export declare function hkdfModR(ikm: Uint8Array, keyInfo?: Uint8Array): Uint8Array;
export declare function deriveMaster(seed: Uint8Array): Uint8Array;
export declare function deriveChild(parentKey: Uint8Array, index: number): Uint8Array;
export declare function deriveSeedTree(seed: Uint8Array, path: string): Uint8Array;
