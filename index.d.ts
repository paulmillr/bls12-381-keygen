export declare function hkdfModR(ikm: Uint8Array, keyInfo?: Uint8Array): Uint8Array;
export declare function deriveMaster(seed: Uint8Array): Uint8Array;
export declare function deriveChild(parentKey: Uint8Array, index: number): Uint8Array;
export declare function deriveSeedTree(seed: Uint8Array, path: string): Uint8Array;
export declare const EIP2334_KEY_TYPES: readonly ["withdrawal", "signing"];
export declare type EIP2334KeyType = typeof EIP2334_KEY_TYPES[number];
export declare function deriveEIP2334Key(seed: Uint8Array, type: EIP2334KeyType, index: number): {
    key: Uint8Array;
    path: string;
};
