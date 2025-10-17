/* tslint:disable */
/* eslint-disable */
export function encrypt(delegating_pk: PublicKey, plaintext: Uint8Array): [Capsule, Uint8Array];
export function decryptOriginal(delegating_sk: SecretKey, capsule: Capsule, ciphertext: Uint8Array): Uint8Array;
export function decryptReencrypted(receiving_sk: SecretKey, delegating_pk: PublicKey, capsule: Capsule, vcfrags: VerifiedCapsuleFrag[], ciphertext: Uint8Array): Uint8Array;
export function generateKFrags(delegating_sk: SecretKey, receiving_pk: PublicKey, signer: Signer, threshold: number, shares: number, sign_delegating_key: boolean, sign_receiving_key: boolean): VerifiedKeyFrag[];
export function reencrypt(capsule: Capsule, kfrag: VerifiedKeyFrag): VerifiedCapsuleFrag;
export class Capsule {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  __getClassname(): string;
  toBytes(): Uint8Array;
  toBytesSimple(): Uint8Array;
  static fromBytes(data: Uint8Array): Capsule;
  toString(): string;
  equals(other: Capsule): boolean;
}
export class CapsuleFrag {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  verify(capsule: Capsule, verifying_pk: PublicKey, delegating_pk: PublicKey, receiving_pk: PublicKey): VerifiedCapsuleFrag;
  toBytes(): Uint8Array;
  toBytesSimple(): Uint8Array;
  static fromBytes(data: Uint8Array): CapsuleFrag;
  toString(): string;
  skipVerification(): VerifiedCapsuleFrag;
  equals(other: CapsuleFrag): boolean;
}
export class CurvePoint {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  coordinates(): [Uint8Array, Uint8Array] | undefined;
}
export class KeyFrag {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  verify(verifying_pk: PublicKey, delegating_pk: PublicKey | null, receiving_pk: PublicKey | null): VerifiedKeyFrag;
  toBytes(): Uint8Array;
  static fromBytes(data: Uint8Array): KeyFrag;
  toString(): string;
  skipVerification(): VerifiedKeyFrag;
  equals(other: KeyFrag): boolean;
}
export class Parameters {
  free(): void;
  [Symbol.dispose](): void;
  constructor();
  readonly u: CurvePoint;
}
export class PublicKey {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  __getClassname(): string;
  toCompressedBytes(): Uint8Array;
  static fromCompressedBytes(data: Uint8Array): PublicKey;
  static recoverFromPrehash(prehash: Uint8Array, signature: RecoverableSignature): PublicKey;
  toString(): string;
  equals(other: PublicKey): boolean;
}
export class RecoverableSignature {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  toBEBytes(): Uint8Array;
  static fromBEBytes(data: Uint8Array): RecoverableSignature;
  toString(): string;
  equals(other: RecoverableSignature): boolean;
}
export class ReencryptionEvidence {
  free(): void;
  [Symbol.dispose](): void;
  constructor(capsule: Capsule, vcfrag: VerifiedCapsuleFrag, verifying_pk: PublicKey, delegating_pk: PublicKey, receiving_pk: PublicKey);
  toBytes(): Uint8Array;
  static fromBytes(data: Uint8Array): ReencryptionEvidence;
  readonly e: CurvePoint;
  readonly ez: CurvePoint;
  readonly e1: CurvePoint;
  readonly e1h: CurvePoint;
  readonly e2: CurvePoint;
  readonly v: CurvePoint;
  readonly vz: CurvePoint;
  readonly v1: CurvePoint;
  readonly v1h: CurvePoint;
  readonly v2: CurvePoint;
  readonly uz: CurvePoint;
  readonly u1: CurvePoint;
  readonly u1h: CurvePoint;
  readonly u2: CurvePoint;
  readonly kfragValidityMessageHash: Uint8Array;
  readonly kfragSignatureV: boolean;
}
export class SecretKey {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Generates a secret key using the default RNG and returns it.
   */
  static random(): SecretKey;
  toBEBytes(): Uint8Array;
  static fromBEBytes(data: Uint8Array): SecretKey;
  /**
   * Generates a secret key using the default RNG and returns it.
   */
  publicKey(): PublicKey;
  toString(): string;
  equals(other: SecretKey): boolean;
}
export class SecretKeyFactory {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Generates a secret key factory using the default RNG and returns it.
   */
  static random(): SecretKeyFactory;
  static seedSize(): number;
  static fromSecureRandomness(seed: Uint8Array): SecretKeyFactory;
  makeSecret(label: Uint8Array): Uint8Array;
  makeKey(label: Uint8Array): SecretKey;
  makeFactory(label: Uint8Array): SecretKeyFactory;
  toString(): string;
}
export class Signature {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  verify(verifying_pk: PublicKey, message: Uint8Array): boolean;
  toDerBytes(): Uint8Array;
  static fromDerBytes(data: Uint8Array): Signature;
  toBEBytes(): Uint8Array;
  static fromBEBytes(data: Uint8Array): Signature;
  toString(): string;
  equals(other: Signature): boolean;
}
export class Signer {
  free(): void;
  [Symbol.dispose](): void;
  constructor(secret_key: SecretKey);
  sign(message: Uint8Array): Signature;
  verifyingKey(): PublicKey;
  toString(): string;
}
export class VerifiedCapsuleFrag {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  __getClassname(): string;
  unverify(): CapsuleFrag;
  toBytes(): Uint8Array;
  toBytesSimple(): Uint8Array;
  toString(): string;
  equals(other: VerifiedCapsuleFrag): boolean;
}
export class VerifiedKeyFrag {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  __getClassname(): string;
  toBytes(): Uint8Array;
  toString(): string;
  equals(other: VerifiedKeyFrag): boolean;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_secretkey_free: (a: number, b: number) => void;
  readonly secretkey_random: () => number;
  readonly secretkey_toBEBytes: (a: number) => [number, number];
  readonly secretkey_fromBEBytes: (a: number, b: number) => [number, number, number];
  readonly secretkey_publicKey: (a: number) => number;
  readonly secretkey_toString: (a: number) => [number, number];
  readonly secretkey_equals: (a: number, b: number) => number;
  readonly __wbg_secretkeyfactory_free: (a: number, b: number) => void;
  readonly secretkeyfactory_random: () => number;
  readonly secretkeyfactory_fromSecureRandomness: (a: number, b: number) => [number, number, number];
  readonly secretkeyfactory_makeSecret: (a: number, b: number, c: number) => [number, number];
  readonly secretkeyfactory_makeKey: (a: number, b: number, c: number) => number;
  readonly secretkeyfactory_makeFactory: (a: number, b: number, c: number) => number;
  readonly secretkeyfactory_toString: (a: number) => [number, number];
  readonly publickey___getClassname: (a: number) => [number, number];
  readonly __wbg_publickey_free: (a: number, b: number) => void;
  readonly publickey_toCompressedBytes: (a: number) => [number, number];
  readonly publickey_fromCompressedBytes: (a: number, b: number) => [number, number, number];
  readonly publickey_recoverFromPrehash: (a: number, b: number, c: number) => [number, number, number];
  readonly publickey_toString: (a: number) => [number, number];
  readonly publickey_equals: (a: number, b: number) => number;
  readonly __wbg_signer_free: (a: number, b: number) => void;
  readonly signer_new: (a: number) => number;
  readonly signer_sign: (a: number, b: number, c: number) => number;
  readonly signer_verifyingKey: (a: number) => number;
  readonly signer_toString: (a: number) => [number, number];
  readonly __wbg_signature_free: (a: number, b: number) => void;
  readonly signature_verify: (a: number, b: number, c: number, d: number) => number;
  readonly signature_toDerBytes: (a: number) => [number, number];
  readonly signature_fromDerBytes: (a: number, b: number) => [number, number, number];
  readonly signature_toBEBytes: (a: number) => [number, number];
  readonly signature_fromBEBytes: (a: number, b: number) => [number, number, number];
  readonly signature_toString: (a: number) => [number, number];
  readonly signature_equals: (a: number, b: number) => number;
  readonly __wbg_recoverablesignature_free: (a: number, b: number) => void;
  readonly recoverablesignature_toBEBytes: (a: number) => [number, number];
  readonly recoverablesignature_fromBEBytes: (a: number, b: number) => [number, number, number];
  readonly recoverablesignature_toString: (a: number) => [number, number];
  readonly recoverablesignature_equals: (a: number, b: number) => number;
  readonly capsule___getClassname: (a: number) => [number, number];
  readonly __wbg_capsule_free: (a: number, b: number) => void;
  readonly capsule_toBytes: (a: number) => [number, number, number, number];
  readonly capsule_toBytesSimple: (a: number) => [number, number];
  readonly capsule_fromBytes: (a: number, b: number) => [number, number, number];
  readonly capsule_toString: (a: number) => [number, number];
  readonly capsule_equals: (a: number, b: number) => number;
  readonly __wbg_capsulefrag_free: (a: number, b: number) => void;
  readonly capsulefrag_verify: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly capsulefrag_toBytes: (a: number) => [number, number, number, number];
  readonly capsulefrag_toBytesSimple: (a: number) => [number, number];
  readonly capsulefrag_fromBytes: (a: number, b: number) => [number, number, number];
  readonly capsulefrag_toString: (a: number) => [number, number];
  readonly capsulefrag_skipVerification: (a: number) => number;
  readonly capsulefrag_equals: (a: number, b: number) => number;
  readonly verifiedcapsulefrag___getClassname: (a: number) => [number, number];
  readonly __wbg_verifiedcapsulefrag_free: (a: number, b: number) => void;
  readonly verifiedcapsulefrag_toBytes: (a: number) => [number, number, number, number];
  readonly verifiedcapsulefrag_toBytesSimple: (a: number) => [number, number];
  readonly verifiedcapsulefrag_toString: (a: number) => [number, number];
  readonly verifiedcapsulefrag_equals: (a: number, b: number) => number;
  readonly encrypt: (a: number, b: number, c: number) => [number, number, number];
  readonly decryptOriginal: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly decryptReencrypted: (a: number, b: number, c: number, d: any, e: number, f: number) => [number, number, number, number];
  readonly __wbg_keyfrag_free: (a: number, b: number) => void;
  readonly keyfrag_verify: (a: number, b: number, c: any, d: any) => [number, number, number];
  readonly keyfrag_toBytes: (a: number) => [number, number, number, number];
  readonly keyfrag_fromBytes: (a: number, b: number) => [number, number, number];
  readonly keyfrag_toString: (a: number) => [number, number];
  readonly keyfrag_skipVerification: (a: number) => number;
  readonly keyfrag_equals: (a: number, b: number) => number;
  readonly verifiedkeyfrag___getClassname: (a: number) => [number, number];
  readonly __wbg_verifiedkeyfrag_free: (a: number, b: number) => void;
  readonly verifiedkeyfrag_toBytes: (a: number) => [number, number, number, number];
  readonly verifiedkeyfrag_toString: (a: number) => [number, number];
  readonly verifiedkeyfrag_equals: (a: number, b: number) => number;
  readonly generateKFrags: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
  readonly reencrypt: (a: number, b: number) => number;
  readonly __wbg_curvepoint_free: (a: number, b: number) => void;
  readonly curvepoint_coordinates: (a: number) => any;
  readonly __wbg_parameters_free: (a: number, b: number) => void;
  readonly parameters_new: () => number;
  readonly parameters_u: (a: number) => number;
  readonly __wbg_reencryptionevidence_free: (a: number, b: number) => void;
  readonly reencryptionevidence_new: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly reencryptionevidence_toBytes: (a: number) => [number, number, number, number];
  readonly reencryptionevidence_fromBytes: (a: number, b: number) => [number, number, number];
  readonly reencryptionevidence_ez: (a: number) => number;
  readonly reencryptionevidence_e1: (a: number) => number;
  readonly reencryptionevidence_e1h: (a: number) => number;
  readonly reencryptionevidence_e2: (a: number) => number;
  readonly reencryptionevidence_v: (a: number) => number;
  readonly reencryptionevidence_vz: (a: number) => number;
  readonly reencryptionevidence_v1: (a: number) => number;
  readonly reencryptionevidence_v1h: (a: number) => number;
  readonly reencryptionevidence_v2: (a: number) => number;
  readonly reencryptionevidence_uz: (a: number) => number;
  readonly reencryptionevidence_u1: (a: number) => number;
  readonly reencryptionevidence_u1h: (a: number) => number;
  readonly reencryptionevidence_u2: (a: number) => number;
  readonly reencryptionevidence_kfragValidityMessageHash: (a: number) => any;
  readonly reencryptionevidence_kfragSignatureV: (a: number) => number;
  readonly verifiedcapsulefrag_unverify: (a: number) => number;
  readonly reencryptionevidence_e: (a: number) => number;
  readonly secretkeyfactory_seedSize: () => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
