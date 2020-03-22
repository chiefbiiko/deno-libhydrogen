# deno-libhydrogen

<p align="center">
  <img width="1864" src="https://raw.githubusercontent.com/chiefbiiko/deno-libhydrogen/master/deno_libhydrogen.png" alt="deno+libhydrogen logo" title="💧">
</p>

deno plugin 2 [`libhydrogen`](https://github.com/jedisct1/libhydrogen)

![ci](https://github.com/chiefbiiko/deno-libhydrogen/workflows/ci/badge.svg?branch=master)

## api

following [`rust-libhydrogen`'s](https://github.com/jedisct1/rust-libhydrogen) API amap

### `random`

``` ts
export namespace random {
  export const SEEDBYTES: number = 32;

  export class Seed {
    public readonly bufferview: Uint8Array;
    constructor(raw_seed?: Uint8Array);
    static gen(): Seed;
  }

  export function buf(out_len: number): Uint8Array;
  export function buf_deterministic(out_len: number, seed: Seed): Uint8Array;
  export function buf_deterministic_into(out: Uint8Array, seed: Seed): void;
  export function buf_into(out: Uint8Array): void;
  export function ratchet(): void;
  export function reseed(): void;
  export function u32(): number;
  export function uniform(upper_bound: number): number;
}
```

### `hash`

``` ts
export namespace hash {
  export const BYTES: number = 32;
  export const BYTES_MAX: number = 65535;
  export const BYTES_MIN: number = 16;
  export const CONTEXTBYTES: number = 8;
  export const KEYBYTES: number = 32;

  export class Context {
    public readonly bufferview: Uint8Array;
    constructor(raw_context: string | Uint8Array);
  }

  export class Key {
    public readonly bufferview: Uint8Array;
    constructor(raw_key?: Uint8Array);
    public static gen(): Key;
  }

  export interface DefaultHasher {
    update(input: Uint8Array): DefaultHasher;
    finish(out_len: number): Uint8Array;
    finish_into(out: Uint8Array): void;
  }

  export function init(context: Context, key?: Key): DefaultHasher;
  export function hash(out_len: number, input: Uint8Array, context: Context, key?: Key): Uint8Array;
  export function hash_into(out: Uint8Array, input: Uint8Array, context: Context, key?: Key): void;
}
```

### `kdf`

``` ts
export namespace kdf {
  export const BYTES_MAX: number = 65535;
  export const BYTES_MIN: number = 16;
  export const CONTEXTBYTES: number = 8;
  export const KEYBYTES: number = 32;

  export class Context {
    public readonly bufferview: Uint8Array;
    constructor(raw_context: string | Uint8Array);
  }

  export class Key {
    public readonly bufferview: Uint8Array;
    constructor(raw_key?: Uint8Array);
    public static gen(): Key;
  }

  export function derive_from_key(subkey_len: number, subkey_id: bigint, context: Context, key: Key): Uint8Array;
}
```

### `secretbox`

``` ts
export namespace secretbox {
  export const CONTEXTBYTES: number = 8;
  export const HEADERBYTES: number = 36;
  export const KEYBYTES: number = 32;
  export const PROBEBYTES: number = 16;

  export class Context {
    public readonly bufferview: Uint8Array;
    constructor(raw_context: string | Uint8Array);
  }

  export class Key {
    public readonly bufferview: Uint8Array;
    constructor(raw_key?: Uint8Array);
    public static gen(): Key;
  }

  export class Probe {
    public readonly bufferview: Uint8Array;
    constructor(input: Uint8Array, context: Context, key: Key);
    public static create(input: Uint8Array, context: Context, key: Key): Probe;
    public verify(input: Uint8Array, context: Context, key: Key): void;
  }

  export function decrypt(input: Uint8Array, msg_id: bigint, context: Context, key: Key): Uint8Array;
  export function encrypt(input: Uint8Array, msg_id: bigint, context: Context, key: Key): Uint8Array;
}
```

### `sign`

``` ts
export namespace sign {
  export const BYTES: number = 64;
  export const CONTEXTBYTES: number = 8;
  export const PUBLICKEYBYTES: number = 32;
  export const SECRETKEYBYTES: number = 64;
  export const SEEDBYTES: number = 32;

  export class Context {
    public readonly bufferview: Uint8Array;
    constructor(raw_context: string | Uint8Array);
  }

  export class KeyPair {
    public readonly public_key: PublicKey;
    public readonly secret_key: SecretKey;
    constructor(raw_public_key: Uint8Array, raw_secret_key: Uint8Array);
    public static gen(): KeyPair;
  }

  export class PublicKey {
    public readonly bufferview: Uint8Array;
    constructor(raw_public_key: Uint8Array);
  }

  export class SecretKey {
    public readonly bufferview: Uint8Array;
    constructor(raw_secret_key: Uint8Array);
  }

  export class Signature {
    public readonly bufferview: Uint8Array;
    constructor(raw_signature: Uint8Array);
  }

  export interface Sign {
    update(input: Uint8Array): Sign;
    finish_create(secret_key: SecretKey): Signature;
    finish_verify(signature: Signature, public_key: PublicKey): void;
  }

  class SignImpl implements Sign {
    private readonly id: Uint8Array;
    constructor(context: Context);
    public update(input: Uint8Array): Sign;
    public finish_create(secret_key: SecretKey): Signature;
    public finish_verify(signature: Signature, public_key: PublicKey): void;
  }

  export function init(context: Context): Sign;
  export function create(input: Uint8Array, context: Context, secret_key: SecretKey): Signature;
  export function verify(signature: Signature, input: Uint8Array, context: Context, public_key: PublicKey): void;
}
```

### `kx`

submodule bindings pending

### `pwhash`

submodule bindings pending

### `utils`

``` ts
export namespace utils {
  export function bin2hex(buf: Uint8Array): string;
  export function compare(a: Uint8Array, b: Uint8Array): number;
  export function equal(a: Uint8Array, b: Uint8Array): boolean;
  export function hex2bin(hex: string, ignore: string = ""): Uint8Array;
  export function increment(buf: Uint8Array): void;
  export function memzero(buf: Uint8Array): void;
  export function pad(buf: Uint8Array, blocksize: number): Uint8Array;
  export function unpad(buf: Uint8Array, blocksize: number): Uint8Array;
}
```

## security considerations

+ `deno-libhydrogen` clears any internally allocated memory after use, both on `deno` and `rust` side - to avoid leakage

+ any instances of `errors.HydroError` have a fixed static message that cannot be altered anyhow, again - to avoid leakage

  + still there is `err.stack` - make sure to not expose it to the outside of your application - that minimizes attack vectors

## license

[MIT](./LICENSE)