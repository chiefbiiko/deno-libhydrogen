import { assert, assertEquals } from "./deps.ts";
import { kdf } from "./../lib.ts";

const CONTEXT: kdf.Context = new kdf.Context(Uint8Array.from([0x68, 0x61, 0x73, 0x68, 0x74, 0x65, 0x73, 0x74]));
const KEY: kdf.Key = new kdf.Key();

Deno.test({
  name: "kdf.BYTES_MIN",
  fn(): void {
    assertEquals(typeof kdf.BYTES_MIN, "number");
    assertEquals(kdf.BYTES_MIN, 16);
  }
});

Deno.test({
  name: "kdf.BYTES_MAX",
  fn(): void {
    assertEquals(typeof kdf.BYTES_MAX, "number");
    assertEquals(kdf.BYTES_MAX, 65535);
  }
});

Deno.test({
  name: "kdf.CONTEXTBYTES",
  fn(): void {
    assertEquals(typeof kdf.CONTEXTBYTES, "number");
    assertEquals(kdf.CONTEXTBYTES, 8);
  }
});

Deno.test({
  name: "kdf.KEYBYTES",
  fn(): void {
    assertEquals(typeof kdf.KEYBYTES, "number");
    assertEquals(kdf.KEYBYTES, 32);
  }
});

Deno.test({
  name: "new kdf.Context() instantiates an 8-byte context for hashing",
  fn(): void {
    const key:kdf.Key = new kdf.Key();

    assertEquals(key.bufferview.byteLength, kdf.KEYBYTES);

    assert(key.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "new kdf.Key() instantiates a 32-byte key for hashing",
  fn(): void {
    const key:kdf.Key = new kdf.Key();

    assertEquals(key.bufferview.byteLength, kdf.KEYBYTES);

    assert(key.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "kdf.derive_from_key(subkey_len, subkey_id, context, key) returns a subkey_len-byte subkey",
  fn(): void {
    const subkey: Uint8Array = kdf.derive_from_key(kdf.BYTES_MAX, 419n, CONTEXT, KEY);

    assertEquals(subkey.byteLength, kdf.BYTES_MAX);

    assert(subkey.some((byte: number): boolean => byte !== 0));
  }
});