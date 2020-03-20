import { assert, assertEquals } from "./deps.ts";
import { hash } from "./../lib.ts";

    const CONTEXT: hash.Context = new hash.Context(Uint8Array.from([0x68, 0x61, 0x73, 0x68, 0x74, 0x65, 0x73, 0x74]));
const INPUT: Uint8Array = new Uint8Array([0x64,0x65,0x6e, 0x6f])
const KEY: hash.Key = new hash.Key();

Deno.test({
  name: "hash.BYTES",
  fn(): void {
    assertEquals(typeof hash.BYTES, "number");
    assertEquals(hash.BYTES, 32);
  }
});

Deno.test({
  name: "hash.BYTES_MIN",
  fn(): void {
    assertEquals(typeof hash.BYTES_MIN, "number");
    assertEquals(hash.BYTES_MIN, 16);
  }
});

Deno.test({
  name: "hash.BYTES_MAX",
  fn(): void {
    assertEquals(typeof hash.BYTES_MAX, "number");
    assertEquals(hash.BYTES_MAX, 65535);
  }
});

Deno.test({
  name: "hash.CONTEXTBYTES",
  fn(): void {
    assertEquals(typeof hash.CONTEXTBYTES, "number");
    assertEquals(hash.CONTEXTBYTES, 8);
  }
});

Deno.test({
  name: "hash.KEYBYTES",
  fn(): void {
    assertEquals(typeof hash.KEYBYTES, "number");
    assertEquals(hash.KEYBYTES, 32);
  }
});

Deno.test({
  name: "new hash.Context() instantiates an 8-byte context for hashing",
  fn(): void {
    const key:hash.Key = new hash.Key();

    assertEquals(key.bufferview.byteLength, hash.KEYBYTES);

    assert(key.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "new hash.Key() instantiates a 32-byte key for hashing",
  fn(): void {
    const key:hash.Key = new hash.Key();

    assertEquals(key.bufferview.byteLength, hash.KEYBYTES);

    assert(key.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "hash.init() initializes a hash instance for incremental hash updates",
  fn(): void {
    const inst: hash.DefaultHasher = hash.init(CONTEXT);

    inst.update(INPUT);

    const buf: Uint8Array =  inst.finish(hash.BYTES);

    assertEquals(buf.byteLength, hash.BYTES);

    assert(buf.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "hash..DefaultHasher instances allow detached finishing",
  fn(): void {
    const out: Uint8Array = new Uint8Array(hash.BYTES);

    const inst: hash.DefaultHasher = hash.init(CONTEXT);

    inst.update(INPUT);

    inst.finish_into(out);

    assertEquals(out.byteLength, hash.BYTES);

    assert(out.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "hash..DefaultHasher's two finish methods return identical bytes",
  fn(): void {
  const buf: Uint8Array =  hash.init(CONTEXT)
      .update(INPUT)
      .finish(hash.BYTES);

    const out: Uint8Array = new Uint8Array(hash.BYTES);

    hash.init(CONTEXT)
      .update(INPUT)
      .finish_into(out);

    assertEquals(buf, out);
  }
});

Deno.test({
  name: "hash.hash(out_len, input, context, key?) returns a out_len-byte hash",
  fn(): void {
    const buf: Uint8Array = hash.hash(hash.BYTES, INPUT, CONTEXT);

    assert(buf.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "hash.hash_into(out, input, context, key?) fills out with a hash",
  fn(): void {
    const out: Uint8Array = new Uint8Array(hash.BYTES)

    hash.hash_into(out, INPUT, CONTEXT);

    assert(out.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "hash.hash*(out, input, context, key?) yield identical bytes",
  fn(): void {
    const out: Uint8Array = new Uint8Array(hash.BYTES)

    hash.hash_into(out, INPUT, CONTEXT);

  const buf: Uint8Array = hash.hash(hash.BYTES, INPUT, CONTEXT);

    assertEquals(buf, out);
  }
});

Deno.test({
  name: "hash.hash*(out, input, context, key?) with a key yield identical bytes",
  fn(): void {
    const out: Uint8Array = new Uint8Array(hash.BYTES)

    hash.hash_into(out, INPUT, CONTEXT, KEY);

  const buf: Uint8Array = hash.hash(hash.BYTES, INPUT, CONTEXT, KEY);

    assertEquals(buf, out);
  }
});