import { assert, assertEquals, assertThrows } from "./deps.ts";
import { errors, sign, utils } from "./../lib.ts";

Deno.test({
  name: "utils.compare(a, b) returns -1 if a is less than b",
  fn(): void {
    const a: Uint8Array = new Uint8Array(2);
    const b: Uint8Array = Uint8Array.from([1,2])

   const ordering: number = utils.compare(a, b)

    assertEquals(ordering, -1)
  }
});

Deno.test({
  name: "utils.compare(a, b) returns 0 if a and b are equal",
  fn(): void {
    const a: Uint8Array = Uint8Array.from([36,44])
    const b: Uint8Array = Uint8Array.from([36,44])

   const ordering: number = utils.compare(a, b)

    assertEquals(ordering, 0)
  }
});

Deno.test({
  name: "utils.compare(a, b) returns 1 if a is more than b",
  fn(): void {
    const a: Uint8Array = Uint8Array.from([44,44])
    const b: Uint8Array = Uint8Array.from([44,43])

   const ordering: number = utils.compare(a, b)

    assertEquals(ordering, 1)
  }
});

Deno.test({
  name: "utils.equal(a, b) does constant time equality checks",
  fn(): void {
    const a: Uint8Array = Uint8Array.from([44,44])
    const b: Uint8Array = Uint8Array.from([44,44])
    const c: Uint8Array = Uint8Array.from([44,43])

assert(utils.equal(a, b))
assert(!utils.equal(b,c))
  }
});

Deno.test({
  name: "utils.increment(buf) increments a buffer in little-endian fashion",
  fn(): void {
    const buf: Uint8Array = new Uint8Array(2);

   for ( let i: number = 0; i < 419 ; ++i) {
      utils.increment(buf)
   }

   const num: number = new DataView(buf.buffer).getUint16(0, true)

    assertEquals(num, 419)
  }
});

Deno.test({
  name: "utils.memzero(x) clears Uint8Arrays",
  fn(): void {
    const buf: Uint8Array = new Uint8Array(2).fill(99);

    assert(buf.every((byte: number): boolean => byte ===99))

    utils.memzero(buf)

    assert(buf.every((byte: number): boolean => byte ===0))
  }
});

Deno.test({
  name: "utils.memzero(x) also clears anything with a bufferview prop",
  fn(): void {
    const buf: Uint8Array = new Uint8Array(sign.SECRETKEYBYTES).fill(99);

    const secret_key :sign.SecretKey = new sign.SecretKey(buf)

    assert(secret_key.bufferview.every((byte: number): boolean => byte ===99))

    utils.memzero(secret_key)

    assert(secret_key.bufferview.every((byte: number): boolean => byte ===0))
  }
});

Deno.test({
  name: "utils.pad(buf, blocksize) constructs and returns a padded buffer",
  fn(): void {
    const blocksize: number = 64;

    const a: Uint8Array = new Uint8Array(2)

    assertEquals(a. byteLength, 2)

    const b: Uint8Array = utils.pad(a, blocksize)

   assert(a!== b)

    assertEquals(b.byteLength, blocksize)
  }
});

Deno.test({
  name:"utils..hex encoding",
  fn():void {
    const msg: string = "41434142";

const buf: Uint8Array = utils.hex2bin(msg);

const str: string = utils.bin2hex(buf);

assertEquals(buf, Uint8Array.from([0x41, 0x43, 0x41, 0x42]))

assertEquals(str, msg)
  }
})

Deno.test({
  name: "utils.unpad(buf, blocksize) constructs and returns an unpadded buffer",
  fn(): void {
    const blocksize: number = 100;

    const a: Uint8Array = Uint8Array.from([52, 53, 50, 97])

    assertEquals(a.byteLength, 4)

    const b: Uint8Array = utils.unpad(a, blocksize)

   assert(a!== b)

    assertEquals(b.byteLength, blocksize)
  }
});