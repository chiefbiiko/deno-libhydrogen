import { assert, assertEquals } from "./deps.ts";
import { random } from "./../lib.ts";

Deno.test({
  name: "random.SEEDBYTES",
  fn(): void {
    assertEquals(typeof random.SEEDBYTES, "number");
    assertEquals(random.SEEDBYTES, 32);
  }
});

Deno.test({
  name: "new random.Seed() instantiates a random 32-byte seed",
  fn(): void {
    const seed: random.Seed = new random.Seed();

    assertEquals(seed.bufferview.byteLength, random.SEEDBYTES);

    assert(seed.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "random.buf(out_len) returns a random out_len-byte array",
  fn(): void {
    const n: number = 5;

    const buf: Uint8Array = random.buf(n);

    assertEquals(buf.byteLength, n);

    assert(buf.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "random.buf_into(out) fills out with random bytes",
  fn(): void {
    const buf: Uint8Array = new Uint8Array(7);

    random.buf_into(buf);

    assert(buf.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name:
    "random.buf_deterministic(out_len, seed) returns a d-random out_len-byte array",
  fn(): void {
    const out_len: number = 5;

    const seed: random.Seed = new random.Seed();

    const buf: Uint8Array = random.buf_deterministic(out_len, seed);

    assertEquals(buf.byteLength, out_len);

    assert(buf.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name:
    "random.buf_deterministic_into(out, seed) fills out with d-random bytes",
  fn(): void {
    const buf: Uint8Array = new Uint8Array(7);

    const seed: random.Seed = new random.Seed();

    random.buf_deterministic_into(buf, seed);

    assert(buf.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "random.ratchet()",
  fn(): void {
    random.ratchet();
  }
});

Deno.test({
  name: "random.reseed()",
  fn(): void {
    random.reseed();
  }
});

Deno.test({
  name: "random.u32()",
  fn(): void {
    assertEquals(typeof random.u32(), "number");
  }
});

Deno.test({
  name: "random.uniform(upper_bound)",
  fn(): void {
    const upper_bound: number = 419;

    const hydrated: number = random.uniform(upper_bound);

    assertEquals(typeof hydrated, "number");
    assert(hydrated < upper_bound);
  }
});
