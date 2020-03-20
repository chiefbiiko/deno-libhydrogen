import { assert, assertEquals, assertThrows } from "./deps.ts";
import { errors,secretbox } from "./../lib.ts";

    const CONTEXT: secretbox.Context = new secretbox.Context(Uint8Array.from([0x68, 0x61, 0x73, 0x68, 0x74, 0x65, 0x73, 0x74]));
const INPUT: Uint8Array = new Uint8Array([0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f,0x64,0x65,0x6e, 0x6f])
const KEY: secretbox.Key = new secretbox.Key();

Deno.test({
  name: "secretbox.CONTEXTBYTES",
  fn(): void {
    assertEquals(typeof secretbox.CONTEXTBYTES, "number");
    assertEquals(secretbox.CONTEXTBYTES, 8);
  }
});

Deno.test({
  name: "secretbox.HEADERBYTES",
  fn(): void {
    assertEquals(typeof secretbox.HEADERBYTES, "number");
    assertEquals(secretbox.HEADERBYTES, 36);
  }
});

Deno.test({
  name: "secretbox.KEYBYTES",
  fn(): void {
    assertEquals(typeof secretbox.KEYBYTES, "number");
    assertEquals(secretbox.KEYBYTES, 32);
  }
});

Deno.test({
  name: "secretbox.PROBEBYTES",
  fn(): void {
    assertEquals(typeof secretbox.PROBEBYTES, "number");
    assertEquals(secretbox.PROBEBYTES, 16);
  }
});

Deno.test({
  name: "new secretbox.Context() instantiates an 8-byte context",
  fn(): void {
    const key:secretbox.Key = new secretbox.Key();

    assertEquals(key.bufferview.byteLength, secretbox.KEYBYTES);

    assert(key.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "new secretbox.Key() instantiates a 32-byte key",
  fn(): void {
    const key:secretbox.Key = new secretbox.Key();

    assertEquals(key.bufferview.byteLength, secretbox.KEYBYTES);

    assert(key.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "new secretbox.Probe() instantiates a 16-byte probe",
  fn(): void {
    const probe:secretbox.Probe = new secretbox.Probe(INPUT, CONTEXT, KEY);

    assertEquals(probe.bufferview.byteLength, secretbox.PROBEBYTES);

    assert(probe.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "secretbox.Probe.create() creates a 16-byte probe",
  fn(): void {
    const probe:secretbox.Probe = secretbox.Probe.create(INPUT, CONTEXT, KEY);

    assertEquals(probe.bufferview.byteLength, secretbox.PROBEBYTES);

    assert(probe.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "secretbox.Probe#verify(input, context, key) verifies",
  fn(): void {
    const probe:secretbox.Probe = new secretbox.Probe(INPUT, CONTEXT, KEY);

    probe.verify(INPUT, CONTEXT, KEY)

    assertEquals(probe.bufferview.byteLength, secretbox.PROBEBYTES);

    assert(probe.bufferview.some((byte: number): boolean => byte !== 0));
  }
});

Deno.test({
  name: "secretbox.Probe#verify(input, context, key) throws if args are invalid",
  fn(): void {
    const probe:secretbox.Probe = new secretbox.Probe(INPUT, CONTEXT, KEY);

    assertThrows(() =>{
probe.verify(INPUT, CONTEXT, new secretbox.Key()),
errors.HydroError,
"plugin op failed"
    })
  }
});

Deno.test({
  name: "secretbox.decrypt|encrypt(input, msg_id, context, key)",
  fn(): void {
   const ciphertext: Uint8Array = secretbox.encrypt(INPUT, 2n, CONTEXT, KEY);

    const plaintext: Uint8Array = secretbox.decrypt(ciphertext, 2n, CONTEXT, KEY);

   assertEquals(plaintext, INPUT)
  }
});

Deno.test({
  name: "secretbox.decrypt(input, msg_id, context, key) throws if input.byteLength is lt 36",
  fn(): void {
    assertThrows(() =>{
secretbox.decrypt(INPUT.slice(0, 35), 2n, CONTEXT, KEY),
errors.HydroError,
"plugin op failed"
    })
  }
});