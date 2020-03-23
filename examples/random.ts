import { random } from "./../mod.ts";

let u32: number = random.uniform(100);

const buf: Uint8Array = random.buf(u32 + 1);
