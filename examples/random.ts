import { random } from "./../mod.ts";

const r: number = random.uniform(100);

const buf: Uint8Array = random.buf(r + 1);
