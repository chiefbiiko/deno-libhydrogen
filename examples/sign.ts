import { sign } from "./../mod.ts";

const context: sign.Context = sign.Context.create("example\0");
const keypair: sign.KeyPair = sign.KeyPair.gen();

/// single-part signature example

const msg: Uint8Array = Uint8Array.from([65, 67, 65, 66]);

const sig: sign.Signature = sign.create(msg, context, keypair.secret_key);

sign.verify(sig, msg, context, keypair.public_key);

/// multi-part signature example

const msg_part1: Uint8Array = Uint8Array.from([0, 4, 1, 9]);
const msg_part2: Uint8Array = Uint8Array.from([67, 65, 83, 72]);

const signature: sign.Signature = sign.init(context)
  .update(msg_part1)
  .update(msg_part2)
  .finish_create(keypair.secret_key);

sign.init(context)
  .update(msg_part1)
  .update(msg_part2)
  .finish_verify(signature, keypair.public_key);
