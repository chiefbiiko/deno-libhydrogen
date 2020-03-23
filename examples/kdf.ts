import { kdf } from "./../mod.ts";

const context: kdf.Context = new kdf.Context("examples");
const master_key: kdf.Key = kdf.Key.gen();

const subkey1: Uint8Array = kdf.derive_from_key(32, 1n, context, master_key);
const subkey2: Uint8Array = kdf.derive_from_key(32, 2n, context, master_key);
const subkey3: Uint8Array = kdf.derive_from_key(64, 3n, context, master_key);
