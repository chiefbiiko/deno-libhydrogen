// deno plugin 2 libhydrogen

#[macro_use]
extern crate lazy_static;

use deno_core;
use libhydrogen;

macro_rules! hydro_op_success_dummy {
    () => {
        deno_core::CoreOp::Sync(Box::new([0u8; 1]))
    };
}

macro_rules! hydro_op_failure {
    () => {
        deno_core::CoreOp::Sync(vec![].into_boxed_slice())
    };
}

fn u8_8(bytes: &[u8]) -> [u8; 8] {
    let mut array: [u8; 8] = [0u8; 8];
    array.copy_from_slice(&bytes[..8]);
    array
}

fn u8_16(bytes: &[u8]) -> [u8; 16] {
    let mut array: [u8; 16] = [0u8; 16];
    array.copy_from_slice(&bytes[..16]);
    array
}

fn u8_32(bytes: &[u8]) -> [u8; 32] {
    let mut array: [u8; 32] = [0u8; 32];
    array.copy_from_slice(&bytes[..32]);
    array
}

fn u8_64(bytes: &[u8]) -> [u8; 64] {
    let mut array: [u8; 64] = [0u8; 64];
    array.copy_from_slice(&bytes[..64]);
    array
}

// TODO: impl this without the macro
// TODO: make sure these get zeroed on drop!!!
lazy_static! {
    static ref DEFAULT_HASHERS: std::sync::Mutex<std::collections::HashMap<u32, libhydrogen::hash::DefaultHasher>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
    static ref SIGNS: std::sync::Mutex<std::collections::HashMap<u32, libhydrogen::sign::Sign>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
}

#[no_mangle]
pub fn deno_plugin_init(context: &mut dyn deno_core::PluginInitContext) {
    libhydrogen::init().unwrap();

    context.register_op("random_buf", Box::new(op_random_buf));
    context.register_op("random_buf_into", Box::new(op_random_buf_into));
    context.register_op(
        "random_buf_deterministic",
        Box::new(op_random_buf_deterministic),
    );
    context.register_op(
        "random_buf_deterministic_into",
        Box::new(op_random_buf_deterministic_into),
    );
    context.register_op("random_ratchet", Box::new(op_random_ratchet));
    context.register_op("random_reseed", Box::new(op_random_reseed));
    context.register_op("random_u32", Box::new(op_random_u32));
    context.register_op("random_uniform", Box::new(op_random_uniform));
    context.register_op("hash_key_gen", Box::new(op_hash_key_gen));
    context.register_op("hash_init", Box::new(op_hash_init));
    context.register_op(
        "hash_defaulthasher_update",
        Box::new(op_hash_defaulthasher_update),
    );
    context.register_op(
        "hash_defaulthasher_finish_into",
        Box::new(op_hash_defaulthasher_finish_into),
    );
    context.register_op(
        "hash_defaulthasher_finish",
        Box::new(op_hash_defaulthasher_finish),
    );
    context.register_op("hash_hash", Box::new(op_hash_hash));
    context.register_op("hash_hash_into", Box::new(op_hash_hash_into));
    context.register_op("kdf_key_gen", Box::new(op_kdf_key_gen));
    context.register_op("kdf_derive_from_key", Box::new(op_kdf_derive_from_key));
    context.register_op("secretbox_key_gen", Box::new(op_secretbox_key_gen));
    context.register_op(
        "secretbox_probe_create",
        Box::new(op_secretbox_probe_create),
    );
    context.register_op(
        "secretbox_probe_verify",
        Box::new(op_secretbox_probe_verify),
    );
    context.register_op("secretbox_decrypt", Box::new(op_secretbox_decrypt));
    context.register_op("secretbox_encrypt", Box::new(op_secretbox_encrypt));
    context.register_op("sign_keypair_gen", Box::new(op_sign_keypair_gen));
    context.register_op("sign_init", Box::new(op_sign_init));
    context.register_op("sign_sign_update", Box::new(op_sign_sign_update));
    context.register_op(
        "sign_sign_finish_create",
        Box::new(op_sign_sign_finish_create),
    );
    context.register_op(
        "sign_sign_finish_verify",
        Box::new(op_sign_sign_finish_verify),
    );
    context.register_op("sign_create", Box::new(op_sign_create));
    context.register_op("sign_verify", Box::new(op_sign_verify));
    context.register_op("utils_bin2hex", Box::new(op_utils_bin2hex));
    context.register_op("utils_hex2bin", Box::new(op_utils_hex2bin));
    context.register_op("utils_increment", Box::new(op_utils_increment));
    context.register_op("utils_compare", Box::new(op_utils_compare));
    context.register_op("utils_equal", Box::new(op_utils_equal));
    context.register_op("utils_pad", Box::new(op_utils_pad));
    context.register_op("utils_unpad", Box::new(op_utils_unpad));
}

pub fn op_random_buf(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..2] is reserved for random::buf's outlen arg
    let out_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);

    let buf: Vec<u8> = libhydrogen::random::buf(out_len as usize);

    libhydrogen::utils::memzero(&mut control);

    deno_core::CoreOp::Sync(buf.into_boxed_slice())
}

pub fn op_random_buf_deterministic(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let out_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);

    let seed: libhydrogen::random::Seed =
        libhydrogen::random::Seed::from(u8_32(&control[2..2 + libhydrogen::random::SEEDBYTES]));

    let buf: Vec<u8> = libhydrogen::random::buf_deterministic(out_len as usize, &seed);

    libhydrogen::utils::memzero(&mut control);

    deno_core::CoreOp::Sync(buf.into_boxed_slice())
}

pub fn op_random_buf_deterministic_into(
    mut control: &[u8],
    mut zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(out) = zero_copy.as_mut() {
        // control consists solely of the seed bytes
        let seed: libhydrogen::random::Seed = libhydrogen::random::Seed::from(u8_32(control));

        libhydrogen::utils::memzero(&mut control);

        libhydrogen::random::buf_deterministic_into(out, &seed);

        hydro_op_success_dummy!()
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_random_buf_into(
    _control: &[u8],
    mut zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(out) = zero_copy.as_mut() {
        libhydrogen::random::buf_into(out);

        hydro_op_success_dummy!()
    } else {
        hydro_op_failure!()
    }
}

pub fn op_random_ratchet(
    _control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    libhydrogen::random::ratchet();

    hydro_op_success_dummy!()
}

pub fn op_random_reseed(
    _control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    libhydrogen::random::reseed();

    hydro_op_success_dummy!()
}

pub fn op_random_u32(
    _control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let four_be_bytes: [u8; 4] = libhydrogen::random::u32().to_be_bytes();

    deno_core::CoreOp::Sync(Box::new(four_be_bytes))
}

pub fn op_random_uniform(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..4] is reserved for random::uniform's upper_bound arg
    let upper_bound: u32 = (control[0] as u32) << 24
        | (control[1] as u32) << 16
        | (control[2] as u32) << 8
        | (control[3] as u32);

    libhydrogen::utils::memzero(&mut control);

    let four_be_bytes: [u8; 4] = libhydrogen::random::uniform(upper_bound).to_be_bytes();

    deno_core::CoreOp::Sync(Box::new(four_be_bytes))
}

pub fn op_hash_key_gen(
    _control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let key: [u8; libhydrogen::hash::KEYBYTES] = libhydrogen::hash::Key::gen().into();

    deno_core::CoreOp::Sync(Box::new(key))
}

pub fn op_hash_init(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let id: u32 = libhydrogen::random::u32();

    // control[0..32] is reserved for hash::init's key arg
    let key: libhydrogen::hash::Key =
        libhydrogen::hash::Key::from(u8_32(&control[0..libhydrogen::hash::KEYBYTES]));

    // control[32..40] is reserved for hash::init's context arg
    let context: libhydrogen::hash::Context = libhydrogen::hash::Context::from(u8_8(
        &control[libhydrogen::hash::KEYBYTES
            ..(libhydrogen::hash::KEYBYTES + libhydrogen::hash::CONTEXTBYTES)],
    ));

    libhydrogen::utils::memzero(&mut control);

    let default_hasher: libhydrogen::hash::DefaultHasher = libhydrogen::hash::init(&context, &key);

    match DEFAULT_HASHERS.lock() {
        Ok(mut map) => {
            map.insert(id, default_hasher);

            deno_core::CoreOp::Sync(Box::new(id.to_be_bytes()))
        }
        Err(_) => hydro_op_failure!(),
    }
}

pub fn op_hash_defaulthasher_update(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..4] is reserved for the hash instance id
        let id: u32 = (control[0] as u32) << 24
            | (control[1] as u32) << 16
            | (control[2] as u32) << 8
            | (control[3] as u32);

        libhydrogen::utils::memzero(&mut control);

        match DEFAULT_HASHERS.lock() {
            Ok(mut map) => {
                if let Some(default_hasher) = map.get_mut(&id) {
                    default_hasher.update(input);

                    hydro_op_success_dummy!()
                } else {
                    hydro_op_failure!()
                }
            }
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_hash_defaulthasher_finish_into(
    mut control: &[u8],
    mut zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(out) = zero_copy.as_mut() {
        // control[0..4] is reserved for the hash instance id
        let id: u32 = (control[0] as u32) << 24
            | (control[1] as u32) << 16
            | (control[2] as u32) << 8
            | (control[3] as u32);

        libhydrogen::utils::memzero(&mut control);

        match DEFAULT_HASHERS.lock() {
            Ok(mut map) => {
                if let Some(default_hasher) = map.remove(&id) {
                    match default_hasher.finish_into(out) {
                        Ok(()) => hydro_op_success_dummy!(),
                        Err(_) => hydro_op_failure!(),
                    }
                } else {
                    hydro_op_failure!()
                }
            }
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_hash_defaulthasher_finish(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..4] is reserved for the hash instance id
    let id: u32 = (control[0] as u32) << 24
        | (control[1] as u32) << 16
        | (control[2] as u32) << 8
        | (control[3] as u32);

    // control[4..6] is reserved for hash::DefaultHasher::finish's outlen arg
    let out_len: u16 = (control[4] as u16) << 8 | (control[5] as u16);

    libhydrogen::utils::memzero(&mut control);

    match DEFAULT_HASHERS.lock() {
        Ok(mut map) => {
            if let Some(default_hasher) = map.remove(&id) {
                match default_hasher.finish(out_len as usize) {
                    Ok(digest) => deno_core::CoreOp::Sync(digest.into_boxed_slice()),
                    Err(_) => hydro_op_failure!(),
                }
            } else {
                hydro_op_failure!()
            }
        }
        Err(_) => hydro_op_failure!(),
    }
}

pub fn op_hash_hash(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..2] is reserved for hash::hash's outlen arg
        let out_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);

        // control[2..34] is reserved for hash::hash's key arg
        let key: libhydrogen::hash::Key =
            libhydrogen::hash::Key::from(u8_32(&control[2..2 + libhydrogen::hash::KEYBYTES]));

        // control[34..42] is reserved for hash::hash's context arg
        let context: libhydrogen::hash::Context = libhydrogen::hash::Context::from(u8_8(
            &control[2 + libhydrogen::hash::KEYBYTES
                ..2 + libhydrogen::hash::KEYBYTES + libhydrogen::hash::CONTEXTBYTES],
        ));

        libhydrogen::utils::memzero(&mut control);

        match libhydrogen::hash::hash(out_len as usize, input, &context, &key) {
            Ok(digest) => deno_core::CoreOp::Sync(digest.into_boxed_slice()),
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_hash_hash_into(
    mut control: &[u8],
    mut zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(out) = zero_copy.as_mut() {
        // control[0..32] is reserved for hash::hash's key arg
        let key: libhydrogen::hash::Key =
            libhydrogen::hash::Key::from(u8_32(&control[0..libhydrogen::hash::KEYBYTES]));

        // control[32..40] is reserved for hash::hash's context arg
        let context: libhydrogen::hash::Context = libhydrogen::hash::Context::from(u8_8(
            &control[libhydrogen::hash::KEYBYTES
                ..libhydrogen::hash::KEYBYTES + libhydrogen::hash::CONTEXTBYTES],
        ));

        match libhydrogen::hash::hash_into(
            out,
            &control[libhydrogen::hash::KEYBYTES + libhydrogen::hash::CONTEXTBYTES..],
            &context,
            &key,
        ) {
            Ok(()) => {
                libhydrogen::utils::memzero(&mut control);

                hydro_op_success_dummy!()
            }
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_kdf_key_gen(
    _control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let key: [u8; libhydrogen::kdf::KEYBYTES] = libhydrogen::kdf::Key::gen().into();

    deno_core::CoreOp::Sync(Box::new(key))
}

pub fn op_kdf_derive_from_key(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..32] is reserved for kdf::derive_from_key's key arg
    let key: libhydrogen::kdf::Key =
        libhydrogen::kdf::Key::from(u8_32(&control[0..libhydrogen::kdf::KEYBYTES]));

    // control[32..40] is reserved for kdf::derive_from_key's context arg
    let context: libhydrogen::kdf::Context = libhydrogen::kdf::Context::from(u8_8(
        &control[libhydrogen::kdf::KEYBYTES
            ..libhydrogen::kdf::KEYBYTES + libhydrogen::kdf::CONTEXTBYTES],
    ));

    // control[40..42] is reserved for kdf::derive_from_key's subkey_len arg
    let subkey_len: u16 = (control[40] as u16) << 8 | (control[41] as u16);

    // control[42..50] is reserved for kdf::derive_from_key's subkey_id arg
    let subkey_id: u64 = (control[42] as u64) << 56
        | (control[43] as u64) << 48
        | (control[44] as u64) << 40
        | (control[45] as u64) << 32
        | (control[46] as u64) << 24
        | (control[47] as u64) << 16
        | (control[48] as u64) << 8
        | (control[49] as u64);

    libhydrogen::utils::memzero(&mut control);

    match libhydrogen::kdf::derive_from_key(subkey_len as usize, subkey_id, &context, &key) {
        Ok(subkey) => deno_core::CoreOp::Sync(subkey.into_boxed_slice()),
        Err(_) => hydro_op_failure!(),
    }
}

pub fn op_secretbox_key_gen(
    _control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let key: [u8; libhydrogen::secretbox::KEYBYTES] = libhydrogen::secretbox::Key::gen().into();

    deno_core::CoreOp::Sync(Box::new(key))
}

pub fn op_secretbox_probe_create(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..32] is reserved for hash::hash's key arg
        let key: libhydrogen::secretbox::Key =
            libhydrogen::secretbox::Key::from(u8_32(&control[0..libhydrogen::secretbox::KEYBYTES]));

        // control[32..40] is reserved for hash::hash's context arg
        let context: libhydrogen::secretbox::Context = libhydrogen::secretbox::Context::from(u8_8(
            &control[libhydrogen::secretbox::KEYBYTES
                ..libhydrogen::secretbox::KEYBYTES + libhydrogen::secretbox::CONTEXTBYTES],
        ));

        libhydrogen::utils::memzero(&mut control);

        let probe_bytes: [u8; libhydrogen::secretbox::PROBEBYTES] =
            libhydrogen::secretbox::Probe::create(input, &context, &key).into();

        deno_core::CoreOp::Sync(Box::new(probe_bytes))
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_secretbox_probe_verify(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        let probe: libhydrogen::secretbox::Probe = libhydrogen::secretbox::Probe::from(u8_16(
            &control[0..libhydrogen::secretbox::PROBEBYTES],
        ));

        // control[0..32] is reserved for hash::hash's key arg
        let key: libhydrogen::secretbox::Key = libhydrogen::secretbox::Key::from(u8_32(
            &control[libhydrogen::secretbox::PROBEBYTES
                ..libhydrogen::secretbox::PROBEBYTES + libhydrogen::secretbox::KEYBYTES],
        ));

        // control[32..40] is reserved for hash::hash's context arg
        let context: libhydrogen::secretbox::Context = libhydrogen::secretbox::Context::from(u8_8(
            &control[libhydrogen::secretbox::PROBEBYTES + libhydrogen::secretbox::KEYBYTES
                ..libhydrogen::secretbox::PROBEBYTES
                    + libhydrogen::secretbox::KEYBYTES
                    + libhydrogen::secretbox::CONTEXTBYTES],
        ));

        libhydrogen::utils::memzero(&mut control);

        match probe.verify(input, &context, &key) {
            Ok(()) => hydro_op_success_dummy!(),
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_secretbox_decrypt(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..32] is reserved for kdf::derive_from_key's key arg
        let key: libhydrogen::secretbox::Key =
            libhydrogen::secretbox::Key::from(u8_32(&control[0..libhydrogen::secretbox::KEYBYTES]));

        // control[32..40] is reserved for kdf::derive_from_key's context arg
        let context: libhydrogen::secretbox::Context = libhydrogen::secretbox::Context::from(u8_8(
            &control[libhydrogen::secretbox::KEYBYTES
                ..libhydrogen::secretbox::KEYBYTES + libhydrogen::secretbox::CONTEXTBYTES],
        ));

        // control[40..48] is reserved for secretbox::decrypt's msg_id arg
        let msg_id: u64 = (control[40] as u64) << 56
            | (control[41] as u64) << 48
            | (control[42] as u64) << 40
            | (control[43] as u64) << 32
            | (control[44] as u64) << 24
            | (control[45] as u64) << 16
            | (control[46] as u64) << 8
            | (control[47] as u64);

        libhydrogen::utils::memzero(&mut control);

        match libhydrogen::secretbox::decrypt(input, msg_id, &context, &key) {
            // NOTE: ts assured input.byteLength is gt 0 --- thus likewise plaintext
            Ok(plaintext) => deno_core::CoreOp::Sync(plaintext.into_boxed_slice()),
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_secretbox_encrypt(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..32] is reserved for kdf::derive_from_key's key arg
        let key: libhydrogen::secretbox::Key =
            libhydrogen::secretbox::Key::from(u8_32(&control[0..libhydrogen::secretbox::KEYBYTES]));

        // control[32..40] is reserved for kdf::derive_from_key's context arg
        let context: libhydrogen::secretbox::Context = libhydrogen::secretbox::Context::from(u8_8(
            &control[libhydrogen::secretbox::KEYBYTES
                ..libhydrogen::secretbox::KEYBYTES + libhydrogen::secretbox::CONTEXTBYTES],
        ));

        // control[40..48] is reserved for secretbox::decrypt's msg_id arg
        let msg_id: u64 = (control[40] as u64) << 56
            | (control[41] as u64) << 48
            | (control[42] as u64) << 40
            | (control[43] as u64) << 32
            | (control[44] as u64) << 24
            | (control[45] as u64) << 16
            | (control[46] as u64) << 8
            | (control[47] as u64);

        libhydrogen::utils::memzero(&mut control);

        let ciphertext: Vec<u8> = libhydrogen::secretbox::encrypt(input, msg_id, &context, &key);

        // NOTE: ts assured input.byteLength is gt 0 --- thus likewise ciphertext
        deno_core::CoreOp::Sync(ciphertext.into_boxed_slice())
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_sign_keypair_gen(
    _control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let keypair: libhydrogen::sign::KeyPair = libhydrogen::sign::KeyPair::gen();

    let mut keys: Vec<u8> = keypair.public_key.as_ref().to_vec();

    keys.extend_from_slice(keypair.secret_key.as_ref());

    deno_core::CoreOp::Sync(keys.into_boxed_slice())
}

pub fn op_sign_init(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let id: u32 = libhydrogen::random::u32();

    // control entirely consists of sign::init's context arg
    let context: libhydrogen::sign::Context = libhydrogen::sign::Context::from(u8_8(control));

    libhydrogen::utils::memzero(&mut control);

    let sign: libhydrogen::sign::Sign = libhydrogen::sign::init(&context);

    match SIGNS.lock() {
        Ok(mut map) => {
            map.insert(id, sign);

            deno_core::CoreOp::Sync(Box::new(id.to_be_bytes()))
        }
        Err(_) => hydro_op_failure!(),
    }
}

pub fn op_sign_sign_update(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..4] is reserved for the sign instance id
        let id: u32 = (control[0] as u32) << 24
            | (control[1] as u32) << 16
            | (control[2] as u32) << 8
            | (control[3] as u32);

        libhydrogen::utils::memzero(&mut control);

        match SIGNS.lock() {
            Ok(mut map) => {
                if let Some(sign) = map.get_mut(&id) {
                    sign.update(input);

                    hydro_op_success_dummy!()
                } else {
                    hydro_op_failure!()
                }
            }
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_sign_sign_finish_create(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..4] is reserved for the sign instance id
    let id: u32 = (control[0] as u32) << 24
        | (control[1] as u32) << 16
        | (control[2] as u32) << 8
        | (control[3] as u32);

    let secret_key: libhydrogen::sign::SecretKey = libhydrogen::sign::SecretKey::from(u8_64(
        &control[4..4 + libhydrogen::sign::SECRETKEYBYTES],
    ));

    libhydrogen::utils::memzero(&mut control);

    match SIGNS.lock() {
        Ok(mut map) => {
            if let Some(sign) = map.remove(&id) {
                match sign.finish_create(&secret_key) {
                    Ok(signature) => {
                        let signature_bytes: [u8; libhydrogen::sign::BYTES] = signature.into();

                        deno_core::CoreOp::Sync(Box::new(signature_bytes))
                    }
                    Err(_) => hydro_op_failure!(),
                }
            } else {
                hydro_op_failure!()
            }
        }
        Err(_) => hydro_op_failure!(),
    }
}

pub fn op_sign_sign_finish_verify(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..4] is reserved for the sign instance id
    let id: u32 = (control[0] as u32) << 24
        | (control[1] as u32) << 16
        | (control[2] as u32) << 8
        | (control[3] as u32);

    // control[4..68] is reserved for sign::Sign::finish_verify's signature arg
    let signature: libhydrogen::sign::Signature =
        libhydrogen::sign::Signature::from(u8_64(&control[4..4 + libhydrogen::sign::BYTES]));

    // control[68..100] is reserved for sign::Sign::finish_verify's public_key arg
    let public_key: libhydrogen::sign::PublicKey = libhydrogen::sign::PublicKey::from(u8_32(
        &control[4 + libhydrogen::sign::BYTES
            ..4 + libhydrogen::sign::BYTES + libhydrogen::sign::PUBLICKEYBYTES],
    ));

    libhydrogen::utils::memzero(&mut control);

    match SIGNS.lock() {
        Ok(mut map) => {
            if let Some(sign) = map.remove(&id) {
                match sign.finish_verify(&signature, &public_key) {
                    Ok(()) => hydro_op_success_dummy!(),
                    Err(_) => hydro_op_failure!(),
                }
            } else {
                hydro_op_failure!()
            }
        }
        Err(_) => hydro_op_failure!(),
    }
}

pub fn op_sign_create(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..64] is reserved for sign::create's key arg
        let secret_key: libhydrogen::sign::SecretKey = libhydrogen::sign::SecretKey::from(u8_64(
            &control[0..libhydrogen::sign::SECRETKEYBYTES],
        ));

        // control[64..72] is reserved for sign::create's context arg
        let context: libhydrogen::sign::Context = libhydrogen::sign::Context::from(u8_8(
            &control[libhydrogen::sign::SECRETKEYBYTES
                ..libhydrogen::sign::SECRETKEYBYTES + libhydrogen::sign::CONTEXTBYTES],
        ));

        libhydrogen::utils::memzero(&mut control);

        match libhydrogen::sign::create(input, &context, &secret_key) {
            Ok(signature) => {
                let signature_bytes: [u8; libhydrogen::sign::BYTES] = signature.into();

                deno_core::CoreOp::Sync(Box::new(signature_bytes))
            }
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_sign_verify(
    mut control: &[u8],
    zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(input) = zero_copy.as_ref() {
        // control[0..32] is reserved for hash::hash's key arg
        let public_key: libhydrogen::sign::PublicKey = libhydrogen::sign::PublicKey::from(u8_32(
            &control[0..libhydrogen::sign::PUBLICKEYBYTES],
        ));

        // control[32..40] is reserved for hash::hash's context arg
        let context: libhydrogen::sign::Context = libhydrogen::sign::Context::from(u8_8(
            &control[libhydrogen::sign::PUBLICKEYBYTES
                ..libhydrogen::sign::PUBLICKEYBYTES + libhydrogen::sign::CONTEXTBYTES],
        ));

        // control[40..104] is reserved for sign::verify's signature arg
        let signature: libhydrogen::sign::Signature = libhydrogen::sign::Signature::from(u8_64(
            &control[libhydrogen::sign::PUBLICKEYBYTES + libhydrogen::sign::CONTEXTBYTES
                ..libhydrogen::sign::PUBLICKEYBYTES
                    + libhydrogen::sign::CONTEXTBYTES
                    + libhydrogen::sign::BYTES],
        ));

        libhydrogen::utils::memzero(&mut control);

        match libhydrogen::sign::verify(&signature, input, &context, &public_key) {
            Ok(()) => hydro_op_success_dummy!(),
            Err(_) => hydro_op_failure!(),
        }
    } else {
        libhydrogen::utils::memzero(&mut control);

        hydro_op_failure!()
    }
}

pub fn op_utils_bin2hex(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control solely consists of the buffer to be converted to hex
    let hex: String = libhydrogen::utils::bin2hex(control);

    libhydrogen::utils::memzero(&mut control);

    deno_core::CoreOp::Sync(hex.into_bytes().into_boxed_slice())
}

pub fn op_utils_hex2bin(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..2] is reserved for passing hex's length
    let hex_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);

    // control[2..4] is reserved for passing ignore's length
    let ignore_len: u16 = (control[2] as u16) << 8 | (control[3] as u16);

    match std::str::from_utf8(&control[4..4 + (hex_len as usize)]) {
        Ok(str) => {
            let ignore: std::option::Option<&[u8]> = if ignore_len != 0 {
                Some(
                    &control
                        [4 + (hex_len as usize)..4 + (hex_len as usize) + (ignore_len as usize)],
                )
            } else {
                None
            };

            libhydrogen::utils::memzero(&mut control);

            match libhydrogen::utils::hex2bin(str, ignore) {
                Ok(bin) => deno_core::CoreOp::Sync(bin.into_boxed_slice()),
                Err(_) => hydro_op_failure!(),
            }
        }
        Err(_) => {
            libhydrogen::utils::memzero(&mut control);

            hydro_op_failure!()
        }
    }
}

pub fn op_utils_increment(
    _control: &[u8],
    mut zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    if let Some(buf) = zero_copy.as_mut() {
        libhydrogen::utils::increment(buf);

        hydro_op_success_dummy!()
    } else {
        hydro_op_failure!()
    }
}

pub fn op_utils_compare(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    let a_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);

    let b_len: u16 = (control[2] as u16) << 8 | (control[3] as u16);

    let ordering: core::cmp::Ordering = libhydrogen::utils::compare(
        &control[4..4 + (a_len as usize)],
        &control[4 + (a_len as usize)..4 + (a_len as usize) + (b_len as usize)],
    );

    libhydrogen::utils::memzero(&mut control);

    let ordering_byte: u8 = match ordering {
        core::cmp::Ordering::Less => 0,
        core::cmp::Ordering::Equal => 1,
        core::cmp::Ordering::Greater => 2,
    };

    deno_core::CoreOp::Sync(vec![ordering_byte].into_boxed_slice())
}

pub fn op_utils_equal(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..2] is reserved for passing a's length
    let a_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);

    // control[2..4] is reserved for passing b's length
    let b_len: u16 = (control[2] as u16) << 8 | (control[3] as u16);

    let equality: bool = libhydrogen::utils::equal(
        &control[4..4 + (a_len as usize)],
        &control[4 + (a_len as usize)..4 + (a_len as usize) + (b_len as usize)],
    );

    libhydrogen::utils::memzero(&mut control);

    let equality_byte: u8 = equality as u8;

    deno_core::CoreOp::Sync(vec![equality_byte].into_boxed_slice())
}

pub fn op_utils_pad(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..2] is reserved for passing the buf length
    let buf_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);
    // control[2..4] is reserved for passing utils::pad's blocksize arg
    let blocksize: u16 = (control[2] as u16) << 8 | (control[3] as u16);

    let mut buf: Vec<u8> = control[4..4 + (buf_len as usize)].to_vec();

    libhydrogen::utils::memzero(&mut control);

    libhydrogen::utils::pad(&mut buf, blocksize as usize);

    deno_core::CoreOp::Sync(buf.into_boxed_slice())
}

pub fn op_utils_unpad(
    mut control: &[u8],
    _zero_copy: Option<deno_core::ZeroCopyBuf>,
) -> deno_core::CoreOp {
    // control[0..2] is reserved for passing the buf length
    let buf_len: u16 = (control[0] as u16) << 8 | (control[1] as u16);
    // control[2..4] is reserved for passing utils::unpad's blocksize arg
    let blocksize: u16 = (control[2] as u16) << 8 | (control[3] as u16);

    let mut buf: Vec<u8> = control[4..(4 + (buf_len as usize))].to_vec();

    libhydrogen::utils::memzero(&mut control);

    match libhydrogen::utils::unpad(&mut buf, blocksize as usize) {
        Ok(()) => deno_core::CoreOp::Sync(buf.into_boxed_slice()),
        Err(_) => {
            libhydrogen::utils::memzero(&mut buf);

            hydro_op_failure!()
        }
    }
}
