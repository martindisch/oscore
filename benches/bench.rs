use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use oscore::edhoc::{PartyI, PartyR};
use oscore::oscore::SecurityContext;

// EDHOC ----------------------------------------------------------------------

const AUTH_U_PRIVATE: [u8; 32] = [
    0x53, 0x21, 0xFC, 0x01, 0xC2, 0x98, 0x20, 0x06, 0x3A, 0x72, 0x50, 0x8F,
    0xC6, 0x39, 0x25, 0x1D, 0xC8, 0x30, 0xE2, 0xF7, 0x68, 0x3E, 0xB8, 0xE3,
    0x8A, 0xF1, 0x64, 0xA5, 0xB9, 0xAF, 0x9B, 0xE3,
];
const AUTH_U_PUBLIC: [u8; 32] = [
    0x42, 0x4C, 0x75, 0x6A, 0xB7, 0x7C, 0xC6, 0xFD, 0xEC, 0xF0, 0xB3, 0xEC,
    0xFC, 0xFF, 0xB7, 0x53, 0x10, 0xC0, 0x15, 0xBF, 0x5C, 0xBA, 0x2E, 0xC0,
    0xA2, 0x36, 0xE6, 0x65, 0x0C, 0x8A, 0xB9, 0xC7,
];
const KID_U: [u8; 1] = [0xA2];
const AUTH_V_PRIVATE: [u8; 32] = [
    0x74, 0x56, 0xB3, 0xA3, 0xE5, 0x8D, 0x8D, 0x26, 0xDD, 0x36, 0xBC, 0x75,
    0xD5, 0x5B, 0x88, 0x63, 0xA8, 0x5D, 0x34, 0x72, 0xF4, 0xA0, 0x1F, 0x02,
    0x24, 0x62, 0x1B, 0x1C, 0xB8, 0x16, 0x6D, 0xA9,
];
const AUTH_V_PUBLIC: [u8; 32] = [
    0x1B, 0x66, 0x1E, 0xE5, 0xD5, 0xEF, 0x16, 0x72, 0xA2, 0xD8, 0x77, 0xCD,
    0x5B, 0xC2, 0x0F, 0x46, 0x30, 0xDC, 0x78, 0xA1, 0x14, 0xDE, 0x65, 0x9C,
    0x7E, 0x50, 0x4D, 0x0F, 0x52, 0x9A, 0x6B, 0xD3,
];
const KID_V: [u8; 1] = [0xA3];

const TYPE: isize = 1;
const EPH_U_PRIVATE: [u8; 32] = [
    0xD4, 0xD8, 0x1A, 0xBA, 0xFA, 0xD9, 0x08, 0xA0, 0xCC, 0xEF, 0xEF, 0x5A,
    0xD6, 0xB0, 0x5D, 0x50, 0x27, 0x02, 0xF1, 0xC1, 0x6F, 0x23, 0x2C, 0x25,
    0x92, 0x93, 0x09, 0xAC, 0x44, 0x1B, 0x95, 0x8E,
];
const C_U: [u8; 1] = [0xC3];
const MESSAGE_1: [u8; 38] = [
    0x01, 0x00, 0x58, 0x20, 0xB1, 0xA3, 0xE8, 0x94, 0x60, 0xE8, 0x8D, 0x3A,
    0x8D, 0x54, 0x21, 0x1D, 0xC9, 0x5F, 0x0B, 0x90, 0x3F, 0xF2, 0x05, 0xEB,
    0x71, 0x91, 0x2D, 0x6D, 0xB8, 0xF4, 0xAF, 0x98, 0x0D, 0x2D, 0xB8, 0x3A,
    0x41, 0xC3,
];

const EPH_V_PRIVATE: [u8; 32] = [
    0x17, 0xCD, 0xC7, 0xBC, 0xA3, 0xF2, 0xA0, 0xBD, 0xA6, 0x0C, 0x6D, 0xE5,
    0xB9, 0x6F, 0x82, 0xA3, 0x62, 0x39, 0xB4, 0x4B, 0xDE, 0x39, 0x7A, 0x38,
    0x62, 0xD5, 0x29, 0xBA, 0x8B, 0x3D, 0x7C, 0x62,
];
const C_V: [u8; 1] = [0xC4];
const MESSAGE_2: [u8; 114] = [
    0x58, 0x20, 0x8D, 0xB5, 0x77, 0xF9, 0xB9, 0xC2, 0x74, 0x47, 0x98, 0x98,
    0x7D, 0xB5, 0x57, 0xBF, 0x31, 0xCA, 0x48, 0xAC, 0xD2, 0x05, 0xA9, 0xDB,
    0x8C, 0x32, 0x0E, 0x5D, 0x49, 0xF3, 0x02, 0xA9, 0x64, 0x74, 0x41, 0xC4,
    0x58, 0x4C, 0x1E, 0x6B, 0xFE, 0x0E, 0x77, 0x99, 0xCE, 0xF0, 0x66, 0xA3,
    0x4F, 0x08, 0xEF, 0xAA, 0x90, 0x00, 0x6D, 0xB4, 0x4C, 0x90, 0x1C, 0xF7,
    0x9B, 0x23, 0x85, 0x3A, 0xB9, 0x7F, 0xD8, 0xDB, 0xC8, 0x53, 0x39, 0xD5,
    0xED, 0x80, 0x87, 0x78, 0x3C, 0xF7, 0xA4, 0xA7, 0xE0, 0xEA, 0x38, 0xC2,
    0x21, 0x78, 0x9F, 0xA3, 0x71, 0xBE, 0x64, 0xE9, 0x3C, 0x43, 0xA7, 0xDB,
    0x47, 0xD1, 0xE3, 0xFB, 0x14, 0x78, 0x8E, 0x96, 0x7F, 0xDD, 0x78, 0xD8,
    0x80, 0x78, 0xE4, 0x9B, 0x78, 0xBF,
];
const MESSAGE_3: [u8; 80] = [
    0x41, 0xC4, 0x58, 0x4C, 0xDE, 0x4A, 0x83, 0x3D, 0x48, 0xB6, 0x64, 0x74,
    0x14, 0x2C, 0xC9, 0xBD, 0xCE, 0x87, 0xD9, 0x3A, 0xF8, 0x35, 0x57, 0x9C,
    0x2D, 0xBF, 0x1B, 0x9E, 0x2F, 0xB4, 0xDC, 0x66, 0x60, 0x0D, 0xBA, 0xC6,
    0xBB, 0x3C, 0xC0, 0x5C, 0x29, 0x0E, 0xF3, 0x5D, 0x51, 0x5B, 0x4D, 0x7D,
    0x64, 0x83, 0xF5, 0x09, 0x61, 0x43, 0xB5, 0x56, 0x44, 0xCF, 0xAF, 0xD1,
    0xFF, 0xAA, 0x7F, 0x2B, 0xA3, 0x86, 0x36, 0x57, 0x83, 0x1D, 0xD2, 0xE5,
    0xBD, 0x04, 0x04, 0x38, 0x60, 0x14, 0x0D, 0xC8,
];

fn edhoc_detailed(c: &mut Criterion) {
    let mut group = c.benchmark_group("edhoc_detailed");

    group.bench_function("party_u_build", |b| {
        b.iter(|| {
            PartyI::new(
                C_U.to_vec(),
                EPH_U_PRIVATE,
                &AUTH_U_PRIVATE,
                &AUTH_U_PUBLIC,
                KID_U.to_vec(),
            )
        })
    });

    group.bench_function("msg1_generate", |b| {
        b.iter_batched(
            || {
                PartyI::new(
                    C_U.to_vec(),
                    EPH_U_PRIVATE,
                    &AUTH_U_PRIVATE,
                    &AUTH_U_PUBLIC,
                    KID_U.to_vec(),
                )
            },
            |msg1_sender| msg1_sender.generate_message_1(TYPE).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("party_v_build", |b| {
        b.iter(|| {
            PartyR::new(
                C_V.to_vec(),
                EPH_V_PRIVATE,
                &AUTH_V_PRIVATE,
                &AUTH_V_PUBLIC,
                KID_V.to_vec(),
            )
        })
    });

    group.bench_function("msg1_handle", |b| {
        b.iter_batched(
            || {
                (
                    MESSAGE_1.to_vec(),
                    PartyR::new(
                        C_V.to_vec(),
                        EPH_V_PRIVATE,
                        &AUTH_V_PRIVATE,
                        &AUTH_V_PUBLIC,
                        KID_V.to_vec(),
                    ),
                )
            },
            |(msg1_bytes, msg1_receiver)| {
                msg1_receiver.handle_message_1(msg1_bytes).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg2_generate", |b| {
        b.iter_batched(
            || {
                let msg1_receiver = PartyR::new(
                    C_V.to_vec(),
                    EPH_V_PRIVATE,
                    &AUTH_V_PRIVATE,
                    &AUTH_V_PUBLIC,
                    KID_V.to_vec(),
                );
                msg1_receiver.handle_message_1(MESSAGE_1.to_vec()).unwrap()
            },
            |msg2_sender| msg2_sender.generate_message_2().unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg2_extract", |b| {
        b.iter_batched(
            || {
                let msg1_sender = PartyI::new(
                    C_U.to_vec(),
                    EPH_U_PRIVATE,
                    &AUTH_U_PRIVATE,
                    &AUTH_U_PUBLIC,
                    KID_U.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(TYPE).unwrap();
                (MESSAGE_2.to_vec(), msg2_receiver)
            },
            |(msg2_bytes, msg2_receiver)| {
                msg2_receiver.extract_peer_kid(msg2_bytes).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg2_verify", |b| {
        b.iter_batched(
            || {
                let msg1_sender = PartyI::new(
                    C_U.to_vec(),
                    EPH_U_PRIVATE,
                    &AUTH_U_PRIVATE,
                    &AUTH_U_PUBLIC,
                    KID_U.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(TYPE).unwrap();
                let (_, msg2_verifier) = msg2_receiver
                    .extract_peer_kid(MESSAGE_2.to_vec())
                    .unwrap();
                msg2_verifier
            },
            |msg2_verifier| {
                msg2_verifier.verify_message_2(&AUTH_V_PUBLIC).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg3_generate", |b| {
        b.iter_batched(
            || {
                let msg1_sender = PartyI::new(
                    C_U.to_vec(),
                    EPH_U_PRIVATE,
                    &AUTH_U_PRIVATE,
                    &AUTH_U_PUBLIC,
                    KID_U.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(TYPE).unwrap();
                let (_v_kid, msg2_verifier) = msg2_receiver
                    .extract_peer_kid(MESSAGE_2.to_vec())
                    .unwrap();
                msg2_verifier.verify_message_2(&AUTH_V_PUBLIC).unwrap()
            },
            |msg3_sender| msg3_sender.generate_message_3().unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg3_extract", |b| {
        b.iter_batched(
            || {
                let msg1_receiver = PartyR::new(
                    C_V.to_vec(),
                    EPH_V_PRIVATE,
                    &AUTH_V_PRIVATE,
                    &AUTH_V_PUBLIC,
                    KID_V.to_vec(),
                );
                let msg2_sender = msg1_receiver
                    .handle_message_1(MESSAGE_1.to_vec())
                    .unwrap();
                let (_, msg3_receiver) =
                    msg2_sender.generate_message_2().unwrap();
                (MESSAGE_3.to_vec(), msg3_receiver)
            },
            |(msg3_bytes, msg3_receiver)| {
                msg3_receiver.extract_peer_kid(msg3_bytes).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("msg3_verify", |b| {
        b.iter_batched(
            || {
                let msg1_receiver = PartyR::new(
                    C_V.to_vec(),
                    EPH_V_PRIVATE,
                    &AUTH_V_PRIVATE,
                    &AUTH_V_PUBLIC,
                    KID_V.to_vec(),
                );
                let msg2_sender = msg1_receiver
                    .handle_message_1(MESSAGE_1.to_vec())
                    .unwrap();
                let (_, msg3_receiver) =
                    msg2_sender.generate_message_2().unwrap();
                let (_, msg3_verifier) = msg3_receiver
                    .extract_peer_kid(MESSAGE_3.to_vec())
                    .unwrap();
                msg3_verifier
            },
            |msg3_verifier| {
                msg3_verifier.verify_message_3(&AUTH_U_PUBLIC).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn edhoc_full(c: &mut Criterion) {
    let mut group = c.benchmark_group("edhoc_full");

    group.bench_function("party_u", |b| {
        b.iter_batched(
            || MESSAGE_2.to_vec(),
            |msg2_bytes| {
                let msg1_sender = PartyI::new(
                    C_U.to_vec(),
                    EPH_U_PRIVATE,
                    &AUTH_U_PRIVATE,
                    &AUTH_U_PUBLIC,
                    KID_U.to_vec(),
                );
                let (_, msg2_receiver) =
                    msg1_sender.generate_message_1(TYPE).unwrap();

                let (_v_kid, msg2_verifier) =
                    msg2_receiver.extract_peer_kid(msg2_bytes).unwrap();
                let msg3_sender =
                    msg2_verifier.verify_message_2(&AUTH_V_PUBLIC).unwrap();

                msg3_sender.generate_message_3().unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("party_v", |b| {
        b.iter_batched(
            || (MESSAGE_1.to_vec(), MESSAGE_3.to_vec()),
            |(msg1_bytes, msg3_bytes)| {
                let msg1_receiver = PartyR::new(
                    C_V.to_vec(),
                    EPH_V_PRIVATE,
                    &AUTH_V_PRIVATE,
                    &AUTH_V_PUBLIC,
                    KID_V.to_vec(),
                );
                let msg2_sender =
                    msg1_receiver.handle_message_1(msg1_bytes).unwrap();
                let (_, msg3_receiver) =
                    msg2_sender.generate_message_2().unwrap();

                let (_u_kid, msg3_verifier) =
                    msg3_receiver.extract_peer_kid(msg3_bytes).unwrap();
                msg3_verifier.verify_message_3(&AUTH_U_PUBLIC).unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

// OSCORE ---------------------------------------------------------------------

const MASTER_SECRET: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10,
];
const MASTER_SALT: [u8; 8] = [0x9E, 0x7C, 0xA9, 0x22, 0x23, 0x78, 0x63, 0x40];
const CLIENT_ID: [u8; 0] = [];
const SERVER_ID: [u8; 1] = [0x01];

const REQ_UNPROTECTED: [u8; 22] = [
    0x44, 0x01, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F, 0x63,
    0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x83, 0x74, 0x76, 0x31,
];
const REQ_PROTECTED: [u8; 35] = [
    0x44, 0x02, 0x5D, 0x1F, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6C, 0x6F, 0x63,
    0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x62, 0x09, 0x14, 0xFF, 0x61, 0x2F,
    0x10, 0x92, 0xF1, 0x77, 0x6F, 0x1C, 0x16, 0x68, 0xB3, 0x82, 0x5E,
];

fn oscore(c: &mut Criterion) {
    // Check for no_replay enabled, because otherwise unprotection will fail
    if cfg!(not(feature = "no_replay")) {
        panic!("Run with --features no_replay");
    }

    let mut group = c.benchmark_group("oscore");

    group.bench_function("context_derivation", |b| {
        b.iter(|| {
            SecurityContext::new(
                MASTER_SECRET.to_vec(),
                MASTER_SALT.to_vec(),
                CLIENT_ID.to_vec(),
                SERVER_ID.to_vec(),
            )
            .unwrap()
        })
    });

    let mut req_context = SecurityContext::new(
        MASTER_SECRET.to_vec(),
        MASTER_SALT.to_vec(),
        CLIENT_ID.to_vec(),
        SERVER_ID.to_vec(),
    )
    .unwrap();
    group.bench_function("protection_request", |b| {
        b.iter(|| req_context.protect_request(&REQ_UNPROTECTED).unwrap())
    });

    let mut req_context = SecurityContext::new(
        MASTER_SECRET.to_vec(),
        MASTER_SALT.to_vec(),
        SERVER_ID.to_vec(),
        CLIENT_ID.to_vec(),
    )
    .unwrap();
    group.bench_function("unprotection_request", |b| {
        b.iter(|| req_context.unprotect_request(&REQ_PROTECTED).unwrap())
    });

    group.finish();
}

// Criterion ------------------------------------------------------------------

criterion_group!(oscore_benches, oscore);
criterion_group!(edhoc_benches, edhoc_detailed, edhoc_full);
criterion_main!(edhoc_benches, oscore_benches);
