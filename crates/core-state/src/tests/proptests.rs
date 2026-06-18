use super::*;

use std::collections::{BTreeMap, BTreeSet};

use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use tempfile::TempDir;

const SESSION_CASES: u32 = 64;
const SQLITE_CASES: u32 = 64;

#[derive(Clone, Debug)]
enum SessionOp {
    Create(u8),
    Close(u8),
}

#[derive(Clone, Debug)]
enum BindingOp {
    Upsert { id: u8, account: u8, label: u8 },
    Delete(u8),
}

#[derive(Clone, Debug)]
struct LocalBlockOp {
    chunk: u8,
    ciphertext_bytes: u16,
}

fn session_id(id: u8) -> String {
    format!("sess-{id}")
}

fn session_meta(id: u8) -> SessionMeta {
    SessionMeta {
        session_id: session_id(id),
        persona: format!("persona-{}", id % 3),
        grant_id: format!("grant-{}", id % 4),
        started_at: Utc.timestamp_opt(id as i64, 0).single().unwrap(),
        launcher_pid: 1000 + id as u32,
        authority_strict: id % 2 == 0,
        delegation_id: None,
        delegation_template: None,
        durable_persona: None,
        caller_binding_id: None,
    }
}

fn binding_id(id: u8) -> String {
    format!("binding-{id}")
}

fn service_binding(id: u8, account: u8, label: u8) -> core_event_types::ServiceBinding {
    core_event_types::ServiceBinding {
        id: binding_id(id),
        persona_id: "persona-a".into(),
        descriptor: core_event_types::ServiceDescriptor {
            adapter_kind: "password".into(),
            service_label: format!("service-{label}"),
            endpoint: format!("https://service-{label}.example.test"),
        },
        external_account_id: format!("account-{account}"),
        created_at: 100 + account as u64,
    }
}

fn seed_persona(store: &mut EventStore) {
    append_typed(
        store,
        "evt-root-1",
        EventBody::RootCreated(RootCreatedEvent {
            root_id: "root-a".into(),
            display_name: "Primary".into(),
            initial_key: test_key("key-root-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
    append_typed(
        store,
        "evt-persona-1",
        EventBody::PersonaCreated(PersonaCreatedEvent {
            root_id: "root-a".into(),
            persona_id: "persona-a".into(),
            label: "Work".into(),
            disclosure_profile: Some("persona.professional".into()),
            survival_mode: SurvivalMode::Strict,
            initial_key: test_key("key-persona-a-v1"),
        }),
        SignerBinding::root("root-a", "key-root-a-v1"),
    );
}

fn arb_session_op() -> impl Strategy<Value = SessionOp> {
    prop_oneof![
        (0u8..8).prop_map(SessionOp::Create),
        (0u8..8).prop_map(SessionOp::Close),
    ]
}

fn arb_binding_op() -> impl Strategy<Value = BindingOp> {
    prop_oneof![
        (0u8..8, 0u8..16, 0u8..8).prop_map(|(id, account, label)| BindingOp::Upsert {
            id,
            account,
            label,
        }),
        (0u8..8).prop_map(BindingOp::Delete),
    ]
}

fn arb_local_block_op() -> impl Strategy<Value = LocalBlockOp> {
    (0u8..12, 1u16..8192).prop_map(|(chunk, ciphertext_bytes)| LocalBlockOp {
        chunk,
        ciphertext_bytes,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(SESSION_CASES))]

    // Anchor: core_state_proptest_persistence_landed
    #[test]
    fn session_create_close_sequences_match_open_set(
        ops in proptest::collection::vec(arb_session_op(), 1..64),
    ) {
        let dir = TempDir::new().unwrap();
        let store = SessionStore::new(dir.path().to_path_buf());
        let mut open = BTreeMap::<String, SessionMeta>::new();

        for op in ops {
            match op {
                SessionOp::Create(id) => {
                    let meta = session_meta(id);
                    store.create(&meta).unwrap();
                    open.insert(meta.session_id.clone(), meta);
                }
                SessionOp::Close(id) => {
                    let id = session_id(id);
                    store.close(&id).unwrap();
                    open.remove(&id);
                }
            }
        }

        let listed = store
            .list_open()
            .unwrap()
            .into_iter()
            .map(|meta| meta.session_id)
            .collect::<BTreeSet<_>>();
        let expected = open.keys().cloned().collect::<BTreeSet<_>>();
        prop_assert_eq!(listed, expected);

        for id in 0u8..8 {
            let id = session_id(id);
            let read = store.read(&id).unwrap();
            prop_assert_eq!(read.is_some(), open.contains_key(&id));
            if let (Some(actual), Some(expected)) = (read, open.get(&id)) {
                prop_assert_eq!(actual.session_id.as_str(), expected.session_id.as_str());
                prop_assert_eq!(actual.persona.as_str(), expected.persona.as_str());
                prop_assert_eq!(actual.grant_id.as_str(), expected.grant_id.as_str());
                prop_assert_eq!(actual.authority_strict, expected.authority_strict);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(SQLITE_CASES))]

    #[test]
    fn service_binding_upsert_delete_sequences_persist_last_write(
        ops in proptest::collection::vec(arb_binding_op(), 1..64),
    ) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.sqlite");
        let mut expected = BTreeMap::<String, core_event_types::ServiceBinding>::new();

        {
            let mut store = EventStore::open(&path).unwrap();
            seed_persona(&mut store);

            for op in ops {
                match op {
                    BindingOp::Upsert { id, account, label } => {
                        let binding = service_binding(id, account, label);
                        store.upsert_service_binding(&binding).unwrap();
                        expected.insert(binding.id.clone(), binding);
                    }
                    BindingOp::Delete(id) => {
                        let id = binding_id(id);
                        let existed = expected.remove(&id).is_some();
                        prop_assert_eq!(store.delete_service_binding(&id).unwrap(), existed);
                    }
                }
            }
        }

        let reopened = EventStore::open(&path).unwrap();
        let mut actual = reopened.service_bindings().unwrap();
        actual.sort_by(|left, right| left.id.cmp(&right.id));
        let expected = expected.into_values().collect::<Vec<_>>();
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn local_block_metadata_upsert_sequences_persist_last_write(
        ops in proptest::collection::vec(arb_local_block_op(), 1..64),
    ) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.sqlite");
        let mut expected = BTreeMap::<String, u64>::new();

        {
            let mut store = EventStore::open(&path).unwrap();
            for op in ops {
                let block = LocalBlockRecord {
                    chunk_id: format!("chunk-{}", op.chunk),
                    ciphertext_bytes: op.ciphertext_bytes as u64,
                };
                store.upsert_local_block(&block).unwrap();
                expected.insert(block.chunk_id, block.ciphertext_bytes);
            }
        }

        let reopened = EventStore::open(&path).unwrap();
        let mut stmt = reopened
            .conn
            .prepare("SELECT chunk_id, ciphertext_bytes FROM local_blocks")
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                ))
            })
            .unwrap();
        let actual = rows
            .map(|row| row.unwrap())
            .collect::<BTreeMap<String, u64>>();

        prop_assert_eq!(actual, expected);
    }
}
