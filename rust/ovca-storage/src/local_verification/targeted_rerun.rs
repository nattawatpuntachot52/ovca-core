//! Read-only Capability Registry snapshot adapter for targeted reruns.

use super::{
    db, load_capability, open_connection, stored_generation,
    validate_allocator_at_least_capability, CapabilityCurrent, CapabilityRegistry, CasToken,
    LocalVerificationStoreError, LocalVerificationStoreResult,
};
use ovca_types::{CapabilityRegistryRow, CapabilityRegistrySnapshot};

impl CapabilityRegistry {
    /// Load the complete current Registry projection in canonical identity order.
    ///
    /// Every projection state digest and referenced immutable record checksum is
    /// revalidated before a snapshot is returned. No mutable global revision is
    /// read or created.
    pub fn load_current_snapshot(
        &self,
    ) -> LocalVerificationStoreResult<CapabilityRegistrySnapshot> {
        let connection = open_connection(&self.database_path)?;
        let mut statement = connection
            .prepare(
                "SELECT capability_id, revision, record_digest, generation, state_digest \
                 FROM capability_current ORDER BY capability_id COLLATE BINARY ASC",
            )
            .map_err(|source| db("prepare current capability snapshot", source))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|source| db("query current capability snapshot", source))?;

        let mut capabilities = Vec::new();
        for row in rows {
            let (capability_id, revision, record_digest, generation, state_digest) =
                row.map_err(|source| db("read current capability snapshot row", source))?;
            let revision = stored_generation(revision)?;
            let generation = stored_generation(generation)?;
            let current = CapabilityCurrent {
                capability_id: capability_id.clone(),
                revision,
                record_digest: record_digest.clone(),
                token: CasToken {
                    generation,
                    state_digest: state_digest.clone(),
                },
            };
            current.validate_state_digest()?;
            validate_allocator_at_least_capability(&connection, &current)?;
            let record =
                load_capability(&connection, &capability_id, revision)?.ok_or_else(|| {
                    LocalVerificationStoreError::MissingRecord {
                        kind: "capability",
                        identity: format!("{capability_id}@{revision}"),
                    }
                })?;
            if record.digest != record_digest {
                return Err(LocalVerificationStoreError::BindingMismatch(format!(
                    "current capability {capability_id}@{revision} record digest"
                )));
            }
            capabilities.push(CapabilityRegistryRow {
                definition: record.definition,
                record_digest,
                generation,
                state_digest,
            });
        }
        drop(statement);

        CapabilityRegistrySnapshot::new(capabilities).map_err(|error| {
            LocalVerificationStoreError::InvalidContract {
                contract: "capability_registry_snapshot",
                detail: error.to_string(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalVerificationStore, ProjectionExpectation};
    use ovca_types::{
        CapabilityDefinition, ChangedPathSelector, DeniedAccess, DigestAlgorithm,
        LocalMachinePolicy, PathSelectorKind, ShellPolicy, VerificationCommand, WorkingDirectory,
        LOCAL_VERIFICATION_CONTRACT_VERSION,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use tempfile::TempDir;

    fn capability(id: &str, revision: u64) -> CapabilityDefinition {
        CapabilityDefinition {
            contract_version: LOCAL_VERIFICATION_CONTRACT_VERSION,
            capability_id: id.to_owned(),
            revision,
            criterion_ids: vec![],
            dependencies: vec![],
            changed_path_selectors: vec![ChangedPathSelector {
                kind: PathSelectorKind::Prefix,
                path: format!("src/{id}"),
            }],
            policy: LocalMachinePolicy {
                local_only: true,
                network: DeniedAccess::Denied,
                provider: DeniedAccess::Denied,
                telemetry: DeniedAccess::Denied,
                egress: DeniedAccess::Denied,
                external_evidence: DeniedAccess::Denied,
                external_storage: DeniedAccess::Denied,
                raw_shell: ShellPolicy::Forbidden,
                inherit_environment: false,
                fingerprint_algorithm: DigestAlgorithm::Sha256,
                allowed_executable_ids: BTreeSet::from(["cargo".to_owned()]),
                allowed_environment_names: BTreeSet::new(),
            },
            commands: vec![VerificationCommand {
                command_id: format!("verify-{id}"),
                executable_id: "cargo".to_owned(),
                argv: vec!["test".to_owned()],
                cwd: WorkingDirectory::SnapshotRoot,
                environment_names: BTreeSet::new(),
            }],
        }
    }

    fn publish_current(registry: &CapabilityRegistry, definition: &CapabilityDefinition) {
        let published = registry.publish(definition).unwrap();
        let record = match published {
            crate::PublishOutcome::Inserted(record)
            | crate::PublishOutcome::ExistingIdentical(record) => record,
        };
        registry
            .compare_and_swap_current(
                &definition.capability_id,
                definition.revision,
                &record.digest,
                &ProjectionExpectation::Absent,
            )
            .unwrap();
    }

    #[derive(Serialize)]
    struct ExpectedIdentity<'a> {
        capability_id: &'a str,
        revision: u64,
        record_digest: &'a str,
        generation: u64,
        state_digest: &'a str,
    }

    #[derive(Serialize)]
    struct ExpectedPayload<'a> {
        capabilities: Vec<ExpectedIdentity<'a>>,
    }

    #[test]
    fn snapshot_is_sorted_reopenable_and_digest_binds_exact_current_rows() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        publish_current(&registry, &capability("zeta", 2));
        publish_current(&registry, &capability("alpha", 1));

        let first = registry.load_current_snapshot().unwrap();
        let reopened = CapabilityRegistry::try_new(temp.path())
            .unwrap()
            .load_current_snapshot()
            .unwrap();
        assert_eq!(first, reopened);
        assert_eq!(
            first
                .capabilities
                .iter()
                .map(|row| row.definition.capability_id.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );

        let expected = ExpectedPayload {
            capabilities: first
                .capabilities
                .iter()
                .map(|row| ExpectedIdentity {
                    capability_id: &row.definition.capability_id,
                    revision: row.definition.revision,
                    record_digest: &row.record_digest,
                    generation: row.generation,
                    state_digest: &row.state_digest,
                })
                .collect(),
        };
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&expected).unwrap())
        );
        assert_eq!(first.registry_snapshot_digest, digest);
    }

    #[test]
    fn snapshot_rejects_corrupt_immutable_record() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        publish_current(&registry, &capability("alpha", 1));

        let connection = open_connection(registry.database_path()).unwrap();
        connection
            .execute(
                "UPDATE capability_records SET canonical_json=?1 WHERE capability_id='alpha'",
                [b"{}".as_slice()],
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            registry.load_current_snapshot(),
            Err(LocalVerificationStoreError::CorruptRecord {
                kind: "capability",
                reason: "checksum mismatch",
                ..
            })
        ));
    }

    #[test]
    fn snapshot_rejects_tampered_current_state() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        publish_current(&registry, &capability("alpha", 1));

        let connection = open_connection(registry.database_path()).unwrap();
        connection
            .execute(
                "UPDATE capability_current SET state_digest=?1 WHERE capability_id='alpha'",
                ["0".repeat(64)],
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            registry.load_current_snapshot(),
            Err(LocalVerificationStoreError::InvalidProjectionSelection(_))
        ));
    }

    #[test]
    fn snapshot_rejects_generation_rollback_with_recomputed_state_digest() {
        let temp = TempDir::new().unwrap();
        let store = LocalVerificationStore::try_new(temp.path()).unwrap();
        let registry = store.capability_registry();
        publish_current(&registry, &capability("alpha", 1));

        let prior = registry.load_current("alpha").unwrap().unwrap();
        let definition = capability("alpha", 2);
        let record = match registry.publish(&definition).unwrap() {
            crate::PublishOutcome::Inserted(record)
            | crate::PublishOutcome::ExistingIdentical(record) => record,
        };
        let advanced = registry
            .compare_and_swap_current(
                "alpha",
                definition.revision,
                &record.digest,
                &ProjectionExpectation::Token(prior.token),
            )
            .unwrap();
        assert!(matches!(advanced, crate::CasOutcome::Applied(_)));

        let rolled_back = CapabilityCurrent::new("alpha", 2, &record.digest, 1).unwrap();
        let connection = open_connection(registry.database_path()).unwrap();
        connection
            .execute(
                "UPDATE capability_current SET generation=?1, state_digest=?2 \
                 WHERE capability_id='alpha'",
                rusqlite::params![rolled_back.token.generation, rolled_back.token.state_digest],
            )
            .unwrap();
        drop(connection);

        assert!(matches!(
            registry.load_current_snapshot(),
            Err(LocalVerificationStoreError::CorruptRecord {
                kind: "capability_projection",
                reason: "generation binding does not match projection",
                ..
            })
        ));
    }
}
