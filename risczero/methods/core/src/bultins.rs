use solana_program::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable};
use solana_program::pubkey::Pubkey;
use solana_program_runtime::invoke_context::BuiltinFunctionWithContext;
use solana_sdk::feature_set;



/// Identifies the type of built-in program targeted for Core BPF migration.
/// The type of target determines whether the program should have a program
/// account or not, which is checked before migration.
#[allow(dead_code)] // Remove after first migration is configured.
#[derive(Debug, PartialEq)]
pub(crate) enum CoreBpfMigrationTargetType {
    /// A standard (stateful) builtin program must have a program account.
    Builtin,
    /// A stateless builtin must not have a program account.
    Stateless,
}

/// Configuration for migrating a built-in program to Core BPF.
#[derive(Debug, PartialEq)]
pub(crate) struct CoreBpfMigrationConfig {
    /// The address of the source buffer account to be used to replace the
    /// builtin.
    pub source_buffer_address: Pubkey,
    /// The authority to be used as the BPF program's upgrade authority.
    ///
    /// Note: If this value is set to `None`, then the migration will ignore
    /// the source buffer account's authority. If it's set to any `Some(..)`
    /// value, then the migration will perform a sanity check to ensure the
    /// source buffer account's authority matches the provided value.
    pub upgrade_authority_address: Option<Pubkey>,
    /// The feature gate to trigger the migration to Core BPF.
    /// Note: This feature gate should never be the same as any builtin's
    /// `enable_feature_id`. It should always be a feature gate that will be
    /// activated after the builtin is already enabled.
    pub feature_id: Pubkey,
    /// The type of target to replace.
    pub migration_target: CoreBpfMigrationTargetType,
    /// Static message used to emit datapoint logging.
    /// This is used to identify the migration in the logs.
    /// Should be unique to the migration, ie:
    /// "migrate_{builtin/stateless}_to_core_bpf_{program_name}".
    pub datapoint_name: &'static str,
}

pub struct BuiltinPrototype {
    pub(crate) core_bpf_migration_config: Option<CoreBpfMigrationConfig>,
    pub enable_feature_id: Option<Pubkey>,
    pub program_id: Pubkey,
    pub name: &'static str,
    pub entrypoint: BuiltinFunctionWithContext,
}

impl std::fmt::Debug for BuiltinPrototype {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut builder = f.debug_struct("BuiltinPrototype");
        builder.field("program_id", &self.program_id);
        builder.field("name", &self.name);
        builder.field("enable_feature_id", &self.enable_feature_id);
        builder.field("core_bpf_migration_config", &self.core_bpf_migration_config);
        builder.finish()
    }
}

macro_rules! testable_prototype {
    ($prototype:ident {
        core_bpf_migration_config: $core_bpf_migration_config:expr,
        name: $name:ident,
        $($field:ident : $value:expr),* $(,)?
    }) => {
        $prototype {
            core_bpf_migration_config: {
                #[cfg(not(test))]
                {
                    $core_bpf_migration_config
                }
                #[cfg(test)]
                {
                    Some( test_only::$name::CONFIG )
                }
            },
            name: stringify!($name),
            $($field: $value),*
        }
    };
}

pub static BUILTINS: &[BuiltinPrototype] = &[
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: system_program,
        enable_feature_id: None,
        program_id: solana_system_program::id(),
        entrypoint: solana_system_program::system_processor::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: solana_bpf_loader_deprecated_program,
        enable_feature_id: None,
        program_id: bpf_loader_deprecated::id(),
        entrypoint: solana_bpf_loader_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: solana_bpf_loader_program,
        enable_feature_id: None,
        program_id: bpf_loader::id(),
        entrypoint: solana_bpf_loader_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: solana_bpf_loader_upgradeable_program,
        enable_feature_id: None,
        program_id: bpf_loader_upgradeable::id(),
        entrypoint: solana_bpf_loader_program::Entrypoint::vm,
    }),
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: compute_budget_program,
        enable_feature_id: None,
        program_id: solana_sdk::compute_budget::id(),
        entrypoint: solana_compute_budget_program::Entrypoint::vm,
    }),
    BuiltinPrototype {
        core_bpf_migration_config: Some(CoreBpfMigrationConfig {
            source_buffer_address: buffer_accounts::address_lookup_table_program::id(),
            upgrade_authority_address: None,
            feature_id:
            solana_sdk::feature_set::migrate_address_lookup_table_program_to_core_bpf::id(),
            migration_target: CoreBpfMigrationTargetType::Builtin,
            datapoint_name: "migrate_builtin_to_core_bpf_address_lookup_table_program",
        }),
        name: "address_lookup_table_program",
        enable_feature_id: None,
        program_id: solana_sdk::address_lookup_table::program::id(),
        entrypoint: solana_address_lookup_table_program::processor::Entrypoint::vm,
    },
    testable_prototype!(BuiltinPrototype {
        core_bpf_migration_config: None,
        name: loader_v4,
        enable_feature_id: Some(feature_set::enable_program_runtime_v2_and_loader_v4::id()),
        program_id: solana_sdk::loader_v4::id(),
        entrypoint: solana_loader_v4_program::Entrypoint::vm,
    }),
];

mod buffer_accounts {
    pub mod address_lookup_table_program {
        solana_sdk::declare_id!("AhXWrD9BBUYcKjtpA3zuiiZG4ysbo6C6wjHo1QhERk6A");
    }
    pub mod config_program {
        solana_sdk::declare_id!("BuafH9fBv62u6XjzrzS4ZjAE8963ejqF5rt1f8Uga4Q3");
    }
    pub mod feature_gate_program {
        solana_sdk::declare_id!("3D3ydPWvmEszrSjrickCtnyRSJm1rzbbSsZog8Ub6vLh");
    }
}