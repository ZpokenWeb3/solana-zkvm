use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use solana_bpf_loader_program::syscalls::create_program_runtime_environment_v1;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_loader_v4_program::create_program_runtime_environment_v2;
use solana_program::{address_lookup_table, bpf_loader_upgradeable, loader_v4};
use solana_program::address_lookup_table::error::AddressLookupError;
use solana_program::address_lookup_table::state::AddressLookupTable;
use solana_program::bpf_loader_upgradeable::UpgradeableLoaderState;
use solana_program::clock::{Clock, Slot};
use solana_program::fee_calculator::DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE;
use solana_program::hash::Hash;
use solana_program::instruction::{CompiledInstruction, TRANSACTION_LEVEL_STACK_HEIGHT};
use solana_program::loader_v4::{LoaderV4State, LoaderV4Status};
use solana_program::message::{AddressLoader, AddressLoaderError, SanitizedMessage};
use solana_program::message::v0::{LoadedAddresses, MessageAddressTableLookup};
use solana_program::pubkey::Pubkey;
use solana_program::sysvar::{Sysvar, SysvarId};
use solana_program_runtime::invoke_context::{EnvironmentConfig, InvokeContext};
use solana_program_runtime::loaded_programs::{LoadProgramMetrics, ProgramCacheEntry, ProgramCacheEntryOwner, ProgramCacheEntryType, ProgramCacheForTxBatch, ProgramRuntimeEnvironments};
use solana_program_runtime::log_collector::LogCollector;
use solana_program_runtime::sysvar_cache::SysvarCache;
use solana_program_runtime::timings::ExecuteTimings;
use solana_sdk::account::{Account, AccountSharedData, create_account_shared_data_with_fields, DUMMY_INHERITABLE_ACCOUNT_FIELDS, PROGRAM_OWNERS, ReadableAccount};
use solana_sdk::account_utils::StateMut;
use solana_sdk::feature_set::FeatureSet;
use solana_sdk::sysvar::rent::Rent;
use solana_sdk::inner_instruction::{InnerInstruction, InnerInstructionsList};
use solana_sdk::reserved_account_keys::ReservedAccountKeys;
use solana_sdk::signature::Keypair;
use solana_sdk::transaction::{SanitizedTransaction, TransactionError, VersionedTransaction};
use solana_sdk::transaction_context::{ExecutionRecord, IndexOfAccount, TransactionContext};
use solana_svm::account_loader::construct_instructions_account;
use solana_svm::message_processor::MessageProcessor;
use solana_svm::runtime_config::RuntimeConfig;


use crate::solana_simulator::error::Error;
use crate::types::{BUILTINS, TransactionSimulationResult};

use serde::Serialize;
use serde::Deserialize;
use serde::Serializer;
use serde::de::{self, Deserializer, Visitor};
use std::fmt;


#[cfg(feature = "async_enabled")]
use {
    svm_client::rpc::Rpc,
    crate::solana_simulator::utils::SyncState,
    log::debug,
};

mod utils;
mod error;


#[derive(Debug, Deserialize, Serialize)]
pub struct SolanaSimulator {
    runtime_config: RuntimeConfig,
    feature_set: Arc<FeatureSet>,
    accounts_db: BTreeMap<Pubkey, AccountSharedData>,
    sysvar_cache: SysvarCache,
    #[serde(serialize_with = "serialize_keypair", deserialize_with = "deserialize_keypair")]
    payer: Keypair,
}

impl Default for SolanaSimulator {
    fn default() -> Self {
        let mut sysvar_cache = SysvarCache::default();

        sysvar_cache.set_sysvar(&Clock::default());
        sysvar_cache.set_sysvar(&Rent::default());

        let compute_units = 1_400_000;
        let heap_size = 256 * 1024;

        let mut compute_budget = ComputeBudget::new(compute_units);
        compute_budget.heap_size = heap_size;

        let runtime_config = RuntimeConfig {
            compute_budget: Some(compute_budget),
            log_messages_bytes_limit: Some(100 * 1024),
            transaction_account_lock_limit: None,
        };

        SolanaSimulator {
            runtime_config: runtime_config,
            feature_set: Arc::new(FeatureSet::default()),
            accounts_db: BTreeMap::new(),
            sysvar_cache,
            payer: Keypair::new(),
        }
    }
}

fn serialize_keypair<S>(payer: &Keypair, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let base58_keypair = payer.to_base58_string();
    base58_keypair.serialize(serializer)
}

fn deserialize_keypair<'de, D>(deserializer: D) -> Result<Keypair, D::Error>
where
    D: Deserializer<'de>,
{
    let base58_keypair = String::deserialize(deserializer)?;
    Ok(Keypair::from_base58_string(&base58_keypair))
}

impl SolanaSimulator {
    #[cfg(feature = "async_enabled")]
    pub async fn new(rpc: &impl Rpc) -> Result<Self, Error> {
        Self::new_with_config(rpc, RuntimeConfig::default(), SyncState::Yes).await
    }

    #[cfg(feature = "async_enabled")]
    pub async fn new_without_sync(rpc: &impl Rpc) -> Result<Self, Error> {
        Self::new_with_config(rpc, RuntimeConfig::default(), SyncState::No).await
    }

    #[cfg(feature = "async_enabled")]
    pub async fn new_with_config(
        rpc: &impl Rpc,
        runtime_config: RuntimeConfig,
        sync_state: SyncState,
    ) -> Result<Self, Error> {
        let mut feature_set = FeatureSet::all_enabled();

        if sync_state == SyncState::Yes {
            for feature in rpc.get_deactivated_solana_features().await? {
                feature_set.deactivate(&feature);
            }
        }

        let mut sysvar_cache = SysvarCache::default();

        sysvar_cache.set_rent(Rent::default());
        sysvar_cache.set_clock(Clock::default());

        if sync_state == SyncState::Yes {
            utils::sync_sysvar_accounts(rpc, &mut sysvar_cache).await?;
        }

        Ok(Self {
            runtime_config,
            feature_set: Arc::new(feature_set),
            accounts_db: BTreeMap::new(),
            sysvar_cache,
            payer: Keypair::new(),
        })
    }


    #[cfg(feature = "async_enabled")]
    pub async fn sync_accounts(&mut self, rpc: &impl Rpc, keys: &[Pubkey]) -> Result<(), Error> {
        let mut storable_accounts: Vec<(&Pubkey, &Account)> = vec![];

        let mut programdata_keys = vec![];

        let mut accounts = rpc.get_multiple_accounts(keys).await?;
        for (key, account) in keys.iter().zip(&mut accounts) {
            let Some(account) = account else {
                continue;
            };

            if account.executable && bpf_loader_upgradeable::check_id(&account.owner) {
                let programdata_address = utils::program_data_address(account)?;
                debug!(
                    "program_data_account: program={key} programdata=address{programdata_address}"
                );
                programdata_keys.push(programdata_address);
            }

            if account.owner == address_lookup_table::program::id() {
                utils::reset_alt_slot(account).map_err(|_| Error::InvalidALT)?;
            }

            storable_accounts.push((key, account));
        }

        let mut programdata_accounts = rpc.get_multiple_accounts(&programdata_keys).await?;
        for (key, account) in programdata_keys.iter().zip(&mut programdata_accounts) {
            let Some(account) = account else {
                continue;
            };

            debug!("program_data_account: key={key} account={account:?}");
            utils::reset_program_data_slot(account)?;
            storable_accounts.push((key, account));
        }

        self.set_multiple_accounts(&storable_accounts);

        Ok(())
    }

    pub const fn payer(&self) -> &Keypair {
        &self.payer
    }

    pub fn blockhash(&self) -> Hash {
        Hash::new_unique()
    }

    pub fn slot(&self) -> Result<u64, Error> {
        let clock = self.sysvar_cache.get_clock()?;
        Ok(clock.slot)
    }

    fn replace_sysvar_account<S>(&mut self, sysvar: &S)
    where
        S: Sysvar + SysvarId,
    {
        let old_account = self.accounts_db.get(&S::id());
        let inherit = old_account.map_or(DUMMY_INHERITABLE_ACCOUNT_FIELDS, |a| {
            (a.lamports(), a.rent_epoch())
        });

        let account = create_account_shared_data_with_fields(sysvar, inherit);
        self.accounts_db.insert(S::id(), account);
    }

    pub fn set_clock(&mut self, clock: Clock) {
        self.replace_sysvar_account(&clock);
        self.sysvar_cache.set_sysvar(&clock);
    }

    pub fn set_multiple_accounts(&mut self, accounts: &[(&Pubkey, &Account)]) {
        for (pubkey, account) in accounts {
            self.accounts_db
                .insert(**pubkey, AccountSharedData::from((*account).clone()));
        }
    }

    pub fn get_shared_account(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        self.accounts_db.get(pubkey).cloned()
    }

    pub fn sanitize_transaction(
        &self,
        tx: VersionedTransaction,
        verify: bool,
    ) -> Result<SanitizedTransaction, Error> {
        let sanitized_tx = {
            let size = bincode::serialized_size(&tx)?;
            if verify && (size > solana_sdk::packet::PACKET_DATA_SIZE as u64) {
                return Err(TransactionError::SanitizeFailure.into());
            }

            let message_hash = if verify {
                tx.verify_and_hash_message()?
            } else {
                tx.message.hash()
            };

            SanitizedTransaction::try_create(tx, message_hash, None, self, &ReservedAccountKeys::empty_key_set())
        }?;

        if verify {
            sanitized_tx.verify_precompiles(&self.feature_set)?;
        }

        Ok(sanitized_tx)
    }

    pub fn process_transaction(
        &self,
        blockhash: Hash,
        tx: &SanitizedTransaction,
    ) -> Result<TransactionSimulationResult, Error> {
        let mut transaction_accounts = Vec::new();
        for key in tx.message().account_keys().iter() {
            let account = if solana_sdk::sysvar::instructions::check_id(key) {
                construct_instructions_account(tx.message())
            } else {
                self.accounts_db.get(key).cloned().unwrap_or_default()
            };
            transaction_accounts.push((*key, account));
        }

        let program_indices = Self::build_program_indices(tx, &mut transaction_accounts);

        let compute_budget = self.runtime_config.compute_budget.unwrap_or_default();
        let rent: Arc<Rent> = self.sysvar_cache.get_rent()?;
        let clock: Arc<Clock> = self.sysvar_cache.get_clock()?;

        let lamports_before_tx =
            transaction_accounts_lamports_sum(&transaction_accounts, tx.message()).unwrap_or(0);

        let mut transaction_context = TransactionContext::new(
            transaction_accounts,
            (*rent).clone(),
            compute_budget.max_instruction_stack_depth,
            compute_budget.max_instruction_trace_length,
        );

        let mut loaded_programs = self.load_programs(tx, &compute_budget, &clock);

        let log_collector =
            LogCollector::new_ref_with_limit(self.runtime_config.log_messages_bytes_limit);

        let mut units_consumed = 0u64;

        let env_config = EnvironmentConfig::new(
            blockhash,
            None,
            None,
            self.feature_set.clone(),
            DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE / 2,
            &self.sysvar_cache
        );

        let mut invoke_context = InvokeContext::new(
            &mut transaction_context,
            &mut loaded_programs,
            env_config,
            Some(Rc::clone(&log_collector)), compute_budget);

        let mut status = MessageProcessor::process_message(
            tx.message(),
            &program_indices,
            &mut invoke_context,
            &mut ExecuteTimings::default(),
            &mut units_consumed
        );

        let inner_instructions = Some(inner_instructions_list_from_instruction_trace(
            &transaction_context,
        ));

        let ExecutionRecord {
            accounts,
            return_data,
            touched_account_count: _touched_account_count,
            accounts_resize_delta: _accounts_resize_delta,
        } = transaction_context.into();

        if status.is_ok()
            && transaction_accounts_lamports_sum(&accounts, tx.message())
            .filter(|lamports_after_tx| lamports_before_tx == *lamports_after_tx)
            .is_none()
        {
            status = Err(TransactionError::UnbalancedTransaction);
        }

        let logs = Rc::try_unwrap(log_collector)
            .map(|log_collector| log_collector.into_inner().into_messages())
            .ok();

        let return_data = if return_data.data.is_empty() {
            None
        } else {
            Some(return_data)
        };

        Ok(TransactionSimulationResult {
            result: status,
            logs,
            post_simulation_accounts: accounts,
            units_consumed,
            return_data,
            inner_instructions,
        })
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_program_indices(
        tx: &SanitizedTransaction,
        transaction_accounts: &mut Vec<(Pubkey, AccountSharedData)>,
    ) -> Vec<Vec<IndexOfAccount>> {
        let builtins_start_index = transaction_accounts.len();
        tx.message()
            .instructions()
            .iter()
            .map(|instruction| {
                let mut account_indices: Vec<IndexOfAccount> = Vec::with_capacity(2);

                let program_index = instruction.program_id_index as usize;
                let (program_id, program_account) = &transaction_accounts[program_index];

                if solana_sdk::native_loader::check_id(program_id) {
                    return account_indices;
                }

                account_indices.insert(0, program_index as IndexOfAccount);

                let owner = program_account.owner();
                if solana_sdk::native_loader::check_id(owner) {
                    return account_indices;
                }

                if let Some(owner_index) = transaction_accounts[builtins_start_index..]
                    .iter()
                    .position(|(key, _)| key == owner)
                {
                    let owner_index = owner_index + builtins_start_index;
                    account_indices.insert(0, owner_index as IndexOfAccount);
                } else {
                    let _builtin = BUILTINS
                        .iter()
                        .find(|builtin| builtin.program_id == *owner)
                        .unwrap();

                    let owner_account =
                        AccountSharedData::new(100, 100, &solana_sdk::native_loader::id());
                    transaction_accounts.push((*owner, owner_account));

                    let owner_index = transaction_accounts.len() - 1;
                    account_indices.insert(0, owner_index as IndexOfAccount);
                }

                account_indices
            })
            .collect()
    }

    fn load_programs(
        &self,
        tx: &SanitizedTransaction,
        compute_budget: &ComputeBudget,
        clock: &Arc<Clock>,
    ) -> ProgramCacheForTxBatch {
        let program_runtime_environments = ProgramRuntimeEnvironments {
            program_runtime_v1: Arc::new(
                create_program_runtime_environment_v1(
                    &self.feature_set,
                    compute_budget,
                    true,
                    true,
                )
                    .unwrap(),
            ),
            program_runtime_v2: Arc::new(create_program_runtime_environment_v2(
                compute_budget,
                true,
            )),
        };

        let mut loaded_programs = ProgramCacheForTxBatch::new(
            clock.slot,
            program_runtime_environments.clone(),
            None,
            clock.epoch,
        );

        tx.message().account_keys().iter().for_each(|key| {
            if loaded_programs.find(key).is_none() {
                let account = self.accounts_db.get(key).cloned().unwrap_or_default();
                if PROGRAM_OWNERS.iter().any(|owner| account.owner() == owner) {
                    let mut load_program_metrics = LoadProgramMetrics {
                        program_id: key.to_string(),
                        ..LoadProgramMetrics::default()
                    };
                    let loaded_program = match self.load_program_accounts(account) {
                        ProgramAccountLoadResult::InvalidAccountData => {
                            ProgramCacheEntry::new_tombstone(0, ProgramCacheEntryOwner::NativeLoader, ProgramCacheEntryType::Closed)
                        }

                        ProgramAccountLoadResult::ProgramOfLoaderV1orV2(program_account) => {
                            ProgramCacheEntry::new(
                                program_account.owner(),
                                program_runtime_environments.program_runtime_v1.clone(),
                                0,
                                0,
                                program_account.data(),
                                program_account.data().len(),
                                &mut load_program_metrics,
                            )
                                .unwrap()
                        }

                        ProgramAccountLoadResult::ProgramOfLoaderV3(
                            program_account,
                            programdata_account,
                            _slot,
                        ) => {
                            let programdata = programdata_account
                                .data()
                                .get(UpgradeableLoaderState::size_of_programdata_metadata()..)
                                .unwrap();
                            ProgramCacheEntry::new(
                                program_account.owner(),
                                program_runtime_environments.program_runtime_v1.clone(),
                                0,
                                0,
                                programdata,
                                program_account
                                    .data()
                                    .len()
                                    .saturating_add(programdata_account.data().len()),
                                &mut load_program_metrics,
                            )
                                .unwrap()
                        }

                        ProgramAccountLoadResult::ProgramOfLoaderV4(program_account, _slot) => {
                            let elf_bytes = program_account
                                .data()
                                .get(LoaderV4State::program_data_offset()..)
                                .unwrap();
                            ProgramCacheEntry::new(
                                program_account.owner(),
                                program_runtime_environments.program_runtime_v2.clone(),
                                0,
                                0,
                                elf_bytes,
                                program_account.data().len(),
                                &mut load_program_metrics,
                            )
                                .unwrap()
                        }
                    };
                    loaded_programs.replenish(*key, Arc::new(loaded_program));
                }
            }
        });

        for builtin in BUILTINS {
            // create_loadable_account_with_fields
            let program = ProgramCacheEntry::new_builtin(0, builtin.name.len(), builtin.entrypoint);
            loaded_programs.replenish(builtin.program_id, Arc::new(program));
        }

        loaded_programs
    }

    fn load_program_accounts(
        &self,
        program_account: AccountSharedData,
    ) -> ProgramAccountLoadResult {
        debug_assert!(solana_bpf_loader_program::check_loader_id(
            program_account.owner()
        ));

        if loader_v4::check_id(program_account.owner()) {
            return solana_loader_v4_program::get_state(program_account.data())
                .ok()
                .and_then(|state| {
                    (!matches!(state.status, LoaderV4Status::Retracted)).then_some(state.slot)
                })
                .map_or(ProgramAccountLoadResult::InvalidAccountData, |slot| {
                    ProgramAccountLoadResult::ProgramOfLoaderV4(program_account, slot)
                });
        }

        if !bpf_loader_upgradeable::check_id(program_account.owner()) {
            return ProgramAccountLoadResult::ProgramOfLoaderV1orV2(program_account);
        }

        if let Ok(UpgradeableLoaderState::Program {
                      programdata_address,
                  }) = program_account.state()
        {
            if let Some(programdata_account) = self.accounts_db.get(&programdata_address).cloned() {
                if let Ok(UpgradeableLoaderState::ProgramData {
                              slot,
                              upgrade_authority_address: _,
                          }) = programdata_account.state()
                {
                    return ProgramAccountLoadResult::ProgramOfLoaderV3(
                        program_account,
                        programdata_account,
                        slot,
                    );
                }
            }
        }
        ProgramAccountLoadResult::InvalidAccountData
    }
}

enum ProgramAccountLoadResult {
    InvalidAccountData,
    ProgramOfLoaderV1orV2(AccountSharedData),
    ProgramOfLoaderV3(AccountSharedData, AccountSharedData, Slot),
    ProgramOfLoaderV4(AccountSharedData, Slot),
}

fn transaction_accounts_lamports_sum(
    accounts: &[(Pubkey, AccountSharedData)],
    message: &SanitizedMessage,
) -> Option<u128> {
    let mut lamports_sum = 0u128;
    for i in 0..message.account_keys().len() {
        let (_, account) = accounts.get(i)?;
        lamports_sum = lamports_sum.checked_add(u128::from(account.lamports()))?;
    }
    Some(lamports_sum)
}

impl AddressLoader for &SolanaSimulator {
    fn load_addresses(
        self,
        lookups: &[MessageAddressTableLookup],
    ) -> Result<LoadedAddresses, AddressLoaderError> {
        let loaded_addresses = lookups
            .iter()
            .map(|address_table_lookup| {
                let table_account = self
                    .get_shared_account(&address_table_lookup.account_key)
                    .ok_or(AddressLookupError::LookupTableAccountNotFound)?;

                if table_account.owner() != &address_lookup_table::program::id() {
                    return Err(AddressLookupError::InvalidAccountOwner);
                }

                let current_slot = self
                    .slot()
                    .map_err(|_| AddressLookupError::LookupTableAccountNotFound)?;

                let slot_hashes = self
                    .sysvar_cache
                    .get_slot_hashes()
                    .map_err(|_| AddressLookupError::LookupTableAccountNotFound)?;

                let lookup_table = AddressLookupTable::deserialize(table_account.data())
                    .map_err(|_| AddressLookupError::InvalidAccountData)?;

                Ok(LoadedAddresses {
                    writable: lookup_table.lookup(
                        current_slot,
                        &address_table_lookup.writable_indexes,
                        &slot_hashes,
                    )?,
                    readonly: lookup_table.lookup(
                        current_slot,
                        &address_table_lookup.readonly_indexes,
                        &slot_hashes,
                    )?,
                })
            })
            .collect::<Result<_, AddressLookupError>>()?;

        Ok(loaded_addresses)
    }
}

fn inner_instructions_list_from_instruction_trace(
    transaction_context: &TransactionContext,
) -> InnerInstructionsList {
    debug_assert!(transaction_context
        .get_instruction_context_at_index_in_trace(0)
        .map(|instruction_context| instruction_context.get_stack_height()
            == TRANSACTION_LEVEL_STACK_HEIGHT)
        .unwrap_or(true));
    let mut outer_instructions = Vec::new();
    for index_in_trace in 0..transaction_context.get_instruction_trace_length() {
        if let Ok(instruction_context) =
            transaction_context.get_instruction_context_at_index_in_trace(index_in_trace)
        {
            let stack_height = instruction_context.get_stack_height();
            if stack_height == TRANSACTION_LEVEL_STACK_HEIGHT {
                outer_instructions.push(Vec::new());
            } else if let Some(inner_instructions) = outer_instructions.last_mut() {
                let stack_height = u8::try_from(stack_height).unwrap_or(u8::MAX);
                let instruction = CompiledInstruction::new_from_raw_parts(
                    instruction_context
                        .get_index_of_program_account_in_transaction(
                            instruction_context
                                .get_number_of_program_accounts()
                                .saturating_sub(1),
                        )
                        .unwrap_or_default() as u8,
                    instruction_context.get_instruction_data().to_vec(),
                    (0..instruction_context.get_number_of_instruction_accounts())
                        .map(|instruction_account_index| {
                            instruction_context
                                .get_index_of_instruction_account_in_transaction(
                                    instruction_account_index,
                                )
                                .unwrap_or_default() as u8
                        })
                        .collect(),
                );
                inner_instructions.push(InnerInstruction {
                    instruction,
                    stack_height,
                });
            } else {
                debug_assert!(false);
            }
        } else {
            debug_assert!(false);
        }
    }
    outer_instructions
}