use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{UNIX_EPOCH};
use solana_bpf_loader_program::syscalls::{SyscallAbort, SyscallGetClockSysvar, SyscallInvokeSignedRust, SyscallLog, SyscallMemcpy, SyscallMemset, SyscallSetReturnData};
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_program::bpf_loader_upgradeable;
use solana_program::bpf_loader_upgradeable::UpgradeableLoaderState;
use solana_program::clock::{Clock, UnixTimestamp};
use solana_program::hash::Hash;
use solana_program::instruction::AccountMeta;
use solana_program::pubkey::Pubkey;
use solana_program::sysvar::SysvarId;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_program_runtime::loaded_programs::{ProgramCache, ProgramCacheEntry, ProgramRuntimeEnvironments};
use solana_program_runtime::solana_rbpf::program::{BuiltinFunction, BuiltinProgram, FunctionRegistry};
use solana_program_runtime::solana_rbpf::vm::Config;
use solana_sdk::account::{AccountSharedData, WritableAccount};
use solana_sdk::signature::Signature;
use solana_sdk::transaction::{SanitizedTransaction, TransactionError};
use solana_svm::account_loader::{CheckedTransactionDetails, TransactionCheckResult};
use solana_svm::transaction_processor::TransactionBatchProcessor;
use crate::mock_bank::{MockBankCallback, MockForkGraph};
use crate::transaction_builder::SanitizedTransactionBuilder;

const BPF_LOADER_NAME: &str = "solana_bpf_loader_upgradeable_program";
const SYSTEM_PROGRAM_NAME: &str = "system_program";
const DEPLOYMENT_SLOT: u64 = 0;
const EXECUTION_SLOT: u64 = 5; // The execution slot must be greater than the deployment slot
const DEPLOYMENT_EPOCH: u64 = 0;
const EXECUTION_EPOCH: u64 = 2; // The execution epoch must be greater than the deployment epoch

fn create_custom_environment<'a>() -> BuiltinProgram<InvokeContext<'a>> {
    let compute_budget = ComputeBudget::default();
    let vm_config = Config {
        max_call_depth: compute_budget.max_call_depth,
        stack_frame_size: compute_budget.stack_frame_size,
        enable_address_translation: true,
        enable_stack_frame_gaps: true,
        instruction_meter_checkpoint_distance: 10000,
        enable_instruction_meter: true,
        enable_instruction_tracing: true,
        enable_symbol_and_section_labels: true,
        reject_broken_elfs: true,
        noop_instruction_rate: 256,
        sanitize_user_provided_values: true,
        external_internal_function_hash_collision: false,
        reject_callx_r10: false,
        enable_sbpf_v1: true,
        enable_sbpf_v2: false,
        optimize_rodata: false,
        new_elf_parser: false,
        aligned_memory_mapping: true,
    };

    // These functions are system calls the compile contract calls during execution, so they
    // need to be registered.
    let mut function_registry = FunctionRegistry::<BuiltinFunction<InvokeContext>>::default();
    function_registry
        .register_function_hashed(*b"abort", SyscallAbort::vm)
        .expect("Registration failed");
    function_registry
        .register_function_hashed(*b"sol_log_", SyscallLog::vm)
        .expect("Registration failed");
    function_registry
        .register_function_hashed(*b"sol_memcpy_", SyscallMemcpy::vm)
        .expect("Registration failed");
    function_registry
        .register_function_hashed(*b"sol_memset_", SyscallMemset::vm)
        .expect("Registration failed");

    function_registry
        .register_function_hashed(*b"sol_invoke_signed_rust", SyscallInvokeSignedRust::vm)
        .expect("Registration failed");

    function_registry
        .register_function_hashed(*b"sol_set_return_data", SyscallSetReturnData::vm)
        .expect("Registration failed");

    function_registry
        .register_function_hashed(*b"sol_get_clock_sysvar", SyscallGetClockSysvar::vm)
        .expect("Registration failed");

    BuiltinProgram::new_loader(vm_config, function_registry)
}

pub fn create_executable_environment(
    fork_graph: Arc<RwLock<MockForkGraph>>,
    mock_bank: &mut MockBankCallback,
    program_cache: &mut ProgramCache<MockForkGraph>,
    time_now: i64,
) {
    program_cache.environments = ProgramRuntimeEnvironments {
        program_runtime_v1: Arc::new(create_custom_environment()),
        // We are not using program runtime v2
        program_runtime_v2: Arc::new(BuiltinProgram::new_loader(
            Config::default(),
            FunctionRegistry::default(),
        )),
    };

    program_cache.fork_graph = Some(Arc::downgrade(&fork_graph));

    // We must fill in the sysvar cache entries
    let clock = Clock {
        slot: DEPLOYMENT_SLOT,
        epoch_start_timestamp: time_now.saturating_sub(10) as UnixTimestamp,
        epoch: DEPLOYMENT_EPOCH,
        leader_schedule_epoch: DEPLOYMENT_EPOCH,
        unix_timestamp: time_now as UnixTimestamp,
    };

    let mut account_data = AccountSharedData::default();
    account_data.set_data(bincode::serialize(&clock).unwrap());
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(Clock::id(), account_data);
}

pub fn deploy_program(buffer: &mut Vec<u8>, mock_bank: &mut MockBankCallback) -> Pubkey {
    let program_account = Pubkey::new_unique();
    let program_data_account = Pubkey::new_unique();
    let state = UpgradeableLoaderState::Program {
        programdata_address: program_data_account,
    };

    // The program account must have funds and hold the executable binary
    let mut account_data = AccountSharedData::default();
    account_data.set_data(bincode::serialize(&state).unwrap());
    account_data.set_lamports(1000);
    account_data.set_owner(bpf_loader_upgradeable::id());
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(program_account, account_data);

    let mut account_data = AccountSharedData::default();
    let state = UpgradeableLoaderState::ProgramData {
        slot: DEPLOYMENT_SLOT,
        upgrade_authority_address: None,
    };
    let mut header = bincode::serialize(&state).unwrap();
    let mut complement = vec![
        0;
        std::cmp::max(
            0,
            UpgradeableLoaderState::size_of_programdata_metadata().saturating_sub(header.len())
        )
    ];
    header.append(&mut complement);
    header.append(buffer);
    account_data.set_data(header);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(program_data_account, account_data);

    program_account
}

pub fn register_builtins(
    mock_bank: &MockBankCallback,
    batch_processor: &TransactionBatchProcessor<MockForkGraph>,
) {
    // We must register the bpf loader account as a loadable account, otherwise programs
    // won't execute.
    batch_processor.add_builtin(
        mock_bank,
        bpf_loader_upgradeable::id(),
        BPF_LOADER_NAME,
        ProgramCacheEntry::new_builtin(
            DEPLOYMENT_SLOT,
            BPF_LOADER_NAME.len(),
            solana_bpf_loader_program::Entrypoint::vm,
        ),
    );

    // In order to perform a transference of native tokens using the system instruction,
    // the system program builtin must be registered.
    batch_processor.add_builtin(
        mock_bank,
        solana_system_program::id(),
        SYSTEM_PROGRAM_NAME,
        ProgramCacheEntry::new_builtin(
            DEPLOYMENT_SLOT,
            SYSTEM_PROGRAM_NAME.len(),
            solana_system_program::system_processor::Entrypoint::vm,
        ),
    );
}

pub fn prepare_transactions(
    mock_bank: &mut MockBankCallback,
    program: &mut Vec<u8>
) -> (Vec<SanitizedTransaction>, Vec<TransactionCheckResult>) {
    let mut transaction_builder = SanitizedTransactionBuilder::default();
    let mut all_transactions = Vec::new();
    let mut transaction_checks = Vec::new();

    // A simple funds transfer between accounts
    let transfer_program_account = deploy_program(program, mock_bank);
    let sender = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let fee_payer = Pubkey::new_unique();
    let system_account = Pubkey::from([0u8; 32]);

    transaction_builder.create_instruction(
        transfer_program_account,
        vec![
            AccountMeta {
                pubkey: sender,
                is_signer: true,
                is_writable: true,
            },
            AccountMeta {
                pubkey: recipient,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: system_account,
                is_signer: false,
                is_writable: false,
            },
        ],
        HashMap::from([(sender, Signature::new_unique())]),
        vec![0, 0, 0, 0, 0, 0, 0, 10],
    );

    let sanitized_transaction =
        transaction_builder.build(Hash::default(), (fee_payer, Signature::new_unique()), true);
    all_transactions.push(sanitized_transaction.clone().unwrap());
    transaction_checks.push(Ok(CheckedTransactionDetails {
        nonce: None,
        lamports_per_signature: 20,
    }));

    // Setting up the accounts for the transfer

    // fee payer
    let mut account_data = AccountSharedData::default();
    account_data.set_lamports(80000);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(fee_payer, account_data);

    // sender
    let mut account_data = AccountSharedData::default();
    account_data.set_lamports(900000);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(sender, account_data);

    // recipient
    let mut account_data = AccountSharedData::default();
    account_data.set_lamports(900000);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(recipient, account_data);



    // fee payer
    let mut account_data = AccountSharedData::default();
    account_data.set_lamports(80000);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(fee_payer, account_data);

    // Sender without enough funds
    let mut account_data = AccountSharedData::default();
    account_data.set_lamports(900000);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(sender, account_data);

    // recipient
    let mut account_data = AccountSharedData::default();
    account_data.set_lamports(900000);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(recipient, account_data);

    // A transaction whose verification has already failed
    all_transactions.push(sanitized_transaction.unwrap());
    transaction_checks.push(Err(TransactionError::BlockhashNotFound));

    (all_transactions, transaction_checks)
}