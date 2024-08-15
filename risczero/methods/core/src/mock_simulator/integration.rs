use {
    solana_bpf_loader_program::syscalls::{
        SyscallAbort, SyscallInvokeSignedRust, SyscallLog, SyscallMemcpy,
        SyscallMemset, SyscallSetReturnData,
    },
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_program_runtime::{
        invoke_context::InvokeContext,
        loaded_programs::{
            BlockRelation, ForkGraph, ProgramCache, ProgramCacheEntry, ProgramRuntimeEnvironments,
        },
        solana_rbpf::{
            program::{BuiltinFunction, BuiltinProgram, FunctionRegistry},
            vm::Config,
        },
    },
    solana_sdk::{
        account::{AccountSharedData, WritableAccount},
        bpf_loader_upgradeable::{self, UpgradeableLoaderState},
        clock::{Clock, Epoch, Slot, UnixTimestamp},
        hash::Hash,
        instruction::AccountMeta,
        pubkey::Pubkey,
        signature::Signature,
        sysvar::SysvarId,
        transaction::SanitizedTransaction,
    },
    solana_svm::{
        account_loader::{CheckedTransactionDetails, TransactionCheckResult}
        ,
        transaction_processor::TransactionBatchProcessor
        ,
    },
    std::{
        cmp::Ordering,
        collections::HashMap


        ,
        sync::{Arc, RwLock}
        ,
    },
};
use solana_sdk::transaction::VersionedTransaction;
use crate::mock_simulator::mock_bank::MockBankCallback;
use crate::mock_simulator::transaction_builder::SanitizedTransactionBuilder;

const BPF_LOADER_NAME: &str = "solana_bpf_loader_upgradeable_program";
const SYSTEM_PROGRAM_NAME: &str = "system_program";
const DEPLOYMENT_SLOT: u64 = 0;
const EXECUTION_SLOT: u64 = 5; // The execution slot must be greater than the deployment slot
const DEPLOYMENT_EPOCH: u64 = 0;
const EXECUTION_EPOCH: u64 = 2; // The execution epoch must be greater than the deployment epoch

pub struct MockForkGraph {}

impl ForkGraph for MockForkGraph {
    fn relationship(&self, a: Slot, b: Slot) -> BlockRelation {
        match a.cmp(&b) {
            Ordering::Less => BlockRelation::Ancestor,
            Ordering::Equal => BlockRelation::Equal,
            Ordering::Greater => BlockRelation::Descendant,
        }
    }

    fn slot_epoch(&self, _slot: Slot) -> Option<Epoch> {
        Some(0)
    }
}

pub fn create_custom_environment<'a>() -> BuiltinProgram<InvokeContext<'a>> {
    let compute_budget = ComputeBudget::default();
    let vm_config = Config {
        max_call_depth: compute_budget.max_call_depth,
        stack_frame_size: compute_budget.stack_frame_size,
        enable_address_translation: true,
        enable_stack_frame_gaps: false,
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


pub fn deploy_program(mut buffer: Vec<u8>, mock_bank: &mut MockBankCallback) -> Pubkey {
    let program_account = Pubkey::new_unique();
    let program_data_account = Pubkey::new_unique();
    let state = UpgradeableLoaderState::Program {
        programdata_address: program_data_account,
    };

    // The program account must have funds and hold the executable binary
    let mut account_data = AccountSharedData::default();
    account_data.set_data(bincode::serialize(&state).unwrap());
    account_data.set_lamports(25);
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
            UpgradeableLoaderState::size_of_programdata_metadata().saturating_sub(header.len()),
        )
    ];
    header.append(&mut complement);
    header.append(&mut buffer);
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
    program: Vec<u8>,
    system_account: Pubkey,
    sender: Pubkey,
    recipient: Pubkey,
    fee_payer: Pubkey,
) -> (Vec<SanitizedTransaction>, Vec<TransactionCheckResult>) {
    let mut transaction_builder = SanitizedTransactionBuilder::default();
    let mut all_transactions = Vec::new();
    let mut transaction_checks = Vec::new();

    let hello_program_account = deploy_program(program, mock_bank);

    let fee_payer = Pubkey::new_unique();
    transaction_builder.create_instruction(hello_program_account, Vec::new(), HashMap::new(), Vec::new());

    let sanitized_transaction =
        transaction_builder.build(Hash::default(), (fee_payer, Signature::new_unique()), false);

    all_transactions.push(sanitized_transaction.unwrap());
    transaction_checks.push(Ok(CheckedTransactionDetails {
        nonce: None,
        lamports_per_signature: 20,
    }));

    let mut account_data = AccountSharedData::default();
    account_data.set_lamports(80000);
    mock_bank
        .account_shared_data
        .borrow_mut()
        .insert(fee_payer, account_data);

    // A simple funds transfer between accounts
    // let transfer_program_account = deploy_program(program, mock_bank);
    //
    // transaction_builder.create_instruction(
    //     transfer_program_account,
    //     vec![
    //         AccountMeta {
    //             pubkey: sender,
    //             is_signer: true,
    //             is_writable: true,
    //         },
    //         AccountMeta {
    //             pubkey: recipient,
    //             is_signer: false,
    //             is_writable: true,
    //         },
    //         AccountMeta { pubkey: system_account, is_signer: false, is_writable: false },
    //     ],
    //     HashMap::from([(sender, Signature::new_unique())]),
    //     vec![0, 0, 0, 0, 0, 0, 0, 1],
    // );
    //
    // let sanitized_transaction =
    //     transaction_builder.build(Hash::default(), (fee_payer, Signature::new_unique()), true);
    // all_transactions.push(sanitized_transaction.unwrap());
    // transaction_checks.push(Ok(CheckedTransactionDetails {
    //     nonce: None,
    //     lamports_per_signature: 20,
    // }));
    //
    // // // Setting up the accounts for the transfer
    // //
    // // // fee payer
    // let mut account_data = AccountSharedData::default();
    // account_data.set_lamports(80000);
    // // mock_bank
    //     .account_shared_data
    //     .borrow_mut()
    //     .insert(fee_payer, account_data);
    //
    // // sender
    // let mut account_data = AccountSharedData::default();
    // account_data.set_lamports(900000);
    // mock_bank
    //     .account_shared_data
    //     .borrow_mut()
    //     .insert(sender, account_data);
    //
    // // recipient
    // let mut account_data = AccountSharedData::default();
    // account_data.set_lamports(900000);
    // mock_bank
    //     .account_shared_data
    //     .borrow_mut()
    //     .insert(recipient, account_data);

    (all_transactions, transaction_checks)
}

fn get_transaction(program: Vec<u8>) -> VersionedTransaction{
    let mut mock_bank = MockBankCallback::default();
    let program_id = Pubkey::new_from_array([4u8; 32]);
    let sender = Pubkey::new_from_array([1u8; 32]);
    let recipient = Pubkey::new_from_array([2u8; 32]);
    let fee_payer = Pubkey::new_from_array([3u8; 32]);
    let (transactions, check_results) = prepare_transactions(
        &mut mock_bank,
        program,
        program_id,
        sender,
        recipient,
        fee_payer);
    println!("Check results: {:?}, transactions: {:?}", check_results, transactions);
    transactions.first().unwrap().to_versioned_transaction()
}