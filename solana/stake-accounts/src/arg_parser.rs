use {
    crate::args::{
        Args, AuthorizeArgs, Command, CountArgs, MoveArgs, NewArgs, QueryArgs, RebaseArgs,
        SetLockupArgs,
    },
    clap::{
        crate_description, crate_name, value_t, value_t_or_exit, App, Arg, ArgMatches, SubCommand,
    },
    solana_clap_utils::{
        input_parsers::unix_timestamp_from_rfc3339_datetime,
        input_validators::{is_amount, is_rfc3339_datetime, is_valid_pubkey, is_valid_signer},
    },
    solana_cli_config::CONFIG_FILE,
    solana_sdk::native_token::sol_to_lamports,
    std::{ffi::OsString, process::exit},
};

fn fee_payer_arg<'a, 'b>() -> Arg<'a, 'b> {
    solana_clap_utils::fee_payer::fee_payer_arg().required(true)
}

fn funding_keypair_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("funding_keypair")
        .required(true)
        .takes_value(true)
        .value_name("FUNDING_KEYPAIR")
        .validator(is_valid_signer)
        .help("Keypair to fund accounts")
}

fn base_pubkey_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("base_pubkey")
        .required(true)
        .takes_value(true)
        .value_name("BASE_PUBKEY")
        .validator(is_valid_pubkey)
        .help("Public key which stake account addresses are derived from")
}

fn custodian_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("custodian")
        .required(true)
        .takes_value(true)
        .value_name("KEYPAIR")
        .validator(is_valid_signer)
        .help("Authority to modify lockups")
}

fn new_custodian_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("new_custodian")
        .takes_value(true)
        .value_name("PUBKEY")
        .validator(is_valid_pubkey)
        .help("New authority to modify lockups")
}

fn new_base_keypair_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("new_base_keypair")
        .required(true)
        .takes_value(true)
        .value_name("NEW_BASE_KEYPAIR")
        .validator(is_valid_signer)
        .help("New keypair which stake account addresses are derived from")
}

fn stake_authority_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("stake_authority")
        .long("stake-authority")
        .required(true)
        .takes_value(true)
        .value_name("KEYPAIR")
        .validator(is_valid_signer)
        .help("Stake authority")
}

fn withdraw_authority_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("withdraw_authority")
        .long("withdraw-authority")
        .required(true)
        .takes_value(true)
        .value_name("KEYPAIR")
        .validator(is_valid_signer)
        .help("Withdraw authority")
}

fn new_stake_authority_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("new_stake_authority")
        .long("new-stake-authority")
        .required(true)
        .takes_value(true)
        .value_name("PUBKEY")
        .validator(is_valid_pubkey)
        .help("New stake authority")
}

fn new_withdraw_authority_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("new_withdraw_authority")
        .long("new-withdraw-authority")
        .required(true)
        .takes_value(true)
        .value_name("PUBKEY")
        .validator(is_valid_pubkey)
        .help("New withdraw authority")
}

fn lockup_epoch_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("lockup_epoch")
        .long("lockup-epoch")
        .takes_value(true)
        .value_name("NUMBER")
        .help("The epoch height at which each account will be available for withdrawal")
}

fn lockup_date_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("lockup_date")
        .long("lockup-date")
        .value_name("RFC3339 DATETIME")
        .validator(is_rfc3339_datetime)
        .takes_value(true)
        .help("The date and time at which each account will be available for withdrawal")
}

fn num_accounts_arg<'a, 'b>() -> Arg<'a, 'b> {
    Arg::with_name("num_accounts")
        .long("num-accounts")
        .required(true)
        .takes_value(true)
        .value_name("NUMBER")
        .help("Number of derived stake accounts")
}

pub(crate) fn get_matches<'a, I, T>(args: I) -> ArgMatches<'a>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let default_config_file = CONFIG_FILE.as_ref().unwrap();
    App::new(crate_name!())
        .about(crate_description!())
        .version(solana_version::version!())
        .arg(
            Arg::with_name("config_file")
                .long("config")
                .takes_value(true)
                .value_name("FILEPATH")
                .default_value(default_config_file)
                .help("Config file"),
        )
        .arg(
            Arg::with_name("url")
                .long("url")
                .global(true)
                .takes_value(true)
                .value_name("URL")
                .help("RPC entrypoint address. i.e. http://api.devnet.solana.com"),
        )
        .subcommand(
            SubCommand::with_name("new")
                .about("Create derived stake accounts")
                .arg(fee_payer_arg())
                .arg(funding_keypair_arg().index(1))
                .arg(
                    Arg::with_name("base_keypair")
                        .required(true)
                        .index(2)
                        .takes_value(true)
                        .value_name("BASE_KEYPAIR")
                        .validator(is_valid_signer)
                        .help("Keypair which stake account addresses are derived from"),
                )
                .arg(
                    Arg::with_name("amount")
                        .required(true)
                        .index(3)
                        .takes_value(true)
                        .value_name("AMOUNT")
                        .validator(is_amount)
                        .help("Amount to move into the new stake accounts, in SOL"),
                )
                .arg(
                    Arg::with_name("stake_authority")
                        .long("stake-authority")
                        .required(true)
                        .takes_value(true)
                        .value_name("PUBKEY")
                        .validator(is_valid_pubkey)
                        .help("Stake authority"),
                )
                .arg(
                    Arg::with_name("withdraw_authority")
                        .long("withdraw-authority")
                        .required(true)
                        .takes_value(true)
                        .value_name("PUBKEY")
                        .validator(is_valid_pubkey)
                        .help("Withdraw authority"),
                )
                .arg(
                    Arg::with_name("index")
                        .long("index")
                        .takes_value(true)
                        .default_value("0")
                        .value_name("NUMBER")
                        .help("Index of the derived account to create"),
                ),
        )
        .subcommand(
            SubCommand::with_name("count")
                .about("Count derived stake accounts")
                .arg(base_pubkey_arg().index(1)),
        )
        .subcommand(
            SubCommand::with_name("addresses")
                .about("Show public keys of all derived stake accounts")
                .arg(base_pubkey_arg().index(1))
                .arg(num_accounts_arg()),
        )
        .subcommand(
            SubCommand::with_name("balance")
                .about("Sum balances of all derived stake accounts")
                .arg(base_pubkey_arg().index(1))
                .arg(num_accounts_arg()),
        )
        .subcommand(
            SubCommand::with_name("authorize")
                .about("Set new authorities in all derived stake accounts")
                .arg(fee_payer_arg())
                .arg(base_pubkey_arg().index(1))
                .arg(stake_authority_arg())
                .arg(withdraw_authority_arg())
                .arg(new_stake_authority_arg())
                .arg(new_withdraw_authority_arg())
                .arg(num_accounts_arg()),
        )
        .subcommand(
            SubCommand::with_name("set-lockup")
                .about("Set new lockups in all derived stake accounts")
                .arg(fee_payer_arg())
                .arg(base_pubkey_arg().index(1))
                .arg(custodian_arg())
                .arg(lockup_epoch_arg())
                .arg(lockup_date_arg())
                .arg(new_custodian_arg())
                .arg(num_accounts_arg())
                .arg(
                    Arg::with_name("no_wait")
                        .long("no-wait")
                        .help("Send transactions without waiting for confirmation"),
                )
                .arg(
                    Arg::with_name("unlock_years")
                        .long("unlock-years")
                        .takes_value(true)
                        .value_name("NUMBER")
                        .help("Years to unlock after the cliff"),
                ),
        )
        .subcommand(
            SubCommand::with_name("rebase")
                .about("Relocate derived stake accounts")
                .arg(fee_payer_arg())
                .arg(base_pubkey_arg().index(1))
                .arg(new_base_keypair_arg().index(2))
                .arg(stake_authority_arg())
                .arg(num_accounts_arg()),
        )
        .subcommand(
            SubCommand::with_name("move")
                .about("Rebase and set new authorities in all derived stake accounts")
                .arg(fee_payer_arg())
                .arg(base_pubkey_arg().index(1))
                .arg(new_base_keypair_arg().index(2))
                .arg(stake_authority_arg())
                .arg(withdraw_authority_arg())
                .arg(new_stake_authority_arg())
                .arg(new_withdraw_authority_arg())
                .arg(num_accounts_arg()),
        )
        .get_matches_from(args)
}

fn parse_new_args(matches: &ArgMatches<'_>) -> NewArgs<String, String> {
    NewArgs {
        fee_payer: value_t_or_exit!(matches, "fee_payer", String),
        funding_keypair: value_t_or_exit!(matches, "funding_keypair", String),
        lamports: sol_to_lamports(value_t_or_exit!(matches, "amount", f64)),
        base_keypair: value_t_or_exit!(matches, "base_keypair", String),
        stake_authority: value_t_or_exit!(matches, "stake_authority", String),
        withdraw_authority: value_t_or_exit!(matches, "withdraw_authority", String),
        index: value_t_or_exit!(matches, "index", usize),
    }
}

fn parse_count_args(matches: &ArgMatches<'_>) -> CountArgs<String> {
    CountArgs {
        base_pubkey: value_t_or_exit!(matches, "base_pubkey", String),
    }
}

fn parse_query_args(matches: &ArgMatches<'_>) -> QueryArgs<String> {
    QueryArgs {
        base_pubkey: value_t_or_exit!(matches, "base_pubkey", String),
        num_accounts: value_t_or_exit!(matches, "num_accounts", usize),
    }
}

fn parse_authorize_args(matches: &ArgMatches<'_>) -> AuthorizeArgs<String, String> {
    AuthorizeArgs {
        fee_payer: value_t_or_exit!(matches, "fee_payer", String),
        base_pubkey: value_t_or_exit!(matches, "base_pubkey", String),
        stake_authority: value_t_or_exit!(matches, "stake_authority", String),
        withdraw_authority: value_t_or_exit!(matches, "withdraw_authority", String),
        new_stake_authority: value_t_or_exit!(matches, "new_stake_authority", String),
        new_withdraw_authority: value_t_or_exit!(matches, "new_withdraw_authority", String),
        num_accounts: value_t_or_exit!(matches, "num_accounts", usize),
    }
}

fn parse_set_lockup_args(matches: &ArgMatches<'_>) -> SetLockupArgs<String, String> {
    SetLockupArgs {
        fee_payer: value_t_or_exit!(matches, "fee_payer", String),
        base_pubkey: value_t_or_exit!(matches, "base_pubkey", String),
        custodian: value_t_or_exit!(matches, "custodian", String),
        lockup_epoch: value_t!(matches, "lockup_epoch", u64).ok(),
        lockup_date: unix_timestamp_from_rfc3339_datetime(matches, "lockup_date"),
        new_custodian: value_t!(matches, "new_custodian", String).ok(),
        num_accounts: value_t_or_exit!(matches, "num_accounts", usize),
        no_wait: matches.is_present("no_wait"),
        unlock_years: value_t!(matches, "unlock_years", f64).ok(),
    }
}

fn parse_rebase_args(matches: &ArgMatches<'_>) -> RebaseArgs<String, String> {
    RebaseArgs {
        fee_payer: value_t_or_exit!(matches, "fee_payer", String),
        base_pubkey: value_t_or_exit!(matches, "base_pubkey", String),
        new_base_keypair: value_t_or_exit!(matches, "new_base_keypair", String),
        stake_authority: value_t_or_exit!(matches, "stake_authority", String),
        num_accounts: value_t_or_exit!(matches, "num_accounts", usize),
    }
}

fn parse_move_args(matches: &ArgMatches<'_>) -> MoveArgs<String, String> {
    MoveArgs {
        rebase_args: parse_rebase_args(matches),
        authorize_args: parse_authorize_args(matches),
    }
}

pub(crate) fn parse_args<I, T>(args: I) -> Args<String, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = get_matches(args);
    let config_file = matches.value_of("config_file").unwrap().to_string();
    let url = matches.value_of("url").map(|x| x.to_string());

    let command = match matches.subcommand() {
        ("new", Some(matches)) => Command::New(parse_new_args(matches)),
        ("count", Some(matches)) => Command::Count(parse_count_args(matches)),
        ("addresses", Some(matches)) => Command::Addresses(parse_query_args(matches)),
        ("balance", Some(matches)) => Command::Balance(parse_query_args(matches)),
        ("authorize", Some(matches)) => Command::Authorize(parse_authorize_args(matches)),
        ("set-lockup", Some(matches)) => Command::SetLockup(parse_set_lockup_args(matches)),
        ("rebase", Some(matches)) => Command::Rebase(parse_rebase_args(matches)),
        ("move", Some(matches)) => Command::Move(Box::new(parse_move_args(matches))),
        _ => {
            eprintln!("{}", matches.usage());
            exit(1);
        }
    };
    Args {
        config_file,
        url,
        command,
    }
}
