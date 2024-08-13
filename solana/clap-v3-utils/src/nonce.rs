use {
    crate::{input_validators::*, ArgConstant},
    clap::{Arg, Command},
};

pub const NONCE_ARG: ArgConstant<'static> = ArgConstant {
    name: "nonce",
    long: "nonce",
    help: "Provide the nonce account to use when creating a nonced \n\
           transaction. Nonced transactions are useful when a transaction \n\
           requires a lengthy signing process. Learn more about nonced \n\
           transactions at https://docs.solanalabs.com/cli/examples/durable-nonce",
};

pub const NONCE_AUTHORITY_ARG: ArgConstant<'static> = ArgConstant {
    name: "nonce_authority",
    long: "nonce-authority",
    help: "Provide the nonce authority keypair to use when signing a nonced transaction",
};

#[allow(deprecated)]
fn nonce_arg<'a>() -> Arg<'a> {
    Arg::new(NONCE_ARG.name)
        .long(NONCE_ARG.long)
        .takes_value(true)
        .value_name("PUBKEY")
        .validator(|s| is_valid_pubkey(s))
        .help(NONCE_ARG.help)
}

#[allow(deprecated)]
pub fn nonce_authority_arg<'a>() -> Arg<'a> {
    Arg::new(NONCE_AUTHORITY_ARG.name)
        .long(NONCE_AUTHORITY_ARG.long)
        .takes_value(true)
        .value_name("KEYPAIR")
        .validator(|s| is_valid_signer(s))
        .help(NONCE_AUTHORITY_ARG.help)
}

pub trait NonceArgs {
    fn nonce_args(self, global: bool) -> Self;
}

impl NonceArgs for Command<'_> {
    fn nonce_args(self, global: bool) -> Self {
        self.arg(nonce_arg().global(global)).arg(
            nonce_authority_arg()
                .requires(NONCE_ARG.name)
                .global(global),
        )
    }
}
