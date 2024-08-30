//! The `gen_keys` module makes lots of keypairs

use {
    rand::{Rng, SeedableRng},
    rand_chacha::ChaChaRng,
    rayon::prelude::*,
    solana_sdk::{signature::Keypair, signer::keypair::keypair_from_seed},
};

pub struct GenKeys {
    generator: ChaChaRng,
}

impl GenKeys {
    pub fn new(seed: [u8; 32]) -> GenKeys {
        let generator = ChaChaRng::from_seed(seed);
        GenKeys { generator }
    }

    fn gen_seed(&mut self) -> [u8; 32] {
        let mut seed = [0u8; 32];
        self.generator.fill(&mut seed);
        seed
    }

    fn gen_n_seeds(&mut self, n: u64) -> Vec<[u8; 32]> {
        (0..n).map(|_| self.gen_seed()).collect()
    }

    pub fn gen_keypair(&mut self) -> Keypair {
        let mut seed = [0u8; Keypair::SECRET_KEY_LENGTH];
        self.generator.fill(&mut seed[..]);
        keypair_from_seed(&seed).unwrap()
    }

    pub fn gen_n_keypairs(&mut self, n: u64) -> Vec<Keypair> {
        self.gen_n_seeds(n)
            .into_par_iter()
            .map(|seed| {
                let mut keypair_seed = [0u8; Keypair::SECRET_KEY_LENGTH];
                ChaChaRng::from_seed(seed).fill(&mut keypair_seed[..]);
                keypair_from_seed(&keypair_seed).unwrap()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    pub use solana_sdk::pubkey::Pubkey;
    use {super::*, solana_sdk::signature::Signer, std::collections::HashSet};

    #[test]
    fn test_new_key_is_deterministic() {
        let seed = [0u8; 32];
        let mut gen0 = GenKeys::new(seed);
        let mut gen1 = GenKeys::new(seed);

        for _ in 0..100 {
            assert_eq!(gen0.gen_seed().to_vec(), gen1.gen_seed().to_vec());
        }
    }

    #[test]
    fn test_gen_keypair_is_deterministic() {
        let seed = [0u8; 32];
        let mut gen0 = GenKeys::new(seed);
        let mut gen1 = GenKeys::new(seed);
        assert_eq!(
            gen0.gen_keypair().to_bytes().to_vec(),
            gen1.gen_keypair().to_bytes().to_vec()
        );
    }

    fn gen_n_pubkeys(seed: [u8; 32], n: u64) -> HashSet<Pubkey> {
        GenKeys::new(seed)
            .gen_n_keypairs(n)
            .into_iter()
            .map(|x| x.pubkey())
            .collect()
    }

    #[test]
    fn test_gen_n_pubkeys_deterministic() {
        let seed = [0u8; 32];
        assert_eq!(gen_n_pubkeys(seed, 50), gen_n_pubkeys(seed, 50));
    }
}
