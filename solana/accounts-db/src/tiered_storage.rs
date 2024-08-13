#![allow(dead_code)]

pub mod byte_block;
pub mod error;
pub mod file;
pub mod footer;
pub mod hot;
pub mod index;
pub mod meta;
pub mod mmap_utils;
pub mod owners;
pub mod readable;
mod test_utils;

use {
    crate::{accounts_file::StoredAccountsInfo, storable_accounts::StorableAccounts},
    error::TieredStorageError,
    footer::{AccountBlockFormat, AccountMetaFormat},
    hot::{HotStorageWriter, HOT_FORMAT},
    index::IndexBlockFormat,
    owners::OwnersBlockFormat,
    readable::TieredStorageReader,
    std::{
        fs, io,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            OnceLock,
        },
    },
};

pub type TieredStorageResult<T> = Result<T, TieredStorageError>;

const MAX_TIERED_STORAGE_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB;

/// The struct that defines the formats of all building blocks of a
/// TieredStorage.
#[derive(Clone, Debug, PartialEq)]
pub struct TieredStorageFormat {
    pub meta_entry_size: usize,
    pub account_meta_format: AccountMetaFormat,
    pub owners_block_format: OwnersBlockFormat,
    pub index_block_format: IndexBlockFormat,
    pub account_block_format: AccountBlockFormat,
}

/// The implementation of AccountsFile for tiered-storage.
#[derive(Debug)]
pub struct TieredStorage {
    /// The internal reader instance for its accounts file.
    reader: OnceLock<TieredStorageReader>,
    /// A status flag indicating whether its file has been already written.
    already_written: AtomicBool,
    /// The path to the file that stores accounts.
    path: PathBuf,
}

impl Drop for TieredStorage {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            // Here we bypass NotFound error as the focus of the panic is to
            // detect any leakage of storage resource.
            if err.kind() != io::ErrorKind::NotFound {
                panic!(
                    "TieredStorage failed to remove backing storage file '{}': {err}",
                    self.path.display(),
                );
            }
        }
    }
}

impl TieredStorage {
    /// Creates a new writable instance of TieredStorage based on the
    /// specified path and TieredStorageFormat.
    ///
    /// Note that the actual file will not be created until write_accounts
    /// is called.
    pub fn new_writable(path: impl Into<PathBuf>) -> Self {
        Self {
            reader: OnceLock::<TieredStorageReader>::new(),
            already_written: false.into(),
            path: path.into(),
        }
    }

    /// Creates a new read-only instance of TieredStorage from the
    /// specified path.
    pub fn new_readonly(path: impl Into<PathBuf>) -> TieredStorageResult<Self> {
        let path = path.into();
        Ok(Self {
            reader: TieredStorageReader::new_from_path(&path).map(OnceLock::from)?,
            already_written: true.into(),
            path,
        })
    }

    /// Returns the path to this TieredStorage.
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Writes the specified accounts into this TieredStorage.
    ///
    /// Note that this function can only be called once per a TieredStorage
    /// instance.  Otherwise, it will trigger panic.
    pub fn write_accounts<'a>(
        &self,
        accounts: &impl StorableAccounts<'a>,
        skip: usize,
        format: &TieredStorageFormat,
    ) -> TieredStorageResult<StoredAccountsInfo> {
        let was_written = self.already_written.swap(true, Ordering::AcqRel);

        if was_written {
            panic!("cannot write same tiered storage file more than once");
        }

        if format == &HOT_FORMAT {
            let stored_accounts_info = {
                let mut writer = HotStorageWriter::new(&self.path)?;
                let stored_accounts_info = writer.write_accounts(accounts, skip)?;
                writer.flush()?;
                stored_accounts_info
            };

            // panic here if self.reader.get() is not None as self.reader can only be
            // None since a false-value `was_written` indicates the accounts file has
            // not been written previously, implying is_read_only() was also false.
            debug_assert!(!self.is_read_only());
            self.reader
                .set(TieredStorageReader::new_from_path(&self.path)?)
                .unwrap();

            Ok(stored_accounts_info)
        } else {
            Err(TieredStorageError::UnknownFormat(self.path.to_path_buf()))
        }
    }

    /// Returns the underlying reader of the TieredStorage.  None will be
    /// returned if it's is_read_only() returns false.
    pub fn reader(&self) -> Option<&TieredStorageReader> {
        self.reader.get()
    }

    /// Returns true if the TieredStorage instance is read-only.
    pub fn is_read_only(&self) -> bool {
        self.reader.get().is_some()
    }

    /// Returns the size of the underlying accounts file.
    pub fn len(&self) -> usize {
        self.reader().map_or(0, |reader| reader.len())
    }

    /// Returns whether the underlying storage is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> u64 {
        self.reader()
            .map_or(MAX_TIERED_STORAGE_FILE_SIZE, |reader| reader.capacity())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        file::TieredStorageMagicNumber,
        footer::TieredStorageFooter,
        hot::HOT_FORMAT,
        solana_sdk::{
            account::{AccountSharedData, ReadableAccount},
            clock::Slot,
            pubkey::Pubkey,
            system_instruction::MAX_PERMITTED_DATA_LENGTH,
        },
        std::{
            collections::{HashMap, HashSet},
            mem::ManuallyDrop,
        },
        tempfile::tempdir,
        test_utils::{create_test_account, verify_test_account_with_footer},
    };

    impl TieredStorage {
        fn footer(&self) -> Option<&TieredStorageFooter> {
            self.reader.get().map(|r| r.footer())
        }
    }

    /// Simply invoke write_accounts with empty vector to allow the tiered storage
    /// to persist non-account blocks such as footer, index block, etc.
    fn write_zero_accounts(
        tiered_storage: &TieredStorage,
        expected_result: TieredStorageResult<StoredAccountsInfo>,
    ) {
        let slot_ignored = Slot::MAX;
        let account_refs = Vec::<(&Pubkey, &AccountSharedData)>::new();
        let storable_accounts = (slot_ignored, account_refs.as_slice());

        let result = tiered_storage.write_accounts(&storable_accounts, 0, &HOT_FORMAT);

        match (&result, &expected_result) {
            (
                Err(TieredStorageError::AttemptToUpdateReadOnly(_)),
                Err(TieredStorageError::AttemptToUpdateReadOnly(_)),
            ) => {}
            (Err(TieredStorageError::Unsupported()), Err(TieredStorageError::Unsupported())) => {}
            (Ok(_), Ok(_)) => {}
            // we don't expect error type mis-match or other error types here
            _ => {
                panic!("actual: {result:?}, expected: {expected_result:?}");
            }
        };

        assert!(tiered_storage.is_read_only());
        assert_eq!(
            tiered_storage.len(),
            std::mem::size_of::<TieredStorageFooter>()
                + std::mem::size_of::<TieredStorageMagicNumber>()
        );
    }

    #[test]
    fn test_new_meta_file_only() {
        // Generate a new temp path that is guaranteed to NOT already have a file.
        let temp_dir = tempdir().unwrap();
        let tiered_storage_path = temp_dir.path().join("test_new_meta_file_only");

        {
            let tiered_storage =
                ManuallyDrop::new(TieredStorage::new_writable(&tiered_storage_path));

            assert!(!tiered_storage.is_read_only());
            assert_eq!(tiered_storage.path(), tiered_storage_path);
            assert_eq!(tiered_storage.len(), 0);

            write_zero_accounts(
                &tiered_storage,
                Ok(StoredAccountsInfo {
                    offsets: vec![],
                    size: 0,
                }),
            );
        }

        let tiered_storage_readonly = TieredStorage::new_readonly(&tiered_storage_path).unwrap();
        let footer = tiered_storage_readonly.footer().unwrap();
        assert!(tiered_storage_readonly.is_read_only());
        assert_eq!(tiered_storage_readonly.reader().unwrap().num_accounts(), 0);
        assert_eq!(footer.account_meta_format, HOT_FORMAT.account_meta_format);
        assert_eq!(footer.owners_block_format, HOT_FORMAT.owners_block_format);
        assert_eq!(footer.index_block_format, HOT_FORMAT.index_block_format);
        assert_eq!(footer.account_block_format, HOT_FORMAT.account_block_format);
        assert_eq!(
            tiered_storage_readonly.len(),
            std::mem::size_of::<TieredStorageFooter>()
                + std::mem::size_of::<TieredStorageMagicNumber>()
        );
    }

    #[test]
    #[should_panic(expected = "cannot write same tiered storage file more than once")]
    fn test_write_accounts_twice() {
        // Generate a new temp path that is guaranteed to NOT already have a file.
        let temp_dir = tempdir().unwrap();
        let tiered_storage_path = temp_dir.path().join("test_write_accounts_twice");

        let tiered_storage = TieredStorage::new_writable(&tiered_storage_path);
        write_zero_accounts(
            &tiered_storage,
            Ok(StoredAccountsInfo {
                offsets: vec![],
                size: 0,
            }),
        );
        // Expect AttemptToUpdateReadOnly error as write_accounts can only
        // be invoked once.
        write_zero_accounts(
            &tiered_storage,
            Err(TieredStorageError::AttemptToUpdateReadOnly(
                tiered_storage_path,
            )),
        );
    }

    #[test]
    fn test_remove_on_drop() {
        // Generate a new temp path that is guaranteed to NOT already have a file.
        let temp_dir = tempdir().unwrap();
        let tiered_storage_path = temp_dir.path().join("test_remove_on_drop");
        {
            let tiered_storage = TieredStorage::new_writable(&tiered_storage_path);
            write_zero_accounts(
                &tiered_storage,
                Ok(StoredAccountsInfo {
                    offsets: vec![],
                    size: 0,
                }),
            );
        }
        // expect the file does not exists as it has been removed on drop
        assert!(!tiered_storage_path.try_exists().unwrap());

        {
            let tiered_storage =
                ManuallyDrop::new(TieredStorage::new_writable(&tiered_storage_path));
            write_zero_accounts(
                &tiered_storage,
                Ok(StoredAccountsInfo {
                    offsets: vec![],
                    size: 0,
                }),
            );
        }
        // expect the file exists as we have ManuallyDrop this time.
        assert!(tiered_storage_path.try_exists().unwrap());

        {
            // open again in read-only mode with ManuallyDrop.
            _ = ManuallyDrop::new(TieredStorage::new_readonly(&tiered_storage_path).unwrap());
        }
        // again expect the file exists as we have ManuallyDrop.
        assert!(tiered_storage_path.try_exists().unwrap());

        {
            // open again without ManuallyDrop in read-only mode
            _ = TieredStorage::new_readonly(&tiered_storage_path).unwrap();
        }
        // expect the file does not exist as the file has been removed on drop
        assert!(!tiered_storage_path.try_exists().unwrap());
    }

    /// The helper function for all write_accounts tests.
    /// Currently only supports hot accounts.
    fn do_test_write_accounts(
        path_suffix: &str,
        account_data_sizes: &[u64],
        format: TieredStorageFormat,
    ) {
        let accounts: Vec<_> = account_data_sizes
            .iter()
            .map(|size| create_test_account(*size))
            .collect();

        let account_refs: Vec<_> = accounts
            .iter()
            .map(|account| (&account.0.pubkey, &account.1))
            .collect();

        // Slot information is not used here
        let storable_accounts = (Slot::MAX, &account_refs[..]);

        let temp_dir = tempdir().unwrap();
        let tiered_storage_path = temp_dir.path().join(path_suffix);
        let tiered_storage = TieredStorage::new_writable(tiered_storage_path);
        _ = tiered_storage.write_accounts(&storable_accounts, 0, &format);

        let reader = tiered_storage.reader().unwrap();
        let num_accounts = storable_accounts.len();
        assert_eq!(reader.num_accounts(), num_accounts);

        let mut expected_accounts_map = HashMap::new();
        for i in 0..num_accounts {
            storable_accounts.account_default_if_zero_lamport(i, |account| {
                expected_accounts_map.insert(*account.pubkey(), account.to_account_shared_data());
            });
        }

        let mut verified_accounts = HashSet::new();
        let footer = reader.footer();

        const MIN_PUBKEY: Pubkey = Pubkey::new_from_array([0x00u8; 32]);
        const MAX_PUBKEY: Pubkey = Pubkey::new_from_array([0xFFu8; 32]);
        let mut min_pubkey = MAX_PUBKEY;
        let mut max_pubkey = MIN_PUBKEY;

        reader
            .scan_accounts(|stored_account_meta| {
                if let Some(account) = expected_accounts_map.get(stored_account_meta.pubkey()) {
                    verify_test_account_with_footer(
                        &stored_account_meta,
                        account,
                        stored_account_meta.pubkey(),
                        footer,
                    );
                    verified_accounts.insert(*stored_account_meta.pubkey());
                    if min_pubkey > *stored_account_meta.pubkey() {
                        min_pubkey = *stored_account_meta.pubkey();
                    }
                    if max_pubkey < *stored_account_meta.pubkey() {
                        max_pubkey = *stored_account_meta.pubkey();
                    }
                }
            })
            .unwrap();

        assert_eq!(footer.min_account_address, min_pubkey);
        assert_eq!(footer.max_account_address, max_pubkey);
        assert!(!verified_accounts.is_empty());
        assert_eq!(verified_accounts.len(), expected_accounts_map.len());
    }

    #[test]
    fn test_write_accounts_small_accounts() {
        do_test_write_accounts(
            "test_write_accounts_small_accounts",
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            HOT_FORMAT.clone(),
        );
    }

    #[test]
    fn test_write_accounts_one_max_len() {
        do_test_write_accounts(
            "test_write_accounts_one_max_len",
            &[MAX_PERMITTED_DATA_LENGTH],
            HOT_FORMAT.clone(),
        );
    }

    #[test]
    fn test_write_accounts_mixed_size() {
        do_test_write_accounts(
            "test_write_accounts_mixed_size",
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1000, 2000, 3000, 4000, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ],
            HOT_FORMAT.clone(),
        );
    }
}
