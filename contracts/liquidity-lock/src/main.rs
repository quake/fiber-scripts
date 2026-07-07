#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

use ckb_hash::blake2b_256;
#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!();

use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, prelude::*},
    error::SysError,
    high_level::{
        load_cell_capacity, load_cell_data, load_cell_lock, load_cell_type, load_script,
        load_witness,
    },
};

#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    ArgsLenError,
    WitnessLenError,
    InvalidSince,
    InvalidUnlockType,
    PreimageHashError,
    OutputLockError,
    OutputCapacityError,
    OutputTypeError,
    OutputUdtAmountError,
    GroupInputCountError,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        match err {
            SysError::IndexOutOfBound => Self::IndexOutOfBound,
            SysError::ItemMissing => Self::ItemMissing,
            SysError::LengthNotEnough(_) => Self::LengthNotEnough,
            SysError::Encoding => Self::Encoding,
            SysError::Unknown(err_code) => panic!("unexpected sys error {}", err_code),
            _ => panic!("unreachable spawn related sys error"),
        }
    }
}

pub fn program_entry() -> i8 {
    match verify() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

const ARGS_LEN: usize = 32 + 32 + 32 + 8 + 16 + 32;
const EMPTY_WITNESS_ARGS: [u8; 16] = [16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0];
const UNLOCK_CLAIM: u8 = 1;
const UNLOCK_REFUND: u8 = 2;
const PREIMAGE_LEN: usize = 32;
const CKB_ASSET_TYPE_HASH: [u8; 32] = [0u8; 32];

struct Args(Bytes);

impl Args {
    fn load() -> Result<Self, Error> {
        let script = load_script()?;
        let args: Bytes = script.args().unpack();
        if args.len() != ARGS_LEN {
            return Err(Error::ArgsLenError);
        }
        Ok(Self(args))
    }

    fn payment_hash(&self) -> &[u8] {
        &self.0[0..32]
    }

    fn claimant_lock_hash(&self) -> &[u8] {
        &self.0[32..64]
    }

    fn refund_lock_hash(&self) -> &[u8] {
        &self.0[64..96]
    }

    fn refund_after_lock_time(&self) -> u64 {
        u64::from_le_bytes(self.0[96..104].try_into().unwrap())
    }

    fn amount(&self) -> u128 {
        u128::from_le_bytes(self.0[104..120].try_into().unwrap())
    }

    fn asset_type_hash(&self) -> &[u8] {
        &self.0[120..152]
    }

    fn is_ckb(&self) -> bool {
        self.asset_type_hash() == CKB_ASSET_TYPE_HASH
    }
}

fn verify() -> Result<(), Error> {
    let args = Args::load()?;
    match load_cell_lock(1, Source::GroupInput) {
        Err(SysError::IndexOutOfBound) => {}
        Err(err) => return Err(err.into()),
        Ok(_) => return Err(Error::GroupInputCountError),
    }
    verify_cell_asset(&args, Source::GroupInput)?;

    let witness = load_witness(0, Source::GroupInput)?;
    if witness.len() < EMPTY_WITNESS_ARGS.len() + 1 {
        return Err(Error::WitnessLenError);
    }
    if witness[0..EMPTY_WITNESS_ARGS.len()] != EMPTY_WITNESS_ARGS {
        return Err(Error::WitnessLenError);
    }
    match witness[EMPTY_WITNESS_ARGS.len()] {
        UNLOCK_CLAIM => verify_claim(&args, witness.as_slice()),
        UNLOCK_REFUND => verify_refund(&args, witness.as_slice()),
        _ => Err(Error::InvalidUnlockType),
    }
}

fn verify_claim(args: &Args, witness: &[u8]) -> Result<(), Error> {
    let expected_len = EMPTY_WITNESS_ARGS.len() + 1 + PREIMAGE_LEN;
    if witness.len() != expected_len {
        return Err(Error::WitnessLenError);
    }

    let preimage_start = EMPTY_WITNESS_ARGS.len() + 1;
    let preimage = &witness[preimage_start..preimage_start + PREIMAGE_LEN];
    if blake2b_256(preimage) != args.payment_hash() {
        return Err(Error::PreimageHashError);
    }

    let output_lock = load_cell_lock(0, Source::Output)?;
    if blake2b_256(output_lock.as_slice()) != args.claimant_lock_hash() {
        return Err(Error::OutputLockError);
    }
    verify_cell_asset(args, Source::Output)?;
    Ok(())
}

fn verify_refund(args: &Args, witness: &[u8]) -> Result<(), Error> {
    let expected_len = EMPTY_WITNESS_ARGS.len() + 1;
    if witness.len() != expected_len {
        return Err(Error::WitnessLenError);
    }
    if ckb_std::high_level::load_input_since(0, Source::GroupInput)?
        != args.refund_after_lock_time()
    {
        return Err(Error::InvalidSince);
    }

    let output_lock = load_cell_lock(0, Source::Output)?;
    if blake2b_256(output_lock.as_slice()) != args.refund_lock_hash() {
        return Err(Error::OutputLockError);
    }
    verify_cell_asset(args, Source::Output)?;
    Ok(())
}

fn verify_cell_asset(args: &Args, source: Source) -> Result<(), Error> {
    if args.is_ckb() {
        if load_cell_type(0, source)?.is_some() {
            return Err(Error::OutputTypeError);
        }
        if load_cell_capacity(0, source)? < u64::try_from(args.amount()).unwrap_or(u64::MAX) {
            return Err(Error::OutputCapacityError);
        }
        return Ok(());
    }

    let Some(output_type) = load_cell_type(0, source)? else {
        return Err(Error::OutputTypeError);
    };
    if blake2b_256(output_type.as_slice()) != args.asset_type_hash() {
        return Err(Error::OutputTypeError);
    }

    let output_data = load_cell_data(0, source)?;
    if output_data.len() < 16 {
        return Err(Error::OutputUdtAmountError);
    }
    let output_amount = u128::from_le_bytes(output_data[0..16].try_into().unwrap());
    if output_amount != args.amount() {
        return Err(Error::OutputUdtAmountError);
    }
    Ok(())
}
