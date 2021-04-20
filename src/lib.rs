#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{decl_module, decl_storage, decl_event, decl_error, dispatch, ensure, traits::Get, traits::Vec};
use frame_system::{ensure_signed, ensure_root};
use pallet_session::SessionManager;
use sp_runtime::traits::Convert;
use core::cmp::Reverse;
use sp_std::{
	prelude::*,
	convert::{From},
	str,
};
use codec::{Encode, Decode};
pub use merlin::Transcript;
use sha2::{Sha256, Digest};

// syntactic sugar for logging.
pub(crate) const LOG_TARGET: &'static str = "runtime::nars";
#[macro_export]
macro_rules! log {
	($level:tt, $patter:expr $(, $values:expr)* $(,)?) => {
		log::$level!(
			target: crate::LOG_TARGET,
			concat!("[{:?}] 💸 ", $patter), <frame_system::Pallet<T>>::block_number() $(, $values)*
		)
	};
}

/// Configure the pallet by specifying the parameters and types on which it depends.
pub trait Config: pallet_babe::Config + frame_system::Config {
	/// Because this pallet emits events, it depends on the runtime's definition of an event.
	type Event: From<Event<Self>> + Into<<Self as frame_system::Config>::Event>;
}

/// Compatibility code for the session historical code
pub type FullIdentification = u32;
pub struct FullIdentificationOf<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> Convert<T::AccountId, Option<FullIdentification>> for FullIdentificationOf<T> {
    fn convert(_validator: T::AccountId) -> Option<FullIdentification> {
        Some(0)
    }
}

#[derive(PartialEq, Eq, Clone, Encode, Decode)]
pub struct VrfProof {
	public_key: Vec<u8>,
	signature: Vec<u8>,
	proof: Vec<u8>
}

impl Default for VrfProof {
	fn default() -> Self {
		VrfProof {
			public_key: Default::default(),
			signature: Default::default(),
			proof: Default::default(),
		}
	}
}

type SessionIndex = u32; // A shim while waiting for this type to be exposed by `session`
impl<T: Config> SessionManager<T::AccountId> for Module<T> {
    fn new_session(_: SessionIndex) -> Option<Vec<T::AccountId>> {
		// ------------------------------------------------------------------------------
		let mut missed_accounts: Vec<T::AccountId> = Vec::new();
		let randomness = <pallet_babe::Module<T>>::current_epoch().randomness;

		let kv_vector: Vec<_> = Proofs::<T>::iter().collect();
		for (k, v) in kv_vector.iter() {
			if !NextProofs::<T>::contains_key(k) {
				let concat_arrs = [(randomness.to_vec() as Vec<u8>).as_slice(), v.signature.as_slice()].concat();
				let res_arr = concat_arrs.as_slice();
				let mut hasher = Sha256::new();
				hasher.update(res_arr);
				let new_signature = hasher.finalize();

				NextProofs::<T>::insert(k.clone(), VrfProof {
					public_key: v.public_key.clone(),
					signature: new_signature.to_vec(),
					proof: v.proof.clone(),
				});

				missed_accounts.push(k.clone());
			}
		}
		Self::deposit_event(RawEvent::MissedProofsStored(missed_accounts));
		// ------------------------------------------------------------------------------

		let mut purgers = <Purgers<T>>::get();
		purgers.clear();
		<Purgers<T>>::put(&purgers);
		for (k, _) in Proofs::<T>::iter() {
			Proofs::<T>::remove(k.clone());
		}
		for (k, v) in NextProofs::<T>::iter() {
			Proofs::<T>::insert(k.clone(), v.clone());
			NextProofs::<T>::remove(k.clone());
		}

		Some(Self::get_validators_sorted_by_proof())
    }

    fn start_session(_: SessionIndex) {}
    fn end_session(_: SessionIndex) {}
}

impl<T: Config> pallet_session::historical::SessionManager<T::AccountId, FullIdentification>
    for Module<T>
{
    fn new_session(new_index: SessionIndex) -> Option<Vec<(T::AccountId, FullIdentification)>> {
        <Self as pallet_session::SessionManager<_>>::new_session(new_index).map(|validators| {
            validators
                .into_iter()
                .map(|v| {
                    let full_identification =
                        FullIdentificationOf::<T>::convert(v.clone()).unwrap_or(0);
                    (v, full_identification)
                })
                .collect()
        })
    }

    fn start_session(start_index: SessionIndex) {
        <Self as pallet_session::SessionManager<_>>::start_session(start_index)
    }

    fn end_session(end_index: SessionIndex) {
        <Self as pallet_session::SessionManager<_>>::end_session(end_index)
    }
}


decl_storage! {
	trait Store for Module<T: Config> as Nars {
		Proofs get(fn proofs): map hasher(blake2_128_concat) T::AccountId => VrfProof;
		NextProofs get(fn next_proofs): map hasher(blake2_128_concat) T::AccountId => VrfProof;
		ValidatorsCount get(fn validators_count) config(): u32;
		Purgers get(fn purgers): Vec<T::AccountId>;
	}
	add_extra_genesis {
		config(initials): Vec<(T::AccountId, u32, u64)>;
		build(|config| {
			for &(ref account, public_key_bytes, initial_proof) in &config.initials {
				Proofs::<T>::insert(account.clone(), VrfProof {
					public_key: public_key_bytes.to_be_bytes().to_vec(),
					signature: initial_proof.to_be_bytes().to_vec(),
					proof: initial_proof.to_be_bytes().to_vec()
				});
			}
		})
	}
}


decl_event!(
	pub enum Event<T> where AccountId = <T as frame_system::Config>::AccountId {
		ProofStored(Vec<u8>, AccountId),
		MissedProofsStored(Vec<AccountId>),
		ValidatorsCountStored(u32),
		ProofsSorted(Vec<AccountId>),
		DebugEventMethodCalled(sp_consensus_vrf::schnorrkel::Randomness),
		Verified(bool),
		ProofPurged(AccountId),
	}
);

// Errors inform users that something went wrong.
decl_error! {
	pub enum Error for Module<T: Config> {
		/// Error names should be descriptive.
		NoneValue,
		LowValidatorsCount,
		BadVrfProof,
		ProofAlreadySet,
		AlreadyPurged
	}
}

// Dispatchable functions allows users to interact with the pallet and invoke state changes.
// These functions materialize as "extrinsics", which are often compared to transactions.
// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
decl_module! {
	pub struct Module<T: Config> for enum Call where origin: T::Origin {
		// Errors must be initialized if they are used by the pallet.
		type Error = Error<T>;

		// Events must be initialized if they are used by the pallet.
		fn deposit_event() = default;

		#[weight = 10_000 + T::DbWeight::get().writes(1)]
		pub fn set_proof(origin, public_key_bytes: Vec<u8>, signature: Vec<u8>, proof: Vec<u8>) -> dispatch::DispatchResult {
			let who = ensure_signed(origin)?;
			ensure!(
				!NextProofs::<T>::contains_key(&who),
				Error::<T>::ProofAlreadySet
			);
			let purgers = <Purgers<T>>::get();
			purgers.binary_search(&who).err().ok_or(Error::<T>::AlreadyPurged)?;
			let vrf_output = schnorrkel::vrf::VRFPreOut::from_bytes(&signature).unwrap();
			let vrf_proof = schnorrkel::vrf::VRFProof::from_bytes(&proof).unwrap();

			let verified = schnorrkel::PublicKey::from_bytes(&public_key_bytes).and_then(|p| {
				p.vrf_verify(schnorrkel::signing_context(&Vec::<u8>::new()).bytes(&<pallet_babe::Module<T>>::current_epoch().randomness), &vrf_output, &vrf_proof)
			});
			ensure!(verified.is_ok(), Error::<T>::BadVrfProof);

			NextProofs::<T>::insert(&who, VrfProof {
				public_key: public_key_bytes,
				signature: signature.clone(),
				proof: proof
			});
			Self::deposit_event(RawEvent::ProofStored(signature, who));
			Ok(())
		}

		#[weight = 10_000 + T::DbWeight::get().writes(1)]
		pub fn purge_proof(origin) -> dispatch::DispatchResult {
			let who = ensure_signed(origin)?;
			let mut purgers = <Purgers<T>>::get();
			let location = purgers.binary_search(&who).err().ok_or(Error::<T>::AlreadyPurged)?;
			purgers.insert(location, who.clone());
			<Purgers<T>>::put(&purgers);
			NextProofs::<T>::remove(&who); // TODO Should we check existing?
			Self::deposit_event(RawEvent::ProofPurged(who));
			Ok(())
		}

		#[weight = 10_000 + T::DbWeight::get().writes(1)]
		pub fn set_validators_count(origin, value: u32) -> dispatch::DispatchResult {
			ensure_root(origin)?;
			ensure!(value >= 2, Error::<T>::LowValidatorsCount);
			ValidatorsCount::put(value);
			Self::deposit_event(RawEvent::ValidatorsCountStored(value));
			Ok(())
		}

		#[weight = 10_000]
		pub fn debug_get_sorted(origin) -> dispatch::DispatchResult {
			let sorted = Self::get_validators_sorted_by_proof();
			Self::deposit_event(RawEvent::ProofsSorted(sorted));
			Ok(())
		}

		#[weight = 10_000]
		pub fn debug_call_babe_method(origin) -> dispatch::DispatchResult {
			let rand = <pallet_babe::Module<T>>::current_epoch().randomness;
			Self::deposit_event(RawEvent::DebugEventMethodCalled(rand));
			Ok(())
		}

		#[weight  = 20_000]
		pub fn debug_verify(origin, public_key_bytes: Vec<u8>, signature: Vec<u8>, proof: Vec<u8>) -> dispatch::DispatchResult {
			ensure_signed(origin)?;
			let vrf_output = schnorrkel::vrf::VRFPreOut::from_bytes(&signature).unwrap();
			let vrf_proof = schnorrkel::vrf::VRFProof::from_bytes(&proof).unwrap();
			let verified = schnorrkel::PublicKey::from_bytes(&public_key_bytes).and_then(|p| {
				p.vrf_verify(schnorrkel::signing_context(&Vec::<u8>::new()).bytes(&<pallet_babe::Module<T>>::current_epoch().randomness), &vrf_output, &vrf_proof)
			});
			Self::deposit_event(RawEvent::Verified(verified.is_ok()));
			Ok(())
		}
	}
}

impl<T: Config> Module<T> {
	fn get_validators_sorted_by_proof() -> Vec<T::AccountId> {
		let mut kv_vector: Vec<_> = Proofs::<T>::iter().collect();
		// T::AccountId
		kv_vector.sort_by_key(|a| Reverse(sp_core::U256::from_big_endian(a.1.signature.as_slice())));
		let mut sorted: Vec<T::AccountId> = Vec::new();
		for (account, _) in kv_vector.iter() {
			sorted.push(account.clone());
		}
		let size = ValidatorsCount::get() as usize;
		if sorted.len() >= size {
			(&sorted[0..size]).to_vec()
		} else {
			sorted
		}
	}
}
