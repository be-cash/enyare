use bitcoin_cash::{
    ByteArray, Opcode::*, Pubkey, SigHashFlags,
};

pub struct PartyParams {
    pub pk: Pubkey,
    pub forkid: u32,
}

pub struct Params {
    pub alice: PartyParams,
    pub bob: PartyParams,
    pub sig_hash_flags: SigHashFlags,
}

#[bitcoin_cash::script(SplitCoinsInput)]
pub fn script(
    params: &Params,

    sig: ByteArray,
    
    /// BIP143 preimage signed for this input.
    tx_preimage_1_9: ByteArray,

    is_alice: bool,
) {
    let alice_pk = params.alice.pk;
    let bob_pk = params.bob.pk;

    OP_ROT(is_alice, __, __);

    OP_IF(is_alice); {
        OP_DROP(bob_pk);
        let (pk, __) = OP_SWAP(tx_preimage_1_9, alice_pk);
        let _sighash_type = params.alice.sighash_type(params.sig_hash_flags);
    } OP_ELSE; {
        OP_NIP(alice_pk, __);
        let (pk, __) = OP_SWAP(tx_preimage_1_9, bob_pk);
        let _sighash_type = params.bob.sighash_type(params.sig_hash_flags);
    } OP_ENDIF;

    let tx_preimage = OP_CAT(tx_preimage_1_9, _sighash_type);
    let tx_preimage_hash = OP_SHA256(tx_preimage);

    OP_3DUP(sig, pk, tx_preimage_hash);
    OP_SWAP(pk, tx_preimage_hash);
    OP_CHECKDATASIGVERIFY(sig, tx_preimage_hash, pk);
    OP_DROP(tx_preimage_hash);
    OP_SWAP(sig, pk);
    
    let sig_hash_flags = &[params.sig_hash_flags.bits() as u8];
    let sig_flagged = OP_CAT(sig, sig_hash_flags);
    OP_SWAP(pk, sig_flagged);

    OP_CODESEPARATOR();
    OP_CHECKSIG(sig_flagged, pk);
}

impl PartyParams {
    pub fn sighash_type(&self, sig_hash_flags: SigHashFlags) -> [u8; 4] {
        (sig_hash_flags.bits() | (self.forkid << 8)).to_le_bytes()
    }
}
