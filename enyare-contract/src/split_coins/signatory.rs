use bitcoin_cash::{
    ByteArray, Script, SigHashFlags, Signatory, TxBuilder, TxOutput, TxPreimage, MAX_SIGNATURE_SIZE,
};

use super::script::SplitCoinsInput;

#[derive(Clone, Debug)]
pub struct SplitCoinsSignatory {
    pub is_alice: bool,
    pub sig_hash_flags: SigHashFlags,
}

impl Signatory for SplitCoinsSignatory {
    type Script = SplitCoinsInput;
    type Signatures = ByteArray;
    fn sig_hash_flags(&self) -> Vec<SigHashFlags> {
        vec![self.sig_hash_flags]
    }
    fn placeholder_signatures(&self) -> Self::Signatures {
        vec![0; MAX_SIGNATURE_SIZE].into()
    }
    fn build_script(
        &self,
        tx_preimages: &[TxPreimage],
        _unsigned_tx: &TxBuilder,
        sig: Self::Signatures,
        _lock_script: &Script,
        _tx_outputs: &[TxOutput],
    ) -> Self::Script {
        let tx_preimage = tx_preimages[0].to_byte_array();
        let tx_preimage_len = tx_preimage.len();
        SplitCoinsInput {
            sig,
            tx_preimage_1_9: tx_preimage
                .split(tx_preimage_len - std::mem::size_of::<u32>())
                .expect("invalid preimage")
                .0,
            is_alice: self.is_alice,
        }
    }
}
