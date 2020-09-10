use enyare_contract::split_coins;
use bitcoin_cash::{Sha256d, TxOutpoint, TxBuilder, UnsignedTxInput, SigHashFlags, ECC, TaggedScript};
use bitcoin_cash::*;
use bitcoin_cash_ecc::init_ecc;
use iguana_ws::run_iguana_ws;

fn main() {
    run_iguana_ws(|| {
        let ecc = init_ecc();
        let alice_sk = &[12; 32];
        let bob_sk = &[13; 32];
        let alice_pk = ecc.derive_pubkey(alice_sk.as_ref()).unwrap();
        let bob_pk = ecc.derive_pubkey(bob_sk.as_ref()).unwrap();

        let future_amount = 10_000;

        let alice_forkid = 0;  // forkid of chain that didn't add replay protection
        let bob_forkid = 1;    // forkid of chain that added replay protection

        let is_alice = true;
        let sig_hash_flags = SigHashFlags::DEFAULT;
        
        let params = split_coins::script::Params {
            sig_hash_flags,
            alice: split_coins::script::PartyParams {
                pk: alice_pk.clone(),
                forkid: alice_forkid,
            },
            bob: split_coins::script::PartyParams {
                pk: bob_pk.clone(),
                forkid: bob_forkid,
            },
        };

        let tagged_script: TaggedScript<_> = split_coins::script::script(&params);

        let mut tx_builder = TxBuilder::new_simple();
        let future_token = tx_builder.add_input(
            UnsignedTxInput {
                prev_out: TxOutpoint {
                    tx_hash: Sha256d::new([1; 32]),
                    vout: 0,
                },
                sequence: 0xffff_ffff,
                value: future_amount,
            },
            tagged_script.clone(),
            split_coins::signatory::SplitCoinsSignatory {
                is_alice,
                sig_hash_flags,
            },
        );

        let mut unsigned_tx = tx_builder.build().unwrap();
        
        let tx_preimages = unsigned_tx.preimages();
        let mut tx_preimage = tx_preimages[0][0].clone();

        tx_preimage.sig_hash_type = u32::from_le_bytes(
            if is_alice { params.alice.sighash_type(sig_hash_flags) }
            else {params.bob.sighash_type(sig_hash_flags)}
        );

        let sig = ecc
            .sign(
                if is_alice { &alice_sk[..] } else { &bob_sk[..] },
                Sha256d::digest(tx_preimage.to_byte_array()),
            )
            .unwrap()
            .named("sig");
        unsigned_tx.sign_input(future_token, sig);
        let tx = unsigned_tx.complete_tx();
        Ok(tx)
    });
}
