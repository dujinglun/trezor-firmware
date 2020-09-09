from trezor.crypto.hashlib import sha256
from trezor.messages.SignTx import SignTx
from trezor.messages.TransactionType import TransactionType
from trezor.messages.TxInputType import TxInputType
from trezor.messages.TxOutputType import TxOutputType
from trezor.utils import HashWriter

from apps.common import coininfo

from .. import scripts, writers

if False:
    from typing import List, Union


# BIP-0143 hash
class Hash143:
    def __init__(self) -> None:
        self.h_prevouts = HashWriter(sha256())
        self.h_sequence = HashWriter(sha256())
        self.h_outputs = HashWriter(sha256())

    def add_input(self, txi: TxInputType) -> None:
        writers.write_bytes_reversed(
            self.h_prevouts, txi.prev_hash, writers.TX_HASH_SIZE
        )
        writers.write_uint32(self.h_prevouts, txi.prev_index)
        writers.write_uint32(self.h_sequence, txi.sequence)

    def add_output(self, txo: TxOutputType, script_pubkey: bytes) -> None:
        writers.write_tx_output(self.h_outputs, txo, script_pubkey)

    def preimage_hash(
        self,
        txi: TxInputType,
        public_keys: List[bytes],
        threshold: int,
        tx: Union[SignTx, TransactionType],
        coin: coininfo.CoinInfo,
        sighash_type: int,
    ) -> bytes:
        h_preimage = HashWriter(sha256())

        # nVersion
        writers.write_uint32(h_preimage, tx.version)

        # hashPrevouts
        prevouts_hash = writers.get_tx_hash(
            self.h_prevouts, double=coin.sign_hash_double
        )
        writers.write_bytes_fixed(h_preimage, prevouts_hash, writers.TX_HASH_SIZE)

        # hashSequence
        sequence_hash = writers.get_tx_hash(
            self.h_sequence, double=coin.sign_hash_double
        )
        writers.write_bytes_fixed(h_preimage, sequence_hash, writers.TX_HASH_SIZE)

        # outpoint
        writers.write_bytes_reversed(h_preimage, txi.prev_hash, writers.TX_HASH_SIZE)
        writers.write_uint32(h_preimage, txi.prev_index)

        # scriptCode
        script_code = scripts.bip143_derive_script_code(
            txi, public_keys, threshold, coin
        )
        writers.write_bytes_prefixed(h_preimage, script_code)

        # amount
        writers.write_uint64(h_preimage, txi.amount)

        # nSequence
        writers.write_uint32(h_preimage, txi.sequence)

        # hashOutputs
        outputs_hash = writers.get_tx_hash(self.h_outputs, double=coin.sign_hash_double)
        writers.write_bytes_fixed(h_preimage, outputs_hash, writers.TX_HASH_SIZE)

        # nLockTime
        writers.write_uint32(h_preimage, tx.lock_time)

        # nHashType
        writers.write_uint32(h_preimage, sighash_type)

        return writers.get_tx_hash(h_preimage, double=coin.sign_hash_double)