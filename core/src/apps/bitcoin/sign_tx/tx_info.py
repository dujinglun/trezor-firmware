from micropython import const

from trezor.crypto.hashlib import sha256
from trezor.utils import HashWriter

from .. import common, writers
from ..common import BIP32_WALLET_DEPTH, input_is_external
from .matchcheck import MultisigFingerprintChecker, WalletPathChecker

if False:
    from typing import Optional
    from trezor.messages.SignTx import SignTx
    from trezor.messages.PrevTx import PrevTx
    from trezor.messages.TxInput import TxInput
    from trezor.messages.TxOutput import TxOutput
    from .hash143 import Hash143


# The chain id used for change.
_BIP32_CHANGE_CHAIN = const(1)

# The maximum allowed change address. This should be large enough for normal
# use and still allow to quickly brute-force the correct BIP32 path.
_BIP32_MAX_LAST_ELEMENT = const(1000000)

# Setting nSequence to this value for every input in a transaction disables nLockTime.
_SEQUENCE_FINAL = const(0xFFFFFFFF)


class TxInfoBase:
    def __init__(self, hash143: Hash143) -> None:
        # Checksum of multisig inputs, used to validate change-output.
        self.multisig_fingerprint = MultisigFingerprintChecker()

        # Common prefix of input paths, used to validate change-output.
        self.wallet_path = WalletPathChecker()

        # h_tx_check is used to make sure that the inputs and outputs streamed in
        # different steps are the same every time, e.g. the ones streamed for approval
        # in Steps 1 and 2 and the ones streamed for signing legacy inputs in Step 4.
        self.h_tx_check = HashWriter(sha256())  # not a real tx hash

        # BIP-0143 transaction hashing.
        self.hash143 = hash143

        # The minimum nSequence of all inputs.
        self.min_sequence = _SEQUENCE_FINAL

    def add_input(self, txi: TxInput) -> None:
        self.hash143.add_input(txi)  # all inputs are included (non-segwit as well)
        writers.write_tx_input_check(self.h_tx_check, txi)
        self.min_sequence = min(self.min_sequence, txi.sequence)

        if not input_is_external(txi):
            self.wallet_path.add_input(txi)
            self.multisig_fingerprint.add_input(txi)

    def add_output(self, txo: TxOutput, script_pubkey: bytes) -> None:
        self.hash143.add_output(txo, script_pubkey)
        writers.write_tx_output(self.h_tx_check, txo, script_pubkey)

    def check_input(self, txi: TxInput) -> None:
        self.wallet_path.check_input(txi)
        self.multisig_fingerprint.check_input(txi)

    def output_is_change(self, txo: TxOutput) -> bool:
        if txo.script_type not in common.CHANGE_OUTPUT_SCRIPT_TYPES:
            return False
        if txo.multisig and not self.multisig_fingerprint.output_matches(txo):
            return False
        return (
            self.wallet_path.output_matches(txo)
            and len(txo.address_n) >= BIP32_WALLET_DEPTH
            and txo.address_n[-2] <= _BIP32_CHANGE_CHAIN
            and txo.address_n[-1] <= _BIP32_MAX_LAST_ELEMENT
            and txo.amount > 0
        )

    def lock_time_disabled(self) -> bool:
        return self.min_sequence == _SEQUENCE_FINAL


# Used to keep track of the transaction currently being signed.
class TxInfo(TxInfoBase):
    def __init__(self, tx: SignTx, hash143: Hash143) -> None:
        super().__init__(hash143)
        self.tx = tx

        # h_inputs is a digest of the inputs streamed for approval in Step 1, which
        # is used to ensure that the inputs streamed for verification in Step 3 are
        # the same as those in Step 1.
        self.h_inputs = None  # type: Optional[bytes]


# Used to keep track of any original transactions which are being replaced by the current transaction.
class OriginalTxInfo(TxInfoBase):
    def __init__(self, tx: PrevTx, hash143: Hash143) -> None:
        super().__init__(hash143)
        self.tx = tx

        # The current index when iterating over inputs or outputs.
        self.index = 0

        # The index of the input which will be used for verification.
        self.verification_index = None  # type: Optional[int]

    def add_input(self, txi: TxInput) -> None:
        super().add_input(txi)

        # For verification use the first input that specifies address_n.
        if self.verification_index is None and txi.address_n:
            self.verification_index = self.index
