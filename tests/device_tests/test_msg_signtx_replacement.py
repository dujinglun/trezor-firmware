# This file is part of the Trezor project.
#
# Copyright (C) 2020 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import pytest

from trezorlib import btc, messages
from trezorlib.tools import parse_path

from ..tx_cache import TxCache
from .signtx import (
    request_finished,
    request_input,
    request_meta,
    request_orig_input,
    request_orig_output,
    request_output,
)

B = messages.ButtonRequestType

TX_CACHE_TESTNET = TxCache("Testnet")
TX_CACHE_MAINNET = TxCache("Bitcoin")

TXHASH_50f6f1 = bytes.fromhex(
    "50f6f1209ca92d7359564be803cb2c932cde7d370f7cee50fd1fad6790f6206d"
)
TXHASH_beafc7 = bytes.fromhex(
    "beafc7cbd873d06dbee88a7002768ad5864228639db514c81cfb29f108bb1e7a"
)


@pytest.mark.skip_t1
def test_p2pkh_fee_bump(client):
    inp1 = messages.TxInputType(
        address_n=parse_path("44h/0h/0h/0/4"),
        amount=174998,
        prev_hash=TXHASH_beafc7,
        prev_index=0,
        orig_hash=TXHASH_50f6f1,
        orig_index=0,
    )

    out1 = messages.TxOutputType(
        address_n=parse_path("44h/0h/0h/1/2"),
        amount=174998 - 50000 - 15000,  # Originally fee was 11300, now 15000.
        script_type=messages.OutputScriptType.PAYTOADDRESS,
        orig_hash=TXHASH_50f6f1,
        orig_index=0,
    )

    out2 = messages.TxOutputType(
        address="1GA9u9TfCG7SWmKCveBumdA1TZpfom6ZdJ",
        amount=50000,
        script_type=messages.OutputScriptType.PAYTOADDRESS,
        orig_hash=TXHASH_50f6f1,
        orig_index=1,
    )

    with client:
        client.set_expected_responses(
            [
                request_input(0),
                request_meta(TXHASH_50f6f1),
                request_orig_input(0, TXHASH_50f6f1),
                request_output(0),
                request_orig_output(0, TXHASH_50f6f1),
                request_output(1),
                request_orig_output(1, TXHASH_50f6f1),
                messages.ButtonRequest(code=B.SignTx),
                messages.ButtonRequest(code=B.SignTx),
                request_input(0),
                request_meta(TXHASH_beafc7),
                request_input(0, TXHASH_beafc7),
                request_output(0, TXHASH_beafc7),
                request_orig_input(0, TXHASH_50f6f1),
                request_orig_input(0, TXHASH_50f6f1),
                request_orig_output(0, TXHASH_50f6f1),
                request_orig_output(1, TXHASH_50f6f1),
                request_input(0),
                request_output(0),
                request_output(1),
                request_output(0),
                request_output(1),
                request_finished(),
            ]
        )
        _, serialized_tx = btc.sign_tx(
            client, "Bitcoin", [inp1], [out1, out2], prev_txes=TX_CACHE_MAINNET,
        )
