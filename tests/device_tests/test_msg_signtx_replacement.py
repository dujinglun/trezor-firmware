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
TXHASH_65b768 = bytes.fromhex(
    "65b768dacccfb209eebd95a1fb80a04f1dd6a3abc6d7b41d5e9d9f91605b37d9"
)
TXHASH_e4b5b2 = bytes.fromhex(
    "e4b5b24159856ea18ab5819832da3b4a6330f9c3c0a46d96674e632df504b56b"
)
TXHASH_70f987 = bytes.fromhex(
    "70f9871eb03a38405cfd7a01e0e1448678132d815e2c9f552ad83ae23969509e"
)
TXHASH_334cd7 = bytes.fromhex(
    "334cd7ad982b3b15d07dd1c84e939e95efb0803071648048a7f289492e7b4c8a"
)
TXHASH_5e7667 = bytes.fromhex(
    "5e7667690076ae4737e2f872005de6f6b57592f32108ed9b301eeece6de24ad6"
)
TXHASH_efaa41 = bytes.fromhex(
    "efaa41ff3e67edf508846c1a1ed56894cfd32725c590300108f40c9edc1aac35"
)
TXHASH_ed89ac = bytes.fromhex(
    "ed89acb52cfa438e3653007478e7c7feae89fdde12867943eec91293139730d1"
)
TXHASH_6673b7 = bytes.fromhex(
    "6673b7248e324882b2f9d02fdd1ff1d0f9ed216a234e836b8d3ac65661cbb457"
)
TXHASH_927784 = bytes.fromhex(
    "927784e07bbcefc4c738f5c31c7a739978fc86f35514edf7e7da25d53d83030b"
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


@pytest.mark.skip_t1
def test_p2wpkh_payjoin(client):
    # Original input.
    inp1 = messages.TxInputType(
        address_n=parse_path("84h/1h/0h/0/0"),
        amount=100000,
        script_type=messages.InputScriptType.SPENDWITNESS,
        prev_hash=TXHASH_e4b5b2,
        prev_index=0,
        orig_hash=TXHASH_65b768,
        orig_index=0,
        sequence=1516634,
    )

    # New presigned external input. (Actually 84h/1h/0h/1/1, making it easier to generate witnesses.)
    inp2 = messages.TxInputType(
        amount=19899859,
        script_type=messages.InputScriptType.EXTERNAL,
        prev_hash=TXHASH_70f987,
        prev_index=1,
        witness=bytes.fromhex(
            "02483045022100eb74abb36f317d707c36d6fe1f4f73192d54417b9d5cd274e0077590833aad0a02206cf26621706aaf232c48a139910de71f7dbf17f3fb6af52a7222d19d88041e8b012102d587bc96e0ceab05f27401d66dc3e596ba02f2c0d7b018b5f80eebfaeb011012"
        ),
    )

    # PayJoined output.
    out1 = messages.TxOutputType(
        address="tb1qldlynaqp0hy4zc2aag3pkenzvxy65saesxw3wd",
        # Originally payment was 10000, now we add receiver's inp2.
        amount=10000 + 19899859,
        script_type=messages.OutputScriptType.PAYTOWITNESS,
        orig_hash=TXHASH_65b768,
        orig_index=0,
    )

    # Original change.
    out2 = messages.TxOutputType(
        address_n=parse_path("84h/1h/0h/1/2"),
        amount=100000 - 10000 - 141,
        script_type=messages.OutputScriptType.PAYTOWITNESS,
        orig_hash=TXHASH_65b768,
        orig_index=1,
    )

    # Expected responses when there is a sender fee bump.
    responses = [
        request_input(0),
        request_meta(TXHASH_65b768),
        request_orig_input(0, TXHASH_65b768),
        request_input(1),
        request_output(0),
        request_orig_output(0, TXHASH_65b768),
        request_output(1),
        request_orig_output(1, TXHASH_65b768),
        messages.ButtonRequest(code=B.SignTx),
        messages.ButtonRequest(code=B.SignTx),
        request_input(0),
        request_meta(TXHASH_e4b5b2),
        request_input(0, TXHASH_e4b5b2),
        request_output(0, TXHASH_e4b5b2),
        request_output(1, TXHASH_e4b5b2),
        request_input(1),
        request_meta(TXHASH_70f987),
        request_input(0, TXHASH_70f987),
        request_output(0, TXHASH_70f987),
        request_output(1, TXHASH_70f987),
        request_orig_input(0, TXHASH_65b768),
        request_input(0),
        request_input(1),
        request_output(0),
        request_output(1),
        request_input(0),
        request_input(1),
        request_finished(),
    ]

    # Scenario 1: No fee bump by sender or receiver.
    with client:
        client.set_expected_responses(responses)
        _, serialized_tx = btc.sign_tx(
            client,
            "Testnet",
            [inp1, inp2],
            [out1, out2],
            lock_time=1516634,
            prev_txes=TX_CACHE_TESTNET,
        )

    # Scenario 2: Sender fee bump only.
    out1.amount = 10000 + 19899859  # Receiver does not contribute to fee.
    out2.amount = 100000 - 10000 - 200  # Sender bumps fee from 141 to 200.
    inp2.witness = bytes.fromhex(
        "02483045022100af3a874c966ee595321e8699e7157f0b21f2542ddcdcafd06a9c2b4fd75e998b02206daecf235b5eb3c9dac088c904774cc0a61ac601c840efc5cbe00f99e1979a09012102d587bc96e0ceab05f27401d66dc3e596ba02f2c0d7b018b5f80eebfaeb011012"
    )
    with client:
        client.set_expected_responses(responses)
        _, serialized_tx = btc.sign_tx(
            client,
            "Testnet",
            [inp1, inp2],
            [out1, out2],
            lock_time=1516634,
            prev_txes=TX_CACHE_TESTNET,
        )

    # Scenario 3: Receiver fee bump.
    out1.amount = 10000 + 19899859 - 59  # Receiver contributes 59 to fee.
    out2.amount = 100000 - 10000 - 141  # Sender does not bump fee.
    inp2.witness = bytes.fromhex(
        "0248304502210097a42b35d3d16fa169667cd85a007eaf6b674495634b120d9fb62d72a0df872402203d0cdf746fd7a668276f93f660a9d052bc8a5d7cd8fea36073de38da463ece85012102d587bc96e0ceab05f27401d66dc3e596ba02f2c0d7b018b5f80eebfaeb011012"
    )
    with client:
        client.set_expected_responses(responses)
        _, serialized_tx = btc.sign_tx(
            client,
            "Testnet",
            [inp1, inp2],
            [out1, out2],
            lock_time=1516634,
            prev_txes=TX_CACHE_TESTNET,
        )


@pytest.mark.skip_t1
def test_p2wpkh_in_p2sh_remove_change(client):
    # Test fee bump with change-output removal. Originally fee was 3780, now 98060.

    inp1 = messages.TxInputType(
        address_n=parse_path("49h/1h/0h/0/4"),
        amount=100000,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
        prev_hash=TXHASH_5e7667,
        prev_index=1,
        orig_hash=TXHASH_334cd7,
        orig_index=0,
    )

    inp2 = messages.TxInputType(
        address_n=parse_path("49h/1h/0h/0/3"),
        amount=998060,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
        prev_hash=TXHASH_efaa41,
        prev_index=0,
        orig_hash=TXHASH_334cd7,
        orig_index=1,
    )

    out1 = messages.TxOutputType(
        # Actually m/49'/1'/0'/0/5.
        address="2MvUUSiQZDSqyeSdofKX9KrSCio1nANPDTe",
        amount=1000000,
        orig_hash=TXHASH_334cd7,
        orig_index=0,
    )

    with client:
        client.set_expected_responses(
            [
                request_input(0),
                request_meta(TXHASH_334cd7),
                request_orig_input(0, TXHASH_334cd7),
                request_input(1),
                request_orig_input(1, TXHASH_334cd7),
                request_output(0),
                request_orig_output(0, TXHASH_334cd7),
                request_orig_output(1, TXHASH_334cd7),
                messages.ButtonRequest(code=B.SignTx),
                messages.ButtonRequest(code=B.SignTx),
                request_input(0),
                request_meta(TXHASH_5e7667),
                request_input(0, TXHASH_5e7667),
                request_output(0, TXHASH_5e7667),
                request_output(1, TXHASH_5e7667),
                request_input(1),
                request_meta(TXHASH_efaa41),
                request_input(0, TXHASH_efaa41),
                request_output(0, TXHASH_efaa41),
                request_orig_input(0, TXHASH_334cd7),
                request_input(0),
                request_input(1),
                request_output(0),
                request_input(0),
                request_input(1),
                request_finished(),
            ]
        )
        _, serialized_tx = btc.sign_tx(
            client, "Testnet", [inp1, inp2], [out1], prev_txes=TX_CACHE_TESTNET,
        )


@pytest.mark.skip_t1
def test_tx_meld(client):
    # Meld two original transactions into one, joining the change-outputs into a different one.

    inp1 = messages.TxInputType(
        address_n=parse_path("49h/1h/0h/0/4"),
        amount=100000,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
        prev_hash=TXHASH_5e7667,
        prev_index=1,
        orig_hash=TXHASH_334cd7,
        orig_index=0,
    )

    inp2 = messages.TxInputType(
        address_n=parse_path("49h/1h/0h/0/8"),
        amount=4973340,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
        prev_hash=TXHASH_6673b7,
        prev_index=0,
        orig_hash=TXHASH_ed89ac,
        orig_index=0,
    )

    inp3 = messages.TxInputType(
        address_n=parse_path("49h/1h/0h/0/3"),
        amount=998060,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
        prev_hash=TXHASH_efaa41,
        prev_index=0,
        orig_hash=TXHASH_334cd7,
        orig_index=1,
    )

    inp4 = messages.TxInputType(
        address_n=parse_path("49h/1h/0h/0/9"),
        amount=839318869,
        script_type=messages.InputScriptType.SPENDP2SHWITNESS,
        prev_hash=TXHASH_927784,
        prev_index=0,
        orig_hash=TXHASH_ed89ac,
        orig_index=1,
    )

    out1 = messages.TxOutputType(
        address="moE1dVYvebvtaMuNdXQKvu4UxUftLmS1Gt",
        amount=100000000,
        orig_hash=TXHASH_ed89ac,
        orig_index=1,
    )

    out2 = messages.TxOutputType(
        # Actually m/49'/1'/0'/0/5.
        address="2MvUUSiQZDSqyeSdofKX9KrSCio1nANPDTe",
        amount=1000000,
        orig_hash=TXHASH_334cd7,
        orig_index=0,
    )

    # Change-output. Original fees were 3780 + 90720 = 94500.
    out3 = messages.TxOutputType(
        address_n=parse_path("49h/1h/0h/1/0"),
        amount=100000 + 4973340 + 998060 + 839318869 - 100000000 - 1000000 - 94500,
        script_type=messages.OutputScriptType.PAYTOP2SHWITNESS,
    )

    with client:
        client.set_expected_responses(
            [
                request_input(0),
                request_meta(TXHASH_334cd7),
                request_orig_input(0, TXHASH_334cd7),
                request_input(1),
                request_meta(TXHASH_ed89ac),
                request_orig_input(0, TXHASH_ed89ac),
                request_input(2),
                request_orig_input(1, TXHASH_334cd7),
                request_input(3),
                request_orig_input(1, TXHASH_ed89ac),
                request_output(0),
                request_orig_output(0, TXHASH_ed89ac),
                request_orig_output(1, TXHASH_ed89ac),
                request_output(1),
                request_orig_output(0, TXHASH_334cd7),
                request_output(2),
                request_orig_output(1, TXHASH_334cd7),
                messages.ButtonRequest(code=B.SignTx),
                messages.ButtonRequest(code=B.SignTx),
                messages.ButtonRequest(code=B.SignTx),
                request_input(0),
                request_meta(TXHASH_5e7667),
                request_input(0, TXHASH_5e7667),
                request_output(0, TXHASH_5e7667),
                request_output(1, TXHASH_5e7667),
                request_input(1),
                request_meta(TXHASH_6673b7),
                request_input(0, TXHASH_6673b7),
                request_input(1, TXHASH_6673b7),
                request_input(2, TXHASH_6673b7),
                request_input(3, TXHASH_6673b7),
                request_input(4, TXHASH_6673b7),
                request_output(0, TXHASH_6673b7),
                request_input(2),
                request_meta(TXHASH_efaa41),
                request_input(0, TXHASH_efaa41),
                request_output(0, TXHASH_efaa41),
                request_input(3),
                request_meta(TXHASH_927784),
                request_input(0, TXHASH_927784),
                request_input(1, TXHASH_927784),
                request_input(2, TXHASH_927784),
                request_output(0, TXHASH_927784),
                request_orig_input(0, TXHASH_334cd7),
                request_orig_input(0, TXHASH_ed89ac),
                request_input(0),
                request_input(1),
                request_input(2),
                request_input(3),
                request_output(0),
                request_output(1),
                request_output(2),
                request_input(0),
                request_input(1),
                request_input(2),
                request_input(3),
                request_finished(),
            ]
        )
        _, serialized_tx = btc.sign_tx(
            client,
            "Testnet",
            [inp1, inp2, inp3, inp4],
            [out1, out2, out3],
            prev_txes=TX_CACHE_TESTNET,
        )
