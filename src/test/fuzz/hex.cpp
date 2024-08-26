// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <primitives/block.h>
#include <pubkey.h>
#include <rpc/util.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

FUZZ_TARGET(hex)
{
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    const auto result_size{fdp.ConsumeIntegral<int16_t>()};
    const std::string random_hex_string{fdp.ConsumeRemainingBytesAsString()};
    const std::vector<unsigned char> data = ParseHex(random_hex_string);
    const std::vector<std::byte> bytes{ParseHex<std::byte>(random_hex_string)};
    assert(AsBytes(Span{data}) == Span{bytes});
    const std::string hex_data = HexStr(data);
    if (IsHex(random_hex_string)) {
        assert(ToLower(random_hex_string) == hex_data);
    }
    if (uint256::FromHex(random_hex_string)) {
        assert(random_hex_string.length() == 64);
        assert(Txid::FromHex(random_hex_string));
        assert(Wtxid::FromHex(random_hex_string));
    }
    (void)uint256S(random_hex_string);
    try {
        (void)HexToPubKey(random_hex_string);
    } catch (const UniValue&) {
    }
    if (auto sanitized_hex = TrySanitizeHexNumber(random_hex_string, result_size)) {
        auto sanitized_size = sanitized_hex->size();
        assert(result_size < 0 || sanitized_size == static_cast<size_t>(result_size));
        if (~sanitized_size & 1) {
            assert(TryParseHex(*sanitized_hex));
            assert(IsHex(*sanitized_hex));
            if (sanitized_size == uint256::size() * 2) {
                assert(uint256::FromHex(*sanitized_hex));
                assert(Txid::FromHex(*sanitized_hex));
                assert(Wtxid::FromHex(*sanitized_hex));
            }
        }
    }
    CBlockHeader block_header;
    (void)DecodeHexBlockHeader(block_header, random_hex_string);
    CBlock block;
    (void)DecodeHexBlk(block, random_hex_string);
}
