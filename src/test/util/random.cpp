// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/random.h>

#include <logging.h>
#include <random.h>
#include <uint256.h>
#include <util/check.h>

#include <cstdlib>
#include <iostream>

FastRandomContext g_insecure_rand_ctx;

extern void MakeRandDeterministicDANGEROUS(const uint256& seed) noexcept;

void SeedRandomForTest(SeedRand seedtype)
{
    constexpr auto RANDOM_CTX_SEED{"RANDOM_CTX_SEED"};

    // Do this once, on the first call, regardless of seedtype, because once
    // MakeRandDeterministicDANGEROUS is called, the output of GetRandHash is
    // no longer truly random. It should be enough to get the seed once for the
    // process.
    static const uint256 ctx_seed = []() {
        // If RANDOM_CTX_SEED is set, use that as seed.
        if (const char* num{std::getenv(RANDOM_CTX_SEED)}) {
            if (auto num_parsed{uint256::FromHex(num)}) {
                return *num_parsed;
            } else {
                std::cerr << RANDOM_CTX_SEED << " must be a " << uint256::size() * 2 << " char hex string without '0x'-prefix, was set to: '" << num << "'.\n";
                std::abort();
            }
        }
        // Otherwise use a (truly) random value.
        return GetRandHash();
    }();

    const uint256& seed{seedtype == SeedRand::SEED ? ctx_seed : uint256::ZERO};
    LogInfo("Setting random seed for current tests to %s=%s\n", RANDOM_CTX_SEED, seed.GetHex());
    MakeRandDeterministicDANGEROUS(seed);
    g_insecure_rand_ctx.Reseed(GetRandHash());
}
