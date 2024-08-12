// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license. See the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <policy/forecaster_util.h>

std::string forecastTypeToString(ForecastType forecastType)
{
    switch (forecastType) {
    case ForecastType::BLOCK_POLICY_ESTIMATOR:
        return std::string("Block Policy Estimator");
    }
    // no default case, so the compiler can warn about missing cases
    assert(false);
}
