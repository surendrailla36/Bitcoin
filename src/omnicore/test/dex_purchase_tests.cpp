#include <omnicore/dex.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <stdint.h>

using mastercore::calculateDExPurchase;

BOOST_FIXTURE_TEST_SUITE(omnicore_dex_purchase_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(purchase_amount_exact)
{
    const int64_t MAX = 9223372036854775807LL;

    BOOST_CHECK_EQUAL(0, calculateDExPurchase(1, 1, 0));
    BOOST_CHECK_EQUAL(1, calculateDExPurchase(1, 1, 1));
    BOOST_CHECK_EQUAL(2, calculateDExPurchase(4, 8, 4));
    BOOST_CHECK_EQUAL(3, calculateDExPurchase(9, 9, 3));
    BOOST_CHECK_EQUAL(7, calculateDExPurchase(MAX, MAX, 7));
    BOOST_CHECK_EQUAL(MAX, calculateDExPurchase(MAX, 1, 1));
    BOOST_CHECK_EQUAL(MAX, calculateDExPurchase(MAX, MAX, MAX));
}

BOOST_AUTO_TEST_CASE(purchase_amount_ladder)
{
    const int64_t MAX = 9223372036854775807LL;

    BOOST_CHECK_EQUAL(1, calculateDExPurchase(MAX, MAX, 1));
    BOOST_CHECK_EQUAL(10, calculateDExPurchase(MAX, MAX, 10));
    BOOST_CHECK_EQUAL(100, calculateDExPurchase(MAX, MAX, 100));
    BOOST_CHECK_EQUAL(1000, calculateDExPurchase(MAX, MAX, 1000));
    BOOST_CHECK_EQUAL(10000, calculateDExPurchase(MAX, MAX, 10000));
    BOOST_CHECK_EQUAL(100000L, calculateDExPurchase(MAX, MAX, 100000L));
    BOOST_CHECK_EQUAL(1000000L, calculateDExPurchase(MAX, MAX, 1000000L));
    BOOST_CHECK_EQUAL(10000000L, calculateDExPurchase(MAX, MAX, 10000000L));
    BOOST_CHECK_EQUAL(100000000L, calculateDExPurchase(MAX, MAX, 100000000L));
    BOOST_CHECK_EQUAL(1000000000L, calculateDExPurchase(MAX, MAX, 1000000000L));
    BOOST_CHECK_EQUAL(10000000000LL, calculateDExPurchase(MAX, MAX, 10000000000LL));
    BOOST_CHECK_EQUAL(100000000000LL, calculateDExPurchase(MAX, MAX, 100000000000LL));
    BOOST_CHECK_EQUAL(1000000000000LL, calculateDExPurchase(MAX, MAX, 1000000000000LL));
    BOOST_CHECK_EQUAL(10000000000000LL, calculateDExPurchase(MAX, MAX, 10000000000000LL));
    BOOST_CHECK_EQUAL(100000000000000LL, calculateDExPurchase(MAX, MAX, 100000000000000LL));
    BOOST_CHECK_EQUAL(1000000000000000LL, calculateDExPurchase(MAX, MAX, 1000000000000000LL));
    BOOST_CHECK_EQUAL(10000000000000000LL, calculateDExPurchase(MAX, MAX, 10000000000000000LL));
    BOOST_CHECK_EQUAL(100000000000000000LL, calculateDExPurchase(MAX, MAX, 100000000000000000LL));
    BOOST_CHECK_EQUAL(1000000000000000000LL, calculateDExPurchase(MAX, MAX, 1000000000000000000LL));
    BOOST_CHECK_EQUAL(2345678901234567890LL, calculateDExPurchase(MAX, MAX, 2345678901234567890LL));
    BOOST_CHECK_EQUAL(3333333333333333333LL, calculateDExPurchase(MAX, MAX, 3333333333333333333LL));
    BOOST_CHECK_EQUAL(4008001500160023042LL, calculateDExPurchase(MAX, MAX, 4008001500160023042LL));
    BOOST_CHECK_EQUAL(5000000000000000001LL, calculateDExPurchase(MAX, MAX, 5000000000000000001LL));
    BOOST_CHECK_EQUAL(6777677767776777677LL, calculateDExPurchase(MAX, MAX, 6777677767776777677LL));
    BOOST_CHECK_EQUAL(7107297387477567653LL, calculateDExPurchase(MAX, MAX, 7107297387477567653LL));
    BOOST_CHECK_EQUAL(8999999999999999999LL, calculateDExPurchase(MAX, MAX, 8999999999999999999LL));
    BOOST_CHECK_EQUAL(9111111111111111111LL, calculateDExPurchase(MAX, MAX, 9111111111111111111LL));
}

BOOST_AUTO_TEST_CASE(purchase_amount_fraction)
{
    BOOST_CHECK_EQUAL(10, calculateDExPurchase(17, 13, 7));
    BOOST_CHECK_EQUAL(14, calculateDExPurchase(19, 11, 8));
    BOOST_CHECK_EQUAL(100000000000000000LL, calculateDExPurchase(200000000000000000LL, 1000000000000000000LL, 499999999999999999LL));
    BOOST_CHECK_EQUAL(100000000000000001LL, calculateDExPurchase(200000000000000001LL, 1000000000000000000LL, 500000000000000000LL));
}

BOOST_AUTO_TEST_CASE(overflow_protection)
{
    BOOST_CHECK_EQUAL(0, calculateDExPurchase(100000000, 10000, 0));
}

BOOST_AUTO_TEST_SUITE_END()
