#include "unlimited.h"

#include "test/test_bitcoin.h"
#include "../consensus/consensus.h"

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/lexical_cast.hpp>

using namespace std;

// Defined in rpc_tests.cpp not bitcoin-cli.cpp
extern UniValue CallRPC(string strMethod);

BOOST_FIXTURE_TEST_SUITE(excessiveblock_test, TestingSetup)

BOOST_AUTO_TEST_CASE(rpc_excessive)
{
    BOOST_CHECK_NO_THROW(CallRPC("getexcessiveblock"));

    BOOST_CHECK_NO_THROW(CallRPC("getminingmaxblock"));

    BOOST_CHECK_THROW(CallRPC("setexcessiveblock not_uint"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("setexcessiveblock 1000000 not_uint"), boost::bad_lexical_cast);
    BOOST_CHECK_THROW(CallRPC("setexcessiveblock 1000000 -1"), boost::bad_lexical_cast);
    BOOST_CHECK_THROW(CallRPC("setexcessiveblock -1 0"), boost::bad_lexical_cast);

    BOOST_CHECK_THROW(CallRPC("setexcessiveblock 1000 1"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("setminingmaxblock 1000"));
    BOOST_CHECK_NO_THROW(CallRPC("setexcessiveblock 1000 1"));

    BOOST_CHECK_THROW(CallRPC("setexcessiveblock 1000 0 0"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("setminingmaxblock"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("setminingmaxblock 100000"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("setminingmaxblock not_uint"),  boost::bad_lexical_cast);
    BOOST_CHECK_THROW(CallRPC("setminingmaxblock -1"),  boost::bad_lexical_cast);
    BOOST_CHECK_THROW(CallRPC("setminingmaxblock 0"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("setminingmaxblock 0 0"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("setminingmaxblock 1000"));
    BOOST_CHECK_NO_THROW(CallRPC("setminingmaxblock 101"));
    
}

BOOST_AUTO_TEST_CASE(buip005)
{
    string exceptedEB;
    string exceptedAD;
    excessiveBlockSize = 1000000;
    excessiveAcceptDepth = 9999999;
    exceptedEB = "EB1";
    exceptedAD = "AD9999999";
    settingsToUserAgentString();
    BOOST_CHECK_MESSAGE(BUComments.front() == exceptedEB,
                        "EB ought to have been " << exceptedEB << " when excessiveBlockSize = "
                        << excessiveBlockSize << " but was " << BUComments.front());
    BOOST_CHECK_MESSAGE(BUComments.back() == exceptedAD,
                        "AD ought to have been " << exceptedAD << " when excessiveBlockSize = " << excessiveAcceptDepth);
    excessiveBlockSize = 100000;
    excessiveAcceptDepth = 9999999 + 1;
    exceptedEB = "EB0.1";
    exceptedAD = "AD9999999";
    settingsToUserAgentString();
    BOOST_CHECK_MESSAGE(BUComments.front() == exceptedEB,
                        "EB ought to have been " << exceptedEB << " when excessiveBlockSize = "
                        << excessiveBlockSize << " but was " << BUComments.front());
    BOOST_CHECK_MESSAGE(BUComments.back() == exceptedAD,
                        "AD ought to have been " << exceptedAD << " when excessiveBlockSize = " << excessiveAcceptDepth);
    excessiveBlockSize = 10000;
    exceptedEB = "EB0";
    settingsToUserAgentString();
    BOOST_CHECK_MESSAGE(BUComments.front() == exceptedEB,
                        "EB ought to have been " << exceptedEB << " when excessiveBlockSize = "
                        << excessiveBlockSize << " but was " << BUComments.front());
    excessiveBlockSize = 150000;
    exceptedEB = "EB0.1";
    settingsToUserAgentString();
    BOOST_CHECK_MESSAGE(BUComments.front() == exceptedEB,
                        "EB ought to have been rounded to " << exceptedEB << " when excessiveBlockSize = "
                        << excessiveBlockSize << " but was " << BUComments.front());
    excessiveBlockSize = 150000;
    exceptedEB = "EB0.1";
    settingsToUserAgentString();
    BOOST_CHECK_MESSAGE(BUComments.front() == exceptedEB,
                        "EB ought to have been rounded to " << exceptedEB << " when excessiveBlockSize = "
                        << excessiveBlockSize << " but was " << BUComments.front());

    // set back to defaults
    excessiveBlockSize = 1000000;
    excessiveAcceptDepth = 4;
}


BOOST_AUTO_TEST_CASE(excessiveChecks)
{
  CBlock block;

  excessiveBlockSize = 16000000;  // Ignore excessive block size when checking sigops and block effort

  // Check sigops values

  // Maintain compatibility with the old sigops calculator for blocks <= 1MB
  BOOST_CHECK_MESSAGE(false == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE-1,BLOCKSTREAM_CORE_MAX_BLOCK_SIGOPS,100,100), "improper sigops");
  BOOST_CHECK_MESSAGE(false == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE-1,BLOCKSTREAM_CORE_MAX_BLOCK_SIGOPS,100,100), "improper sigops");
  BOOST_CHECK_MESSAGE(false == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE,BLOCKSTREAM_CORE_MAX_BLOCK_SIGOPS,100,100), "improper sigops");

  BOOST_CHECK_MESSAGE(true == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE-1,BLOCKSTREAM_CORE_MAX_BLOCK_SIGOPS+1,100,100), "improper sigops");
  BOOST_CHECK_MESSAGE(true == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE,BLOCKSTREAM_CORE_MAX_BLOCK_SIGOPS+1,100,100), "improper sigops");


  // Check sigops > 1MB.
  BOOST_CHECK_MESSAGE(false == CheckExcessive(block,1000000+1,(blockSigopsPerMb.value*2),100,100), "improper sigops");
  BOOST_CHECK_MESSAGE(true == CheckExcessive(block,1000000+1,(blockSigopsPerMb.value*2)+1,100,100), "improper sigops");
  BOOST_CHECK_MESSAGE(true == CheckExcessive(block,(2*1000000),(blockSigopsPerMb.value*2)+1,100,100), "improper sigops");
  BOOST_CHECK_MESSAGE(false == CheckExcessive(block,(2*1000000)+1,(blockSigopsPerMb.value*2)+1,100,100), "improper sigops");

  
  // Check tx size values
  maxTxSize.value = DEFAULT_LARGEST_TRANSACTION;

  // Within a 1 MB block, a 1MB transaction is not excessive
  BOOST_CHECK_MESSAGE(false == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE,1,1,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE), "improper max tx");

  // With a > 1 MB block, use the maxTxSize to determine
  BOOST_CHECK_MESSAGE(false == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE+1,1,1,maxTxSize.value), "improper max tx");
  BOOST_CHECK_MESSAGE(true == CheckExcessive(block,BLOCKSTREAM_CORE_MAX_BLOCK_SIZE+1,1,1,maxTxSize.value+1), "improper max tx");


}


BOOST_AUTO_TEST_SUITE_END()
