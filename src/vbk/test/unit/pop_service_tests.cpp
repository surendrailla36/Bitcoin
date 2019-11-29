#include <boost/test/unit_test.hpp>
#include <consensus/validation.h>
#include <test/setup_common.h>
#include <validation.h>

#include <fakeit.hpp>
#include <vbk/config.hpp>
#include <vbk/init.hpp>
#include <vbk/pop_service.hpp>
#include <vbk/pop_service/pop_service_impl.hpp>
#include <vbk/service_locator.hpp>
#include <vbk/test/util/mock.hpp>
#include <vbk/test/util/tx.hpp>

using namespace fakeit;

static CBlock createBlockWithPopTx(TestChain100Setup& test)
{
    CMutableTransaction popTx = VeriBlockTest::makePopTx({1}, {{2}});
    CScript scriptPubKey = CScript() << ToByteVector(test.coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    return test.CreateAndProcessBlock({popTx}, scriptPubKey);
}

inline void setUpAtv(VeriBlock::AltPublication& ATV, const CDataStream& stream, const int64_t& index)
{
    auto* transaction = new VeriBlock::VeriBlockTransaction();
    auto* publicationData = new VeriBlock::PublicationData();

    publicationData->set_identifier(index);
    publicationData->set_header(stream.data(), stream.size());
    transaction->set_allocated_publicationdata(publicationData);
    ATV.set_allocated_transaction(transaction);
}

struct PopServiceFixture : public TestChain100Setup {
    Mock<VeriBlock::PopServiceImpl> pop_service_impl_mock{};

    PopServiceFixture()
    {
        VeriBlock::InitUtilService();
        VeriBlock::InitConfig();
        When(Method(pop_service_impl_mock, addPayloads)).AlwaysReturn(true);
        Fake(Method(pop_service_impl_mock, removePayloads));
        When(Method(pop_service_impl_mock, determineATVPlausibilityWithBTCRules)).AlwaysReturn(true);
    }
};

BOOST_AUTO_TEST_SUITE(pop_service_tests)

BOOST_FIXTURE_TEST_CASE(blockPopValidation_test, PopServiceFixture)
{
    CBlock block = createBlockWithPopTx(*this);

    CBlockIndex* endorsedBlockIndex = ChainActive().Tip()->pprev;
    CBlock endorsedBlock;
    BOOST_CHECK(ReadBlockFromDisk(endorsedBlock, endorsedBlockIndex, Params().GetConsensus()));

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << endorsedBlock.GetBlockHeader();
    auto& config = VeriBlock::getService<VeriBlock::Config>();

    When(Method(pop_service_impl_mock, getPublicationsData)).Do([stream, config](const CTransactionRef& tx, VeriBlock::AltPublication& ATV, std::vector<VeriBlock::VeriBlockPublication>& VTBs) {
        setUpAtv(ATV, stream, config.index.unwrap());
    });

    CValidationState state;
    {
        LOCK(cs_main);
        BOOST_CHECK(VeriBlock::blockPopValidationImpl(pop_service_impl_mock.get(), block, *ChainActive().Tip()->pprev, Params().GetConsensus(), state));
    }
}

BOOST_FIXTURE_TEST_CASE(blockPopValidation_test_wrong_index, PopServiceFixture)
{
    CBlock block = createBlockWithPopTx(*this);

    CBlockIndex* endorsedBlockIndex = ChainActive().Tip()->pprev->pprev->pprev;
    CBlock endorsedBlock;
    BOOST_CHECK(ReadBlockFromDisk(endorsedBlock, endorsedBlockIndex, Params().GetConsensus()));

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << endorsedBlock.GetBlockHeader();

    // make another index
    When(Method(pop_service_impl_mock, getPublicationsData)).Do([stream](const CTransactionRef& tx, VeriBlock::AltPublication& ATV, std::vector<VeriBlock::VeriBlockPublication>& VTBs) {
        setUpAtv(ATV, stream, -1);
    });

    When(Method(pop_service_impl_mock, determineATVPlausibilityWithBTCRules)).Return(false);

    CValidationState state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!blockPopValidationImpl(pop_service_impl_mock.get(), block, *ChainActive().Tip()->pprev, Params().GetConsensus(), state));
    }
    Verify_Method(Method(pop_service_impl_mock, removePayloads)).Once();
}

BOOST_FIXTURE_TEST_CASE(blockPopValidation_test_wrong_ancestor, PopServiceFixture)
{
    CBlockIndex* endorsedBlockIndex = ChainActive().Tip()->pprev->pprev->pprev;
    CBlock endorsedBlock;
    BOOST_CHECK(ReadBlockFromDisk(endorsedBlock, endorsedBlockIndex, Params().GetConsensus()));
    int prevHeight = ChainActive().Height();

    std::shared_ptr<CCoinsViewCache> view;
    {
        LOCK(cs_main);
        view = std::make_shared<CCoinsViewCache>(&ChainstateActive().CoinsTip());
    }

    CValidationState state;
    InvalidateBlock(state, Params(), endorsedBlockIndex);
    ActivateBestChain(state, Params());
    ChainstateActive().ActivateBestChain(state, Params(), nullptr);
    BOOST_CHECK(ChainActive().Height() < prevHeight);

    CBlock block = createBlockWithPopTx(*this);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << endorsedBlock.GetBlockHeader();
    auto& config = VeriBlock::getService<VeriBlock::Config>();

    When(Method(pop_service_impl_mock, getPublicationsData)).Do([stream, config](const CTransactionRef& tx, VeriBlock::AltPublication& ATV, std::vector<VeriBlock::VeriBlockPublication>& VTBs) {
        setUpAtv(ATV, stream, config.index.unwrap());
    });

    {
        LOCK(cs_main);
        BOOST_CHECK(!blockPopValidationImpl(pop_service_impl_mock.get(), block, *ChainActive().Tip()->pprev, Params().GetConsensus(), state));
    }
    Verify_Method(Method(pop_service_impl_mock, removePayloads)).Once();
}

BOOST_FIXTURE_TEST_CASE(blockPopValidation_test_wrong_merkleroot, PopServiceFixture)
{
    CBlockIndex* endorsedBlockIndex = ChainActive().Tip()->pprev->pprev->pprev;
    CBlock endorsedBlock;
    BOOST_CHECK(ReadBlockFromDisk(endorsedBlock, endorsedBlockIndex, Params().GetConsensus()));
    endorsedBlock.hashMerkleRoot.SetHex("fffff");

    CBlock block = createBlockWithPopTx(*this);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << endorsedBlock.GetBlockHeader();
    auto& config = VeriBlock::getService<VeriBlock::Config>();

    When(Method(pop_service_impl_mock, getPublicationsData)).Do([stream, config](const CTransactionRef& tx, VeriBlock::AltPublication& ATV, std::vector<VeriBlock::VeriBlockPublication>& VTBs) {
        setUpAtv(ATV, stream, config.index.unwrap());
    });

    When(Method(pop_service_impl_mock, determineATVPlausibilityWithBTCRules)).AlwaysReturn(true);

    CValidationState state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!blockPopValidationImpl(pop_service_impl_mock.get(), block, *ChainActive().Tip()->pprev, Params().GetConsensus(), state));
    }
    Verify_Method(Method(pop_service_impl_mock, removePayloads)).Once();
}

BOOST_FIXTURE_TEST_CASE(blockPopValidation_test_wrong_settlement_interval, PopServiceFixture)
{
    CBlockIndex* endorsedBlockIndex = ChainActive().Tip()->pprev->pprev->pprev;
    CBlock endorsedBlock;
    BOOST_CHECK(ReadBlockFromDisk(endorsedBlock, endorsedBlockIndex, Params().GetConsensus()));

    CBlock block = createBlockWithPopTx(*this);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << endorsedBlock.GetBlockHeader();
    auto& config = VeriBlock::getService<VeriBlock::Config>();

    When(Method(pop_service_impl_mock, getPublicationsData)).Do([stream, config](const CTransactionRef& tx, VeriBlock::AltPublication& ATV, std::vector<VeriBlock::VeriBlockPublication>& VTBs) {
        setUpAtv(ATV, stream, config.index.unwrap());
    });

    config.POP_REWARD_SETTLEMENT_INTERVAL = 0;
    VeriBlock::setService<VeriBlock::Config>(new VeriBlock::Config(config));

    CValidationState state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!blockPopValidationImpl(pop_service_impl_mock.get(), block, *ChainActive().Tip()->pprev, Params().GetConsensus(), state));
    }
    Verify_Method(Method(pop_service_impl_mock, removePayloads)).Once();
}

BOOST_FIXTURE_TEST_CASE(blockPopValidation_test_wrong_addPayloads, PopServiceFixture)
{
    CBlockIndex* endorsedBlockIndex = ChainActive().Tip()->pprev->pprev->pprev;
    CBlock endorsedBlock;
    BOOST_CHECK(ReadBlockFromDisk(endorsedBlock, endorsedBlockIndex, Params().GetConsensus()));

    CBlock block = createBlockWithPopTx(*this);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << endorsedBlock.GetBlockHeader();
    auto& config = VeriBlock::getService<VeriBlock::Config>();

    When(Method(pop_service_impl_mock, getPublicationsData)).Do([stream, config](const CTransactionRef& tx, VeriBlock::AltPublication& ATV, std::vector<VeriBlock::VeriBlockPublication>& VTBs) {
        setUpAtv(ATV, stream, config.index.unwrap());
    });

    When(Method(pop_service_impl_mock, addPayloads)).Return(false);

    CValidationState state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!blockPopValidationImpl(pop_service_impl_mock.get(), block, *ChainActive().Tip()->pprev, Params().GetConsensus(), state));
    }
    Verify_Method(Method(pop_service_impl_mock, removePayloads)).Once();
}
BOOST_AUTO_TEST_SUITE_END()
