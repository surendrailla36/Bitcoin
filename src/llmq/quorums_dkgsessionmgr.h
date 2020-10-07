// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_DKGSESSIONMGR_H
#define SYSCOIN_LLMQ_QUORUMS_DKGSESSIONMGR_H

#include <llmq/quorums_dkgsessionhandler.h>

#include <validation.h>

#include <ctpl.h>
class CConnman;
class UniValue;

namespace llmq
{

class CDKGSessionManager
{
    static const int64_t MAX_CONTRIBUTION_CACHE_TIME = 60 * 1000;

private:
    CDBWrapper& llmqDb;
    CBLSWorker& blsWorker;
    CConnman& connman;

    std::map<uint8_t, CDKGSessionHandler> dkgSessionHandlers;

    RecursiveMutex contributionsCacheCs;
    struct ContributionsCacheKey {
        uint8_t llmqType;
        uint256 quorumHash;
        uint256 proTxHash;
        bool operator<(const ContributionsCacheKey& r) const
        {
            if (llmqType != r.llmqType) return llmqType < r.llmqType;
            if (quorumHash != r.quorumHash) return quorumHash < r.quorumHash;
            return proTxHash < r.proTxHash;
        }
    };
    struct ContributionsCacheEntry {
        int64_t entryTime;
        BLSVerificationVectorPtr vvec;
        CBLSSecretKey skContribution;
    };
    std::map<ContributionsCacheKey, ContributionsCacheEntry> contributionsCache;

public:
    CDKGSessionManager(CDBWrapper& _llmqDb, CBLSWorker& _blsWorker, CConnman &connman);
    ~CDKGSessionManager();

    void StartThreads();
    void StopThreads();

    void UpdatedBlockTip(const CBlockIndex *pindexNew, bool fInitialDownload);

    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    bool AlreadyHave(const uint256& hash) const;
    bool GetContribution(const uint256& hash, CDKGContribution& ret) const;
    bool GetComplaint(const uint256& hash, CDKGComplaint& ret) const;
    bool GetJustification(const uint256& hash, CDKGJustification& ret) const;
    bool GetPrematureCommitment(const uint256& hash, CDKGPrematureCommitment& ret) const;

    // Verified contributions are written while in the DKG
    void WriteVerifiedVvecContribution(uint8_t llmqType, const CBlockIndex* pindexQuorum, const uint256& proTxHash, const BLSVerificationVectorPtr& vvec);
    void WriteVerifiedSkContribution(uint8_t llmqType, const CBlockIndex* pindexQuorum, const uint256& proTxHash, const CBLSSecretKey& skContribution);
    bool GetVerifiedContributions(uint8_t llmqType, const CBlockIndex* pindexQuorum, const std::vector<bool>& validMembers, std::vector<uint16_t>& memberIndexesRet, std::vector<BLSVerificationVectorPtr>& vvecsRet, BLSSecretKeyVector& skContributionsRet);
    bool GetVerifiedContribution(uint8_t llmqType, const CBlockIndex* pindexQuorum, const uint256& proTxHash, BLSVerificationVectorPtr& vvecRet, CBLSSecretKey& skContributionRet);

private:
    void CleanupCache();
};

extern CDKGSessionManager* quorumDKGSessionManager;

} // namespace llmq

#endif //SYSCOIN_LLMQ_QUORUMS_DKGSESSIONMGR_H
