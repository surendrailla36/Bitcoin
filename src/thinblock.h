// Copyright (c) 2015 G. Andrew Stone
// Copyright (c) 2016 The Bitcoin Unlimited developers
// Copyright (c) 2016 Tom Zander <tomz@freedommail.ch>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_THINBLOCK_H
#define BITCOIN_THINBLOCK_H

#include "serialize.h"
#include "uint256.h"
#include "primitives/block.h"
#include "bloom.h"

#include "net.h"
#include "util.h"

#include <vector>

class CBlock;
class CNode;


class CXThinBlock
{
public:
    CBlockHeader header;
    std::vector<uint64_t> vTxHashes; // List of all transactions id's in the block
    std::vector<CTransaction> vMissingTx; // vector of transactions that did not match the bloom filter
    bool collision;

public:
    CXThinBlock(const CBlock& block, CBloomFilter* filter); // Use the filter to determine which txns the client has
    CXThinBlock(const CBlock& block);  // Assume client has all of the transactions (except coinbase)
    CXThinBlock() {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(header);
        READWRITE(vTxHashes);
        READWRITE(vMissingTx);
    }
};

// This class is used for retrieving a list of still missing transactions after receiving a "thinblock" message.
// The CXThinBlockTx when recieved can be used to fill in the missing transactions after which it is sent
// back to the requestor.  This class uses a 64bit hash as opposed to the normal 256bit hash.
class CXThinBlockTx
{
public:
    /** Public only for unit testing */
    uint256 blockhash;
    std::vector<CTransaction> vMissingTx; // map of missing transactions

public:
    CXThinBlockTx(uint256 blockHash, std::vector<CTransaction>& vTx);
    CXThinBlockTx() {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(blockhash);
        READWRITE(vMissingTx);
    }
};

// This class is used for retrieving a list of still missing transactions after receiving a "thinblock" message.
// The CXThinBlockTx when recieved can be used to fill in the missing transactions after which it is sent
// back to the requestor.  This class uses a 64bit hash as opposed to the normal 256bit hash.
class CXRequestThinBlockTx
{
public:
    /** Public only for unit testing */
    uint256 blockhash;
    std::set<uint64_t> setCheapHashesToRequest; // map of missing transactions

public:
    CXRequestThinBlockTx(uint256 blockHash, std::set<uint64_t>& setHashesToRequest);
    CXRequestThinBlockTx() {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(blockhash);
        READWRITE(setCheapHashesToRequest);
    }
};

bool HaveThinblockNodes();
bool CheckThinblockTimer(const uint256 &hash);
inline bool IsThinBlocksEnabled()
{
    return GetBoolArg("-use-thinblocks", true);
}
bool IsChainNearlySyncd();
CBloomFilter createSeededBloomFilter(const std::vector<uint256>& vOrphanHashes);
void LoadFilter(CNode *pfrom, CBloomFilter *filter);
void HandleBlockMessage(CNode *pfrom, const std::string &strCommand, const CBlock &block, const CInv &inv);

#endif
