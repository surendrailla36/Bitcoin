// Copyright (c) 2015-2017 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "expedited.h"
#include "tweak.h"
#include "main.h"
#include "rpc/server.h"
#include "thinblock.h"
#include "unlimited.h"

#include <univalue.h>

#define NUM_XPEDITED_STORE 10

// Just save the last few expedited sent blocks so we don't resend (uint256)
uint256 xpeditedBlkSent[NUM_XPEDITED_STORE];
// zeros on construction)
int xpeditedBlkSendPos = 0;

using namespace std;

bool CheckAndRequestExpeditedBlocks(CNode *pfrom)
{
    if (pfrom->nVersion >= EXPEDITED_VERSION)
    {
        BOOST_FOREACH (std::string &strAddr, mapMultiArgs["-expeditedblock"])
        {
            std::string strListeningPeerIP;
            std::string strPeerIP = pfrom->addr.ToString();
            // Add the peer's listening port if it was provided (only misbehaving clients do not provide it)
            if (pfrom->addrFromPort != 0)
            {
                int pos1 = strAddr.rfind(":");
                int pos2 = strAddr.rfind("]:");
                if (pos1 <= 0 && pos2 <= 0)
                    strAddr += ':' + boost::lexical_cast<std::string>(pfrom->addrFromPort);

                pos1 = strPeerIP.rfind(":");
                pos2 = strPeerIP.rfind("]:");
                // Handle both ipv4 and ipv6 cases
                if (pos1 <= 0 && pos2 <= 0)
                    strListeningPeerIP = strPeerIP + ':' + boost::lexical_cast<std::string>(pfrom->addrFromPort);
                else if (pos1 > 0)
                    strListeningPeerIP =
                        strPeerIP.substr(0, pos1) + ':' + boost::lexical_cast<std::string>(pfrom->addrFromPort);
                else
                    strListeningPeerIP =
                        strPeerIP.substr(0, pos2) + ':' + boost::lexical_cast<std::string>(pfrom->addrFromPort);
            }
            else
                strListeningPeerIP = strPeerIP;

            if (strAddr == strListeningPeerIP)
            {
                if (!IsThinBlocksEnabled())
                {
                    LogPrintf("You do not have Thinblocks enabled.  You can not request expedited blocks from peer %s "
                              "(%d).\n",
                        strListeningPeerIP, pfrom->id);
                    return false;
                }
                else if (!pfrom->ThinBlockCapable())
                {
                    LogPrintf("Thinblocks is not enabled on remote peer.  You can not request expedited blocks from "
                              "peer %s (%d).\n",
                        strListeningPeerIP, pfrom->id);
                    return false;
                }
                else
                {
                    LogPrintf("Requesting expedited blocks from peer %s (%d).\n", strListeningPeerIP, pfrom->id);
                    pfrom->PushMessage(NetMsgType::XPEDITEDREQUEST, ((uint64_t)EXPEDITED_BLOCKS));
                    xpeditedBlkUp.push_back(pfrom);
                    return true;
                }
            }
        }
    }
    return false;
}

void HandleExpeditedRequest(CDataStream &vRecv, CNode *pfrom)
{
    uint64_t options;
    vRecv >> options;
    bool stop = ((options & EXPEDITED_STOP) != 0); // Are we starting or stopping expedited service?
    if (options & EXPEDITED_BLOCKS)
    {
        if (stop) // If stopping, find the array element and clear it.
        {
            LogPrint("blk", "Stopping expedited blocks to peer %s (%d).\n", pfrom->addrName.c_str(), pfrom->id);
            std::vector<CNode *>::iterator it = std::find(xpeditedBlk.begin(), xpeditedBlk.end(), pfrom);
            if (it != xpeditedBlk.end())
            {
                *it = NULL;
                pfrom->Release();
            }
        }
        else // Otherwise, add the new node to the end
        {
            std::vector<CNode *>::iterator it1 = std::find(xpeditedBlk.begin(), xpeditedBlk.end(), pfrom);
            if (it1 == xpeditedBlk.end()) // don't add it twice
            {
                unsigned int maxExpedited = GetArg("-maxexpeditedblockrecipients", 32);
                if (xpeditedBlk.size() < maxExpedited)
                {
                    LogPrint("blk", "Starting expedited blocks to peer %s (%d).\n", pfrom->addrName.c_str(), pfrom->id);
                    // find an empty array location
                    std::vector<CNode *>::iterator it =
                        std::find(xpeditedBlk.begin(), xpeditedBlk.end(), ((CNode *)NULL));
                    if (it != xpeditedBlk.end())
                        *it = pfrom;
                    else
                        xpeditedBlk.push_back(pfrom);
                    pfrom->AddRef(); // add a reference because we have added this pointer into the expedited array
                }
                else
                {
                    LogPrint("blk", "Expedited blocks requested from peer %s (%d), but I am full.\n",
                        pfrom->addrName.c_str(), pfrom->id);
                }
            }
        }
    }
    if (options & EXPEDITED_TXNS)
    {
        if (stop) // If stopping, find the array element and clear it.
        {
            LogPrint("blk", "Stopping expedited transactions to peer %s (%d).\n", pfrom->addrName.c_str(), pfrom->id);
            std::vector<CNode *>::iterator it = std::find(xpeditedTxn.begin(), xpeditedTxn.end(), pfrom);
            if (it != xpeditedTxn.end())
            {
                *it = NULL;
                pfrom->Release();
            }
        }
        else // Otherwise, add the new node to the end
        {
            std::vector<CNode *>::iterator it1 = std::find(xpeditedTxn.begin(), xpeditedTxn.end(), pfrom);
            if (it1 == xpeditedTxn.end()) // don't add it twice
            {
                unsigned int maxExpedited = GetArg("-maxexpeditedtxrecipients", 32);
                if (xpeditedTxn.size() < maxExpedited)
                {
                    LogPrint("blk", "Starting expedited transactions to peer %s (%d).\n", pfrom->addrName.c_str(),
                        pfrom->id);
                    std::vector<CNode *>::iterator it =
                        std::find(xpeditedTxn.begin(), xpeditedTxn.end(), ((CNode *)NULL));
                    if (it != xpeditedTxn.end())
                        *it = pfrom;
                    else
                        xpeditedTxn.push_back(pfrom);
                    pfrom->AddRef();
                }
                else
                {
                    LogPrint("blk", "Expedited transactions requested from peer %s (%d), but I am full.\n",
                        pfrom->addrName.c_str(), pfrom->id);
                }
            }
        }
    }
}

bool IsRecentlyExpeditedAndStore(const uint256 &hash)
{
    for (int i = 0; i < NUM_XPEDITED_STORE; i++)
        if (xpeditedBlkSent[i] == hash)
            return true;

    xpeditedBlkSent[xpeditedBlkSendPos] = hash;
    xpeditedBlkSendPos++;
    if (xpeditedBlkSendPos >= NUM_XPEDITED_STORE)
        xpeditedBlkSendPos = 0;

    return false;
}

bool HandleExpeditedBlock(CDataStream &vRecv, CNode *pfrom)
{
    unsigned char hops;
    unsigned char msgType;
    vRecv >> msgType >> hops;

    if (msgType == EXPEDITED_MSG_XTHIN)
    {
        CXThinBlock thinBlock;
        vRecv >> thinBlock;
        uint256 blkHash = thinBlock.header.GetHash();
        CInv inv(MSG_BLOCK, blkHash);

        BlockMap::iterator mapEntry = mapBlockIndex.find(blkHash);
        CBlockIndex *blkidx = NULL;
        unsigned int status = 0;
        if (mapEntry != mapBlockIndex.end())
        {
            blkidx = mapEntry->second;
            if (blkidx)
                status = blkidx->nStatus;
        }
        bool newBlock =
            ((blkidx == NULL) ||
                (!(blkidx->nStatus &
                    BLOCK_HAVE_DATA))); // If I have never seen the block or just seen an INV, treat the block as new
        int nSizeThinBlock = ::GetSerializeSize(
            thinBlock, SER_NETWORK, PROTOCOL_VERSION); // TODO replace with size of vRecv for efficiency
        LogPrint("thin",
            "Received %s expedited thinblock %s from peer %s (%d). Hop %d. Size %d bytes. (status %d,0x%x)\n",
            newBlock ? "new" : "repeated", inv.hash.ToString(), pfrom->addrName.c_str(), pfrom->id, hops,
            nSizeThinBlock, status, status);

        // Skip if we've already seen this block
        // TODO move this above the print, once we ensure no unexpected dups.
        if (IsRecentlyExpeditedAndStore(blkHash))
            return true;
        if (!newBlock)
        {
            // TODO determine if we have the block or just have an INV to it.
            return true;
        }

        CValidationState state;
        if (!CheckBlockHeader(thinBlock.header, state, true)) // block header is bad
        {
            // demerit the sender, it should have checked the header before expedited relay
            return false;
        }
        // TODO:  Start headers-only mining now

        SendExpeditedBlock(thinBlock, hops + 1, pfrom); // I should push the vRecv rather than reserialize
        thinBlock.process(pfrom, nSizeThinBlock, NetMsgType::XPEDITEDBLK);
    }
    else
    {
        LogPrint("thin", "Received unknown (0x%x) expedited message from peer %s (%d). Hop %d.\n", msgType,
            pfrom->addrName.c_str(), pfrom->id, hops);
        return false;
    }
    return true;
}

void SendExpeditedBlock(CXThinBlock &thinBlock, unsigned char hops, const CNode *skip)
{
    // bool cameFromUpstream = false;
    std::vector<CNode *>::iterator end = xpeditedBlk.end();
    for (std::vector<CNode *>::iterator it = xpeditedBlk.begin(); it != end; it++)
    {
        CNode *n = *it;
        // if (n == skip) cameFromUpstream = true;
        if ((n != skip) && (n != NULL)) // Don't send it back in case there is a forwarding loop
        {
            if (n->fDisconnect)
            {
                *it = NULL;
                n->Release();
            }
            else
            {
                LogPrint("thin", "Sending expedited block %s to %s.\n", thinBlock.header.GetHash().ToString(),
                    n->addrName.c_str());
                n->PushMessage(NetMsgType::XPEDITEDBLK, (unsigned char)EXPEDITED_MSG_XTHIN, hops,
                    thinBlock); // I should push the vRecv rather than reserialize
                n->blocksSent += 1;
            }
        }
    }

#if 0 // Probably better to have the upstream explicitly request blocks from the downstream.
  // Upstream
  // TODO, if it came from an upstream block I really want to delay for a short period and then check if we got it and then send.  But this solves some of the issue
  if (!cameFromUpstream)
    {
      std::vector<CNode*>::iterator end = xpeditedBlkUp.end();
      for (std::vector<CNode*>::iterator it = xpeditedBlkUp.begin(); it != end; it++)
        {
          CNode* n = *it;
          if ((n != skip)&&(n != NULL)) // Don't send it back to the sender in case there is a forwarding loop
            {
              if (n->fDisconnect)
                {
                  *it = NULL;
                  n->Release();
                }
              else
                {
                  LogPrint("thin", "Sending expedited block %s upstream to %s.\n", thinBlock.header.GetHash().ToString(),n->addrName.c_str());
                  // I should push the vRecv rather than reserialize
                  n->PushMessage(NetMsgType::XPEDITEDBLK, (unsigned char) EXPEDITED_MSG_XTHIN, hops, thinBlock);
                  n->blocksSent += 1;
                }
            }
        }
    }
#endif
}

void SendExpeditedBlock(const CBlock &block, const CNode *skip)
{
    // If we've already put the block in our hash table, we've already sent it out
    // BlockMap::iterator it = mapBlockIndex.find(block.GetHash());
    // if (it != mapBlockIndex.end()) return;


    if (!IsRecentlyExpeditedAndStore(block.GetHash()))
    {
        CXThinBlock thinBlock(block);
        SendExpeditedBlock(thinBlock, 0, skip);
    }
    else
    {
        // LogPrint("thin", "No need to send expedited block %s\n", block.GetHash().ToString());
    }
}





