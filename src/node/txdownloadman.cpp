// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txdownloadman.h>
#include <node/txdownloadman_impl.h>

namespace node {

TxDownloadManager::TxDownloadManager(const TxDownloadOptions& options) :
    m_impl{std::make_unique<TxDownloadImpl>(options)}
{}
TxDownloadManager::~TxDownloadManager() = default;

TxOrphanage& TxDownloadManager::GetOrphanageRef()
{
    return m_impl->m_orphanage;
}
TxRequestTracker& TxDownloadManager::GetTxRequestRef()
{
    return m_impl->m_txrequest;
}
CRollingBloomFilter& TxDownloadManager::RecentRejectsFilter()
{
    return m_impl->RecentRejectsFilter();
}
CRollingBloomFilter& TxDownloadManager::RecentRejectsReconsiderableFilter()
{
    return m_impl->RecentRejectsReconsiderableFilter();
}
void TxDownloadManager::ActiveTipChange()
{
    m_impl->ActiveTipChange();
}
void TxDownloadManager::BlockConnected(const std::shared_ptr<const CBlock>& pblock)
{
    m_impl->BlockConnected(pblock);
}
void TxDownloadManager::BlockDisconnected()
{
    m_impl->BlockDisconnected();
}

bool TxDownloadManager::AlreadyHaveTx(const GenTxid& gtxid, bool include_reconsiderable)
{
    return m_impl->AlreadyHaveTx(gtxid, include_reconsiderable);
}
} // namespace node
