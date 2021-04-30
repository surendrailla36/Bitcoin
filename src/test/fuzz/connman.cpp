// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <chainparams.h>
#include <common/args.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <protocol.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/net.h>
#include <test/util/setup_common.h>
#include <util/translation.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace {
const TestingSetup* g_setup;
} // namespace

void initialize_connman()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(connman, .init = initialize_connman)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    SetMockTime(ConsumeTime(fuzzed_data_provider));

    // Mock CreateSock() to create FuzzedSock.
    auto CreateSockOrig = CreateSock;
    CreateSock = [&fuzzed_data_provider](const CService&) {
        return std::make_unique<FuzzedSock>(fuzzed_data_provider);
    };

    // Mock g_dns_lookup() to return a fuzzed address.
    g_dns_lookup = [&fuzzed_data_provider](const std::string&, bool) {
        return std::vector<CNetAddr>{ConsumeNetAddr(fuzzed_data_provider)};
    };

    ConnmanTestMsg connman{fuzzed_data_provider.ConsumeIntegral<uint64_t>(),
                     fuzzed_data_provider.ConsumeIntegral<uint64_t>(),
                     *g_setup->m_node.addrman,
                     *g_setup->m_node.netgroupman,
                     fuzzed_data_provider.ConsumeBool()};
    CConnman::Options options;
    options.m_msgproc = g_setup->m_node.peerman.get();
    connman.Init(options);

    CNetAddr random_netaddr;
    CAddress random_address;
    CNode random_node = ConsumeNode(fuzzed_data_provider);
    CSubNet random_subnet;
    std::string random_string;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 100) {
        CNode& p2p_node{*ConsumeNodeAsUniquePtr(fuzzed_data_provider).release()};
        connman.AddTestNode(p2p_node);
    }

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 10000) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                random_netaddr = ConsumeNetAddr(fuzzed_data_provider);
            },
            [&] {
                random_address = ConsumeAddress(fuzzed_data_provider);
            },
            [&] {
                random_subnet = ConsumeSubNet(fuzzed_data_provider);
            },
            [&] {
                random_string = fuzzed_data_provider.ConsumeRandomLengthString(64);
            },
            [&] {
                connman.AddNode(random_string);
            },
            [&] {
                connman.CheckIncomingNonce(fuzzed_data_provider.ConsumeIntegral<uint64_t>());
            },
            [&] {
                connman.DisconnectNode(fuzzed_data_provider.ConsumeIntegral<NodeId>());
            },
            [&] {
                connman.DisconnectNode(random_netaddr);
            },
            [&] {
                connman.DisconnectNode(random_string);
            },
            [&] {
                connman.DisconnectNode(random_subnet);
            },
            [&] {
                connman.ForEachNode([](auto) {});
            },
            [&] {
                (void)connman.ForNode(fuzzed_data_provider.ConsumeIntegral<NodeId>(), [&](auto) { return fuzzed_data_provider.ConsumeBool(); });
            },
            [&] {
                (void)connman.GetAddresses(
                    /*max_addresses=*/fuzzed_data_provider.ConsumeIntegral<size_t>(),
                    /*max_pct=*/fuzzed_data_provider.ConsumeIntegral<size_t>(),
                    /*network=*/std::nullopt);
            },
            [&] {
                (void)connman.GetAddresses(
                    /*requestor=*/random_node,
                    /*max_addresses=*/fuzzed_data_provider.ConsumeIntegral<size_t>(),
                    /*max_pct=*/fuzzed_data_provider.ConsumeIntegral<size_t>());
            },
            [&] {
                (void)connman.GetDeterministicRandomizer(fuzzed_data_provider.ConsumeIntegral<uint64_t>());
            },
            [&] {
                (void)connman.GetNodeCount(fuzzed_data_provider.PickValueInArray({ConnectionDirection::None, ConnectionDirection::In, ConnectionDirection::Out, ConnectionDirection::Both}));
            },
            [&] {
                (void)connman.OutboundTargetReached(fuzzed_data_provider.ConsumeBool());
            },
            [&] {
                CSerializedNetMsg serialized_net_msg;
                serialized_net_msg.m_type = fuzzed_data_provider.ConsumeRandomLengthString(CMessageHeader::COMMAND_SIZE);
                serialized_net_msg.data = ConsumeRandomLengthByteVector(fuzzed_data_provider);
                connman.PushMessage(&random_node, std::move(serialized_net_msg));
            },
            [&] {
                connman.RemoveAddedNode(random_string);
            },
            [&] {
                connman.SetNetworkActive(fuzzed_data_provider.ConsumeBool());
            },
            [&] {
                connman.SetTryNewOutboundPeer(fuzzed_data_provider.ConsumeBool());
            },
            [&] {
                const auto& to_addr{random_address};

                const bool count_failure{fuzzed_data_provider.ConsumeBool()};

                CSemaphoreGrant grant;
                CSemaphoreGrant* grant_ptr{fuzzed_data_provider.ConsumeBool() ? nullptr : &grant};

                const char* to_str{fuzzed_data_provider.ConsumeBool() ? nullptr :
                                                                        random_string.c_str()};

                ConnectionType conn_type{
                    fuzzed_data_provider.PickValueInArray(ALL_CONNECTION_TYPES)};
                if (conn_type == ConnectionType::INBOUND) { // INBOUND is not allowed
                    conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
                }

                connman.OpenNetworkConnection(to_addr, count_failure, grant_ptr, to_str, conn_type);
            },
            [&] {
                connman.SetNetworkActive(true);

                NetPermissionFlags permissions{
                    ConsumeWeakEnum(fuzzed_data_provider, ALL_NET_PERMISSION_FLAGS)};
                auto me = ConsumeAddress(fuzzed_data_provider);
                auto peer = ConsumeAddress(fuzzed_data_provider);
                auto sock = CreateSock(peer);

                connman.CreateNodeFromAcceptedSocketPublic(std::move(sock), permissions, me, peer);
            },
            [&] {
                CConnman::Options options;

                options.vBinds = ConsumeServiceVector(fuzzed_data_provider, 5);

                options.vWhiteBinds = std::vector<NetWhitebindPermissions>{
                    fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 5)};
                for (auto& wb : options.vWhiteBinds) {
                    wb.m_flags = ConsumeWeakEnum(fuzzed_data_provider, ALL_NET_PERMISSION_FLAGS);
                    wb.m_service = ConsumeService(fuzzed_data_provider);
                }

                options.onion_binds = ConsumeServiceVector(fuzzed_data_provider, 5);

                options.bind_on_any = options.vBinds.empty() && options.vWhiteBinds.empty() &&
                                      options.onion_binds.empty();

                connman.InitBindsPublic(options);
            },
            [&] {
                connman.SocketHandlerPublic();
            });
    }
    (void)connman.GetAddedNodeInfo();
    (void)connman.GetExtraFullOutboundCount();
    (void)connman.GetLocalServices();
    (void)connman.GetMaxOutboundTarget();
    (void)connman.GetMaxOutboundTimeframe();
    (void)connman.GetMaxOutboundTimeLeftInCycle();
    (void)connman.GetNetworkActive();
    std::vector<CNodeStats> stats;
    connman.GetNodeStats(stats);
    (void)connman.GetOutboundTargetBytesLeft();
    (void)connman.GetTotalBytesRecv();
    (void)connman.GetTotalBytesSent();
    (void)connman.GetTryNewOutboundPeer();
    (void)connman.GetUseAddrmanOutgoing();

    connman.ClearTestNodes();
    CreateSock = CreateSockOrig;
}
