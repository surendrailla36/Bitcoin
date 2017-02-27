#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the listsincelast RPC."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class ListSinceBlockTest (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 6

    def test_reorg(self):
        '''
        `listsinceblock` did not behave correctly when handed a block that was
        no longer in the main chain:

             ab0
          /       \
        aa1 [tx0]   bb1
         |           |
        aa2         bb2
         |           |
        aa3         bb3
                     |
                    bb4

        Consider a client that has only seen block `aa3` above. It asks the node
        to `listsinceblock aa3`. But at some point prior the main chain switched
        to the bb chain.

        Previously: listsinceblock would find height=4 for block aa3 and compare
        this to height=5 for the tip of the chain (bb4). It would then return
        results restricted to bb3-bb4.

        Now: listsinceblock finds the fork at ab0 and returns results in the
        range bb1-bb4.

        This test only checks that [tx0] is present.
        '''

        assert_equal(self.is_network_split, False)
        self.nodes[2].generate(101)
        self.sync_all()

        assert_equal(self.nodes[0].getbalance(), 0)
        assert_equal(self.nodes[1].getbalance(), 0)
        assert_equal(self.nodes[2].getbalance(), 50)
        assert_equal(self.nodes[3].getbalance(), 0)

        # Split network into two
        self.split_network()
        assert_equal(self.is_network_split, True)

        # send to nodes[0] from nodes[2]
        senttx = self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 1)

        # generate on both sides
        lastblockhash = self.nodes[1].generate(6)[5]
        self.nodes[2].generate(7)
        self.log.info('lastblockhash=%s' % (lastblockhash))

        self.sync_all()

        self.join_network()

        # listsinceblock(lastblockhash) should now include tx, as seen from nodes[0]
        lsbres = self.nodes[0].listsinceblock(lastblockhash)
        found = False
        for tx in lsbres['transactions']:
            if tx['txid'] == senttx:
                found = True
                break
        assert_equal(found, True)

    def test_reorg3(self):
        '''
        Same as above, except there are now three conflicting chains (the middle
        one being the longest).
        '''

        assert_equal(self.is_network_split, False)
        assert_equal(len(self.nodes), 6)
        self.sync_all()

        # Split network into three chains
        self.split_network([2, 4])
        assert_equal(len(self.chains), 3)
        assert_equal(len(self.chains[0]), 2)
        assert_equal(len(self.chains[1]), 2)
        assert_equal(len(self.chains[2]), 2)
        assert_equal(self.is_network_split, True)

        # send to nodes[0] from nodes[2]
        senttx = self.nodes[2].sendtoaddress(self.nodes[0].getnewaddress(), 1)

        # generate on all sides
        lastblockhash = self.nodes[1].generate(6)[5]
        self.nodes[2].generate(8)
        self.nodes[4].generate(7)
        self.log.info('lastblockhash=%s' % (lastblockhash))

        self.sync_all()

        self.join_network()
        assert_equal(len(self.chains), 1)

        # listsinceblock(lastblockhash) should now include tx, as seen from nodes[0]
        lsbres = self.nodes[0].listsinceblock(lastblockhash)
        found = False
        for tx in lsbres['transactions']:
            if tx['txid'] == senttx:
                found = True
                break
        assert_equal(found, True)

    def run_test(self):
        self.test_reorg()
        self.test_reorg3()

if __name__ == '__main__':
    ListSinceBlockTest().main()
