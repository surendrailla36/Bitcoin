// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef H_BITCOIN_SCRIPT_INTERPRETER
#define H_BITCOIN_SCRIPT_INTERPRETER

#include "core.h"

#include <vector>
#include <stdint.h>
#include <string>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

/** Signature hash types/flags */
enum
{
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH      = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    // Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
    // skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG    = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S     = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),
};

class TxSignatureHasher
{
private:
    const CTransaction txTo;
    unsigned int nIn;
public:
    TxSignatureHasher(const CTransaction& txToIn, unsigned int nInIn) : txTo(txToIn), nIn(nInIn) {}
    uint256 SignatureHash(const CScript& scriptCode, int nHashType) const;
};

class BaseSignatureChecker
{
public:
    virtual bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode) const
    {
        return false;
    }

    virtual ~BaseSignatureChecker() {}
};

class SignatureChecker : public BaseSignatureChecker
{
private:
    const TxSignatureHasher hasher;
protected:
    virtual bool VerifySignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const;

public:
    SignatureChecker(const CTransaction& txToIn, unsigned int nIn) : hasher(TxSignatureHasher(txToIn, nIn)) { }
    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode) const;
};

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, unsigned int flags, const BaseSignatureChecker& checker);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, const BaseSignatureChecker& checker);

#endif // H_BITCOIN_SCRIPT_INTERPRETER
