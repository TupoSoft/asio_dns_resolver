#pragma once

#include "common.hpp"

namespace tuposoft::asio::dns {
    enum struct qtype : std::uint8_t {
        A = 1, // IPv4 address record
        NS = 2, // Delegates a DNS zone to use the given authoritative name servers
        CNAME = 5, // Canonical name record
        SOA = 6, // Start of [a zone of] authority record
        PTR = 12, // Pointer record
        MX = 15, // Mail exchange record
        TXT = 16, // Arbitrary text record
        AAAA = 28, // IPv6 address record
        SRV = 33, // Service locator
        OPT = 41, // Option record
        DS = 43, // Delegation signer
        RRSIG = 46, // DNSSEC signature
        NSEC = 47, // Next-secure record
        DNSKEY = 48 // DNSSEC public key
    };
} // namespace tuposoft
