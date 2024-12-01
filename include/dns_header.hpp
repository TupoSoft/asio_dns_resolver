#pragma once

#include "common.hpp"

#include <cstdint>
#include <iostream>

namespace tuposoft::asio::dns {
    struct dns_header {
        std::uint16_t id{}; // Identification

        std::uint8_t rd : 1 {1}; // Recursion Desired
        std::uint8_t tc : 1 {}; // Truncated Message
        std::uint8_t aa : 1 {}; // Authoritative Answer
        std::uint8_t opcode : 4 {}; // Opcode
        std::uint8_t qr : 1 {}; // Query/Response uint8_t

        std::uint8_t rcode : 4 {}; // Response Code
        std::uint8_t cd : 1 {}; // Checking Disabled
        std::uint8_t ad : 1 {}; // Authenticated Data
        std::uint8_t z : 1 {}; // Reserved
        std::uint8_t ra : 1 {}; // Recursion Available

        std::uint16_t qdcount{1}; // Number of question entries
        std::uint16_t ancount{}; // Number of answer entries
        std::uint16_t nscount{}; // Number of authority entries
        std::uint16_t arcount{}; // Number of resource entries
    };

    auto tie_dns_header(const dns_header &header);

    auto operator==(const dns_header &first, const dns_header &second) -> bool;

    auto operator>>(std::istream &input, dns_header &header) -> decltype(input);

    auto operator<<(std::ostream &output, const dns_header &header) -> decltype(output);

    enum flag_positions : unsigned char {
        RD_POSITION = 8U,
        TC_POSITION = 9U,
        AA_POSITION = 10U,
        OPCODE_POSITION = 11U,
        QR_POSITION = 15U,
        RCODE_POSITION = 0U,
        CD_POSITION = 4U,
        AD_POSITION = 5U,
        Z_POSITION = 6U,
        RA_POSITION = 7U,
    };
} // namespace tuposoft
