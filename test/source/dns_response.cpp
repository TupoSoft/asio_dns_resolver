#include "dns_response.hpp"
#include "qclass.hpp"

#include "gtest/gtest.h"

#include <span>

using namespace tuposoft::asio::dns;

TEST(dns_response, mx) {
    constexpr auto RESPONSE_ID = 0x276F;
    constexpr auto TTL = 300;

    std::vector<dns_answer<qtype::MX>> expected = {
            {"foobar.com", qtype::MX, 1, TTL, 19,
             mx_rdata{
                     1,
                     "aspmx.l.google.com",
             }},
            {"foobar.com", qtype::MX, 1, TTL, 9,
             mx_rdata{
                     10,
                     "alt3.aspmx.l.google.com",
             }},
            {"foobar.com", qtype::MX, 1, TTL, 9,
             mx_rdata{
                     10,
                     "alt4.aspmx.l.google.com",
             }},
            {"foobar.com", qtype::MX, 1, TTL, 9,
             mx_rdata{
                     5,
                     "alt1.aspmx.l.google.com",
             }},
            {"foobar.com", qtype::MX, 1, TTL, 9,
             mx_rdata{
                     5,
                     "alt2.aspmx.l.google.com",
             }},
    };
    auto expected_response =
            dns_response<qtype::MX>{{
                                            .header =
                                                    {
                                                            .id = RESPONSE_ID,
                                                            .rd = 1,
                                                            .qr = 1,
                                                            .ra = 1,
                                                            .qdcount = 1,
                                                            .ancount = static_cast<std::uint16_t>(expected.size()),
                                                            .nscount = 0,
                                                            .arcount = 1,
                                                    },
                                            .question =
                                                    {
                                                            .qname = "foobar.com",
                                                            .type = qtype::MX,
                                                    },
                                    },
                                    expected};

    auto span = std::span{
            "'o\201\200\000\001\000\005\000\000\000\001\006foobar\003com\000\000\017\000\001\300\f\000\017\000\001\000"
            "\000\001,\000\023\000\001\005aspmx\001l\006google\300\023\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\n\004alt3\300*\300\f\000\017\000\001\000\000\001,\000\t\000\n\004alt4\300*"
            "\300\f\000\017\000\001\000\000\001,\000\t\000\005\004alt1\300*\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\005\004alt2\300*\000\000)\004\320\000\000\000\000\000\000"};

    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};

    auto actual_dns_response = dns_response<qtype::MX>{};
    input >> actual_dns_response;

    ASSERT_EQ(expected_response.header, actual_dns_response.header) << "The header doesn't match!";
    ASSERT_EQ(expected_response.question, actual_dns_response.question) << "The question doesn't match!";
    ASSERT_EQ(expected_response.answers, actual_dns_response.answers) << "The answers don't match!";
    ASSERT_EQ(expected_response, actual_dns_response) << "The response doesn't match!";
}

TEST(dns_response, soa) {
    auto span =
            std::span{"5D\201\240\000\001\000\001\000\000\000\001\aexample\003com\000\000\006\000\001\300\f\000\006\000"
                      "\001\000\000\016\020\000,\002ns\005icann\003org\000\003noc\003dns\300,x\244mt\000\000\034 "
                      "\000\000\016\020\000\022u\000\000\000\016\020\000\000)\004\320\000\000\000\000\000\000"};

    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};

    auto actual = dns_response<qtype::SOA>{};
    input >> actual;

    constexpr auto RESPONSE_ID = 0x3544;
    constexpr auto TTL = 3600;
    constexpr auto RDLENGH = 44;
    constexpr auto SERIAL = 2024041844;
    constexpr auto REFRESH = 7200;
    constexpr auto RETRY = 3600;
    constexpr auto EXPIRE = 1209600;
    constexpr auto MINIMUM = 3600;

    std::vector<dns_answer<qtype::SOA>> answers = {{"example.com", qtype::SOA, 1, TTL, RDLENGH,
                                                    soa_rdata{
                                                            .mname = "ns.icann.org",
                                                            .rname = "noc.dns.icann.org",
                                                            .serial = SERIAL,
                                                            .refresh = REFRESH,
                                                            .retry = RETRY,
                                                            .expire = EXPIRE,
                                                            .minimum = MINIMUM,
                                                    }}};

    auto expected = dns_response<qtype::SOA>{
            {{
                     .id = RESPONSE_ID,
                     .rd = 1,
                     .qr = 1,
                     .ad = 1,
                     .ra = 1,
                     .qdcount = 1,
                     .ancount = 1,
                     .nscount = 0,
                     .arcount = 1,
             },
             {
                     .qname = "example.com",
                     .type = qtype::SOA,
             }},
            answers,
    };

    ASSERT_EQ(expected.header, actual.header) << "The header doesn't match!";
    ASSERT_EQ(expected.question, actual.question) << "The question doesn't match!";
    ASSERT_EQ(expected.answers, expected.answers) << "The answers don't match!";
    ASSERT_EQ(expected, actual) << "The response doesn't match!";
}
