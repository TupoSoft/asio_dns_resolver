#include "dns_answer.hpp"

#include "gtest/gtest.h"

#include <span>

using namespace tuposoft::asio::dns;

TEST(dns_answer, parse_rdata_a) {
    constexpr auto expected = "178.151.191.58";
    auto span = std::span{"\262\227\277:"};
    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};
    const auto actual = parse_rdata(input, qtype::A, 1, 4);
    ASSERT_EQ(expected, std::get<std::string>(actual));
}

TEST(dns_answer, parse_rdata_aaaa) {
    constexpr auto expected = "2606:2800:21f:cb07:6820:80da:af6b:8b2c";
    auto span = std::span{"&\006(\000\002\037\313\ah \200\332\257k\213,"};
    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};
    const auto actual = parse_rdata(input, qtype::AAAA, 1, 16);
    ASSERT_EQ(expected, std::get<std::string>(actual));
}

TEST(dns_answer, parse_rdata_ns) {
    constexpr auto expected = "gabriella.ns.cloudflare.com";
    constexpr auto response =
            std::span{"\221X\201\200\000\001\000\002\000\000\000\001\btuposoft\003com\000\000\002\000\001\300\f"
                      "\000\002\000\001\000\001Q\200\000\031\bbenedict\002ns\ncloudflare\300\025\300\f\000\002\000"
                      "\001\000\001Q\200\000\f\tgabriella\3003\000\000)\004\320\000\000\000\000\000\000"};

    const auto response_str = std::string{response.begin(), response.end()};
    const auto offset = response_str.find("\tgabriella");
    ASSERT_NE(offset, std::string::npos);

    auto input = std::istringstream{response_str, std::ios::binary};
    input.seekg(static_cast<std::streamoff>(offset));
    const auto actual = parse_rdata(input, qtype::NS, 1, 12);
    ASSERT_EQ(expected, std::get<std::string>(actual));
}

TEST(dns_answer, parse_rdata_txt) {
    constexpr auto expected = "v=spf1 ip4:217.160.29.228 ~all";
    constexpr auto rdata = std::span{"\036"
                                     "v=spf1 ip4:217.160.29.228 ~all"};
    auto input = std::istringstream{{rdata.begin(), rdata.end()}, std::ios::binary};
    const auto actual = parse_rdata(input, qtype::TXT, 1, 31);
    ASSERT_EQ(expected, std::get<std::string>(actual));
}

TEST(dns_answer, rejects_incorrect_address_lengths_before_reading) {
    for (const auto &[type, length]: std::vector<std::pair<qtype, std::uint16_t>>{
                 {qtype::A, 0}, {qtype::A, 3}, {qtype::A, 5},
                 {qtype::AAAA, 0}, {qtype::AAAA, 15}, {qtype::AAAA, 17}}) {
        SCOPED_TRACE(length);
        auto input = std::istringstream{std::string(length + 4, '*'), std::ios::binary};

        EXPECT_THROW(parse_rdata(input, type, 1, length), std::runtime_error);
        EXPECT_EQ(0, input.tellg());
    }
}

TEST(dns_answer, rejects_rdata_extending_past_message) {
    for (const auto type: {qtype::A, qtype::CNAME, static_cast<qtype>(257)}) {
        auto input = std::istringstream{std::string(3, '\0'), std::ios::binary};

        EXPECT_THROW(parse_rdata(input, type, 1, 4), std::runtime_error);
        EXPECT_EQ(0, input.tellg());
    }
}

TEST(dns_answer, rejects_truncated_record_header) {
    for (std::size_t length = 0; length < 10; ++length) {
        SCOPED_TRACE(length);
        auto input = std::istringstream{std::string(1 + length, '\0'), std::ios::binary};
        auto answer = dns_answer{};

        EXPECT_THROW(input >> answer, std::runtime_error);
    }
}

TEST(dns_answer, name_reads_cannot_cross_rdata_boundary) {
    struct test_case {
        std::string wire;
        std::uint16_t length;
        std::streamoff failure_position;
    };

    for (const auto type: {qtype::CNAME, qtype::NS, qtype::PTR}) {
        for (const auto &test: std::vector<test_case>{
                     {std::string{"\003abc\000", 5}, 3, 1},
                     {std::string{"\001a\000", 3}, 2, 2},
                     {std::string{"\300\000", 2}, 1, 1},
                     {std::string{"\000", 1}, 0, 0}}) {
            SCOPED_TRACE(static_cast<unsigned>(type));
            SCOPED_TRACE(test.length);
            auto input = std::istringstream{test.wire, std::ios::binary};

            EXPECT_THROW(parse_rdata(input, type, 1, test.length), std::runtime_error);
            EXPECT_EQ(test.failure_position, input.tellg());
        }
    }
}

TEST(dns_answer, rejects_trailing_bytes_after_name) {
    auto input = std::istringstream{std::string{"\001a\000\052", 4}, std::ios::binary};

    EXPECT_THROW(parse_rdata(input, qtype::CNAME, 1, 4), std::runtime_error);
    EXPECT_EQ(3, input.tellg());
    EXPECT_EQ(0x2a, input.get());
}

TEST(dns_answer, mx_preference_cannot_cross_rdata_boundary) {
    auto input = std::istringstream{std::string{"\000\012\000", 3}, std::ios::binary};

    EXPECT_THROW(parse_rdata(input, qtype::MX, 1, 1), std::runtime_error);
    EXPECT_EQ(0, input.tellg());
}

TEST(dns_answer, soa_integer_cannot_cross_rdata_boundary) {
    auto input = std::istringstream{std::string(22, '\0'), std::ios::binary};

    EXPECT_THROW(parse_rdata(input, qtype::SOA, 1, 21), std::runtime_error);
    EXPECT_EQ(18, input.tellg());
}

TEST(dns_answer, concatenates_txt_character_strings_and_preserves_next_byte) {
    auto input = std::istringstream{std::string{"\003one\000\003two\052", 10}, std::ios::binary};

    const auto actual = parse_rdata(input, qtype::TXT, 1, 9);

    EXPECT_EQ("onetwo", std::get<std::string>(actual));
    EXPECT_EQ(9, input.tellg());
    EXPECT_EQ(0x2a, input.get());
}

TEST(dns_answer, txt_character_string_cannot_cross_rdata_boundary) {
    auto input = std::istringstream{std::string{"\003abc\052", 5}, std::ios::binary};

    EXPECT_THROW(parse_rdata(input, qtype::TXT, 1, 3), std::runtime_error);
    EXPECT_EQ(1, input.tellg());
}

TEST(dns_answer, rejects_txt_without_character_strings) {
    auto input = std::istringstream{std::string{"\052", 1}, std::ios::binary};

    EXPECT_THROW(parse_rdata(input, qtype::TXT, 1, 0), std::runtime_error);
    EXPECT_EQ(0, input.tellg());
}

TEST(dns_answer, accepts_empty_txt_character_string) {
    auto input = std::istringstream{std::string{"\000\052", 2}, std::ios::binary};

    EXPECT_EQ("", std::get<std::string>(parse_rdata(input, qtype::TXT, 1, 1)));
    EXPECT_EQ(1, input.tellg());
}

TEST(dns_answer, retains_unsupported_class_as_raw_bytes) {
    auto input = std::istringstream{std::string{"\001\002\003\052", 4}, std::ios::binary};

    const auto actual = parse_rdata(input, qtype::A, 3, 3);

    EXPECT_EQ((std::vector<std::uint8_t>{1, 2, 3}), std::get<std::vector<std::uint8_t>>(actual));
    EXPECT_EQ(3, input.tellg());
    EXPECT_EQ(0x2a, input.get());
}

TEST(dns_answer, accepts_empty_unsupported_rdata) {
    auto input = std::istringstream{std::string{"\052", 1}, std::ios::binary};

    const auto actual = parse_rdata(input, qtype::SRV, 1, 0);

    EXPECT_TRUE(std::get<std::vector<std::uint8_t>>(actual).empty());
    EXPECT_EQ(0, input.tellg());
}
