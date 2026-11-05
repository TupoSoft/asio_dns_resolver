#include "common.hpp"

#include "gtest/gtest.h"

#include <algorithm>
#include <span>
#include <sstream>
#include <stdexcept>

using namespace tuposoft::asio::dns;

TEST(common, parse_query) {
    constexpr auto QUERY_QUESTION_OFFSET = 12;
    constexpr auto EXPECTED = "tuposoft.com";
    constexpr auto QUERY_SIZE = 53;
    std::span<const char, QUERY_SIZE> const span(
            "\250\256\001 "
            "\000\001\000\000\000\000\000\001\btuposoft\003com\000\000\017\000\001\000\000)"
            "\004\320\000\000\000\000\000\f\000\n\000\b\027\031>\263\030\356\246\237",
            QUERY_SIZE);
    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};
    input.seekg(QUERY_QUESTION_OFFSET);
    const auto actual = from_dns_label_format(input);
    ASSERT_EQ(EXPECTED, actual);
    ASSERT_EQ(000, input.get());
    ASSERT_EQ(017, input.get());
}

TEST(common, parse_pointer) {
    constexpr auto EXPECTED = "mail.tuposoft.com";
    auto span = std::span{
            "\250\256\201\200\000\001\000\001\000\000\000\001\btuposoft\003com\000\000\017\000\001\300\f\000\017\000"
            "\001\000\000\001,\000\t\000\n\004mail\300\f\000\000)\004\320\000\000\000\000\000\000"};
    const auto iter = std::ranges::find(span, '\004');
    const auto query_rdata_mx_offset = std::distance(span.begin(), iter);
    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};
    input.seekg(query_rdata_mx_offset);
    const auto actual = from_dns_label_format(input);
    ASSERT_EQ(EXPECTED, actual);
    ASSERT_EQ(000, input.get());
    ASSERT_EQ(000, input.get());
    ASSERT_EQ(')', input.get());
}

TEST(common, parse_pointer_2) {
    constexpr auto EXPECTED_1 = "aspmx.l.google.com";
    constexpr auto EXPECTED_2 = "alt3.aspmx.l.google.com";
    auto span = std::span{
            "'o\201\200\000\001\000\005\000\000\000\001\006foobar\003com\000\000\017\000\001\300\f\000\017\000\001\000"
            "\000\001,\000\023\000\001\005aspmx\001l\006google\300\023\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\n\004alt3\300*\300\f\000\017\000\001\000\000\001,\000\t\000\n\004alt4\300*"
            "\300\f\000\017\000\001\000\000\001,\000\t\000\005\004alt1\300*\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\005\004alt2\300*\000\000)\004\320\000\000\000\000\000\000"};
    auto query_str = std::string{span.begin(), span.end()};

    const auto expected_1_pos = query_str.find("\005aspmx");
    ASSERT_NE(expected_1_pos, std::string::npos);

    auto input = std::istringstream{query_str, std::ios::binary};
    input.seekg(static_cast<unsigned>(expected_1_pos));
    const auto actual_1 = from_dns_label_format(input);
    ASSERT_EQ(EXPECTED_1, actual_1);

    const auto expected_2_pos = query_str.find("\004alt3");
    ASSERT_NE(expected_2_pos, std::string::npos);

    input.seekg(static_cast<unsigned>(expected_2_pos));
    const auto actual_2 = from_dns_label_format(input);
    ASSERT_EQ(EXPECTED_2, actual_2);
}

TEST(common, rejects_self_referencing_pointer) {
    auto input = std::istringstream{std::string{"\xC0\x00", 2}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, rejects_pointer_cycle) {
    auto input = std::istringstream{std::string{"\xC0\x02\xC0\x00", 4}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, rejects_empty_name_input) {
    auto input = std::istringstream{std::string{}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, rejects_incomplete_pointer) {
    auto input = std::istringstream{std::string{"\xC0", 1}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, rejects_truncated_label) {
    auto input = std::istringstream{std::string{"\x03\x61", 2}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, rejects_name_without_terminator) {
    auto input = std::istringstream{std::string{"\x01\x61", 2}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, rejects_pointer_cycle_through_label) {
    auto input = std::istringstream{std::string{"\x01\x61\xC0\x00", 4}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, parse_pointer_chain) {
    auto input = std::istringstream{std::string{"\x01\x61\x00\xC0\x00\xC0\x03\x2A", 8}, std::ios::binary};
    input.seekg(5);

    EXPECT_EQ("a", from_dns_label_format(input));
    EXPECT_EQ(7, input.tellg());
    EXPECT_EQ(0x2A, input.get());
}

TEST(common, rejects_pointer_past_input) {
    auto input = std::istringstream{std::string{"\xC0\x03", 2}, std::ios::binary};

    EXPECT_THROW(from_dns_label_format(input), std::runtime_error);
}

TEST(common, parse_root_name) {
    auto input = std::istringstream{std::string{"\x00\x2A", 2}, std::ios::binary};

    const auto actual = from_dns_label_format(input);

    EXPECT_TRUE(actual.empty());
    EXPECT_EQ(1, input.tellg());
    EXPECT_EQ(0x2A, input.get());
}

TEST(common, parse_compressed_root_name) {
    auto input = std::istringstream{std::string{"\x00\xC0\x00\x2A", 4}, std::ios::binary};
    input.seekg(1);

    const auto actual = from_dns_label_format(input);

    EXPECT_TRUE(actual.empty());
    EXPECT_EQ(3, input.tellg());
    EXPECT_EQ(0x2A, input.get());
}
