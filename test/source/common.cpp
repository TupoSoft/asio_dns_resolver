#include "common.hpp"

#include "gtest/gtest.h"

#include <span>
#include <algorithm>

using namespace tuposoft::asio::dns;

TEST(common, parse_query) {
    constexpr auto QUERY_QUESTION_OFFSET = 12;
    constexpr auto EXPECTED = "tuposoft.com";
    constexpr auto QUERY_SIZE = 53;
    std::span<const char, QUERY_SIZE> span(
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
