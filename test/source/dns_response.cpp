#include "dns_response.hpp"
#include "qclass.hpp"

#include "gtest/gtest.h"

#include <span>
#include <utility>

using namespace tuposoft::asio::dns;

TEST(dns_response, mx) {
    constexpr auto RESPONSE_ID = 0x276F;
    constexpr auto TTL = 300;

    std::vector<dns_answer> const expected = {
            {
                    .name = "foobar.com",
                    .type = qtype::MX,
                    .cls = 1,
                    .ttl = TTL,
                    .rdlength = 19,
                    .rdata =
                            mx_rdata{
                                    .preference = 1,
                                    .mx = "aspmx.l.google.com",
                            },
            },
            {
                    .name = "foobar.com",
                    .type = qtype::MX,
                    .cls = 1,
                    .ttl = TTL,
                    .rdlength = 9,
                    .rdata =
                            mx_rdata{
                                    .preference = 10,
                                    .mx = "alt3.aspmx.l.google.com",
                            },
            },
            {
                    .name = "foobar.com",
                    .type = qtype::MX,
                    .cls = 1,
                    .ttl = TTL,
                    .rdlength = 9,
                    .rdata =
                            mx_rdata{
                                    .preference = 10,
                                    .mx = "alt4.aspmx.l.google.com",
                            },
            },
            {
                    .name = "foobar.com",
                    .type = qtype::MX,
                    .cls = 1,
                    .ttl = TTL,
                    .rdlength = 9,
                    .rdata =
                            mx_rdata{
                                    .preference = 5,
                                    .mx = "alt1.aspmx.l.google.com",
                            },
            },
            {
                    .name = "foobar.com",
                    .type = qtype::MX,
                    .cls = 1,
                    .ttl = TTL,
                    .rdlength = 9,
                    .rdata =
                            mx_rdata{
                                    .preference = 5,
                                    .mx = "alt2.aspmx.l.google.com",
                            },
            },
    };

    auto const expected_response = dns_response{
            {
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
            expected,
    };

    auto const span = std::span{
            "'o\201\200\000\001\000\005\000\000\000\001\006foobar\003com\000\000\017\000\001\300\f\000\017\000\001\000"
            "\000\001,\000\023\000\001\005aspmx\001l\006google\300\023\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\n\004alt3\300*\300\f\000\017\000\001\000\000\001,\000\t\000\n\004alt4\300*"
            "\300\f\000\017\000\001\000\000\001,\000\t\000\005\004alt1\300*\300\f\000\017\000\001\000\000\001,"
            "\000\t\000\005\004alt2\300*\000\000)\004\320\000\000\000\000\000\000"};

    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};

    auto actual_dns_response = dns_response{};
    input >> actual_dns_response;

    ASSERT_EQ(expected_response.header, actual_dns_response.header) << "The header doesn't match!";
    ASSERT_EQ(expected_response.question, actual_dns_response.question) << "The question doesn't match!";
    ASSERT_EQ(expected_response.answers, actual_dns_response.answers) << "The answers don't match!";
    ASSERT_EQ(expected_response, actual_dns_response) << "The response doesn't match!";
}

TEST(dns_response, soa) {
    auto const span =
            std::span{"5D\201\240\000\001\000\001\000\000\000\001\aexample\003com\000\000\006\000\001\300\f\000\006\000"
                      "\001\000\000\016\020\000,\002ns\005icann\003org\000\003noc\003dns\300,x\244mt\000\000\034 "
                      "\000\000\016\020\000\022u\000\000\000\016\020\000\000)\004\320\000\000\000\000\000\000"};

    auto input = std::istringstream{{span.begin(), span.end()}, std::ios::binary};

    auto actual = dns_response{};
    input >> actual;

    constexpr auto RESPONSE_ID = 0x3544;
    constexpr auto TTL = 3600;
    constexpr auto RDLENGH = 44;
    constexpr auto SERIAL = 2024041844;
    constexpr auto REFRESH = 7200;
    constexpr auto RETRY = 3600;
    constexpr auto EXPIRE = 1209600;
    constexpr auto MINIMUM = 3600;

    std::vector<dns_answer> const answers = {
            {
                    .name = "example.com",
                    .type = qtype::SOA,
                    .cls = 1,
                    .ttl = TTL,
                    .rdlength = RDLENGH,
                    .rdata =
                            soa_rdata{
                                    .mname = "ns.icann.org",
                                    .rname = "noc.dns.icann.org",
                                    .serial = SERIAL,
                                    .refresh = REFRESH,
                                    .retry = RETRY,
                                    .expire = EXPIRE,
                                    .minimum = MINIMUM,
                            },
            },
    };

    auto const expected = dns_response{
            {.header =
                     {
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
             .question =
                     {
                             .qname = "example.com",
                             .type = qtype::SOA,
                     }},
            answers,
    };

    ASSERT_EQ(expected.header, actual.header) << "The header doesn't match!";
    ASSERT_EQ(expected.question, actual.question) << "The question doesn't match!";
    ASSERT_EQ(expected.answers, actual.answers) << "The answers don't match!";
    ASSERT_EQ(expected, actual) << "The response doesn't match!";
}

namespace {
    using namespace std::string_view_literals;

    auto mixed_response(const qtype type, const std::string_view data,
                        const std::string_view cname = "\006target\300\020"sv) -> std::string {
        auto output = std::ostringstream{std::ios::binary};
        const auto question = "\022\064\201\200\000\001\000\002\000\000\000\000"
                              "\003www\007example\003com\000"sv;
        output.write(question.data(), question.size());
        write_big_endian(output, std::to_underlying(type));
        write_big_endian(output, std::uint16_t{1});

        const auto cname_header = "\300\014\000\005\000\001\000\000\000\074"sv;
        output.write(cname_header.data(), cname_header.size());
        write_big_endian(output, static_cast<std::uint16_t>(cname.size()));
        output.write(cname.data(), cname.size());

        // Offset 45 is the earlier CNAME RDATA; its suffix points into the question.
        output.write("\300\055", 2);
        write_big_endian(output, static_cast<std::uint16_t>(type));
        output.write("\000\001\000\000\000\074", 6);
        write_big_endian(output, static_cast<std::uint16_t>(data.size()));
        output.write(data.data(), data.size());
        return output.str();
    }
} // namespace

TEST(dns_response, decodes_cname_before_a_aaaa_and_mx) {
    struct test_case {
        qtype type;
        std::string_view data;
        rdata_value expected;
    };

    for (const auto &test:
         std::vector<test_case>{{qtype::A, "\300\000\002\001"sv, std::string{"192.0.2.1"}},
                                {qtype::AAAA, "\040\001\015\270\000\000\000\000\000\000\000\000\000\000\000\001"sv,
                                 std::string{"2001:db8::1"}},
                                {qtype::MX, "\000\012\004mail\300\055"sv, mx_rdata{10, "mail.target.example.com"}}}) {
        SCOPED_TRACE(static_cast<unsigned>(test.type));
        const auto wire = mixed_response(test.type, test.data);
        auto input = std::istringstream{wire, std::ios::binary};
        auto actual = dns_response{};

        input >> actual;

        EXPECT_EQ(test.type, actual.question.type);
        ASSERT_EQ(2, actual.answers.size());
        EXPECT_EQ("www.example.com", actual.answers[0].name);
        EXPECT_EQ(qtype::CNAME, actual.answers[0].type);
        EXPECT_EQ(9, actual.answers[0].rdlength);
        EXPECT_EQ("target.example.com", std::get<std::string>(actual.answers[0].rdata));
        EXPECT_EQ("target.example.com", actual.answers[1].name);
        EXPECT_EQ(test.type, actual.answers[1].type);
        EXPECT_EQ(test.data.size(), actual.answers[1].rdlength);
        EXPECT_EQ(test.expected, actual.answers[1].rdata);
        EXPECT_EQ(static_cast<std::streamoff>(wire.size()), input.tellg());
    }
}

TEST(dns_response, two_byte_cname_does_not_consume_following_record) {
    const auto wire = mixed_response(qtype::A, "\300\000\002\001"sv, "\300\020"sv);
    auto input = std::istringstream{wire, std::ios::binary};
    auto actual = dns_response{};

    input >> actual;

    ASSERT_EQ(2, actual.answers.size());
    EXPECT_EQ(qtype::CNAME, actual.answers[0].type);
    EXPECT_EQ(2, actual.answers[0].rdlength);
    EXPECT_EQ("example.com", std::get<std::string>(actual.answers[0].rdata));
    EXPECT_EQ("example.com", actual.answers[1].name);
    EXPECT_EQ(qtype::A, actual.answers[1].type);
    EXPECT_EQ("192.0.2.1", std::get<std::string>(actual.answers[1].rdata));
    EXPECT_EQ(static_cast<std::streamoff>(wire.size()), input.tellg());
}

TEST(dns_response, decodes_uncompressed_cname) {
    const auto wire = mixed_response(qtype::A, "\300\000\002\001"sv, "\006target\007example\003com\000"sv);
    auto input = std::istringstream{wire, std::ios::binary};
    auto actual = dns_response{};

    input >> actual;

    ASSERT_EQ(2, actual.answers.size());
    EXPECT_EQ("target.example.com", std::get<std::string>(actual.answers[0].rdata));
    EXPECT_EQ("target.example.com", actual.answers[1].name);
    EXPECT_EQ("192.0.2.1", std::get<std::string>(actual.answers[1].rdata));
    EXPECT_EQ(static_cast<std::streamoff>(wire.size()), input.tellg());
}

TEST(dns_response, preserves_unknown_type_above_255_and_next_record) {
    auto wire = mixed_response(static_cast<qtype>(257), "\000\377\052"sv);
    wire[7] = 3;
    wire.append("\300\014\000\001\000\001\000\000\000\074\000\004\300\000\002\001", 16);
    auto input = std::istringstream{wire, std::ios::binary};
    auto actual = dns_response{};

    input >> actual;

    ASSERT_EQ(3, actual.answers.size());
    EXPECT_EQ(257, static_cast<std::uint16_t>(actual.answers[1].type));
    EXPECT_EQ((std::vector<std::uint8_t>{0, 255, 42}), std::get<std::vector<std::uint8_t>>(actual.answers[1].rdata));
    EXPECT_EQ(qtype::A, actual.answers[2].type);
    EXPECT_EQ("192.0.2.1", std::get<std::string>(actual.answers[2].rdata));
    EXPECT_EQ(static_cast<std::streamoff>(wire.size()), input.tellg());
}

TEST(dns_response, rejects_truncated_header) {
    for (std::size_t length = 0; length < 12; ++length) {
        SCOPED_TRACE(length);
        auto input = std::istringstream{std::string(length, '\0'), std::ios::binary};
        auto actual = dns_response{};

        EXPECT_THROW(input >> actual, std::runtime_error);
    }
}

TEST(dns_response, malformed_later_record_does_not_publish_partial_answers) {
    auto wire = mixed_response(qtype::A, "\300\000\002\001"sv);
    wire.pop_back();
    auto input = std::istringstream{wire, std::ios::binary};
    auto actual = dns_response{};
    actual.header.id = 42;
    actual.answers.push_back(dns_answer{.name = "existing"});
    const auto original = actual;

    EXPECT_THROW(input >> actual, std::runtime_error);
    EXPECT_EQ(original, actual);
}
