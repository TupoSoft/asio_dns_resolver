#include "dns_response.hpp"

#include <gtest/gtest.h>

#include <ios>

using namespace tuposoft::asio::dns;

constexpr auto STRING_TERMINATOR = '\0';

struct dns_test : testing::Test {
protected:
    std::vector<std::uint8_t> domain_labels_ = {static_cast<uint8_t>(label_length_::tuposoft_length),
                                                't',
                                                'u',
                                                'p',
                                                'o',
                                                's',
                                                'o',
                                                'f',
                                                't',
                                                static_cast<uint8_t>(label_length_::com_length),
                                                'c',
                                                'o',
                                                'm',
                                                STRING_TERMINATOR};

    std::string domain_ = "tuposoft.com";

    std::vector<std::uint8_t> query_bytes_ = {
            0x16, 0x6a, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x74, 0x75,
            0x70, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01,
    };

    std::vector<std::uint8_t> response_bytes_ = {
            0xc9, 0x12, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x74, 0x75, 0x70, 0x6f,
            0x73, 0x6f, 0x66, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0f,
            0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x09, 0x00, 0x0a, 0x04, 0x6d, 0x61, 0x69, 0x6c, 0xc0, 0x0c,
    };

    dns_header header_{
            .id = 0x166a,
            .rd = 1,
            .ad = 1,
            .qdcount = 1,
            .arcount = 1,
    };

    dns_question question_{
            .qname = "tuposoft.com",
            .type = qtype::MX,
    };

    dns_query query_{
            .header = header_,
            .question = question_,
    };

    dns_answer<qtype::MX> answer_{
            .name = domain_, .cls = 1, .ttl = 0x012c, .rdlength = 0x09, .rdata = mx_rdata{10, "mail.tuposoft.com"}};

private:
    enum class label_length_ : uint8_t {
        tuposoft_length = 8,
        com_length = 3,
    };
};

TEST_F(dns_test, to_dns_label_format) {
    const auto actual = to_dns_label_format(domain_);
    ASSERT_EQ(domain_labels_, actual);
}

TEST_F(dns_test, from_dns_label_format) {
    std::istringstream input{{domain_labels_.begin(), domain_labels_.end()}};
    const auto actual = from_dns_label_format(input);
    ASSERT_EQ(domain_, actual);
}

TEST_F(dns_test, header_deserialization) {
    std::istringstream input{{query_bytes_.begin(), query_bytes_.end()}, std::ios::binary};
    auto actual = dns_header{};
    input >> actual;
    ASSERT_EQ(header_, actual);
}

TEST_F(dns_test, header_serialization) {
    std::ostringstream output{std::ios::binary};
    output << header_;
    const auto expected = std::string{query_bytes_.begin(), query_bytes_.begin() + 12};
    ASSERT_EQ(output.str(), expected);
}

TEST_F(dns_test, question_deserialization) {
    auto input = std::istringstream{
            {query_bytes_.begin() + static_cast<std::uint8_t>(message_byte_offsets::QUESTION), query_bytes_.end()},
            std::ios::binary};
    auto question = dns_question{};
    input >> question;
    ASSERT_EQ(question_, question);
}

TEST_F(dns_test, question_serialization) {
    auto output = std::ostringstream{std::ios::binary};
    output << question_;
    const auto expected = std::string{query_bytes_.begin() + static_cast<std::uint8_t>(message_byte_offsets::QUESTION),
                                      query_bytes_.end()};
    ASSERT_EQ(output.str(), expected);
}

TEST_F(dns_test, query_deserialization) {
    auto input = std::istringstream{{query_bytes_.begin(), query_bytes_.end()}, std::ios::binary};
    auto query = dns_query{};
    input >> query;
    ASSERT_EQ(query_, query);
}

TEST_F(dns_test, query_serialization) {
    auto output = std::ostringstream{std::ios::binary};
    output << query_;
    const auto expected = std::string{query_bytes_.begin(), query_bytes_.end()};
    ASSERT_EQ(output.str(), expected);
}

TEST_F(dns_test, answer_deserialization) {
    auto input = std::istringstream{{response_bytes_.begin(), response_bytes_.end()}, std::ios::binary};
    input.seekg(static_cast<std::streamoff>(message_byte_offsets::ANSWERS));
    auto expected = dns_answer<qtype::MX>{};
    input >> expected;
    ASSERT_EQ(answer_, expected);
}

TEST_F(dns_test, response_deserialization) {
    auto input = std::istringstream{{response_bytes_.begin(), response_bytes_.end()}, std::ios::binary};
    auto actual = dns_response<qtype::MX>{};
    input >> actual;
    ASSERT_NO_THROW({ actual; });
}
