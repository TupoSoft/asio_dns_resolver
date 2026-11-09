#pragma once

#include "dns_answer.hpp"
#include "dns_query.hpp"

#include <utility>

namespace tuposoft::asio::dns {
    struct dns_response : dns_query {
        std::vector<dns_answer> answers;
    };

    inline auto tie_dns_response(const dns_response &response) {
        return std::tie(response.header, response.question, response.answers);
    }

    inline auto operator==(const dns_response &first, const dns_response &second) -> bool {
        return tie_dns_response(first) == tie_dns_response(second);
    }

    inline auto operator>>(std::istream &input, dns_response &response) -> decltype(input) {
        auto parsed = dns_response{};

        input >> parsed.header;
        input >> parsed.question;

        parsed.answers.reserve(parsed.header.ancount);

        for (std::uint16_t i = 0; i < parsed.header.ancount; ++i) {
            auto answer = dns_answer{};
            input >> answer;
            parsed.answers.push_back(std::move(answer));
        }

        response = std::move(parsed);
        return input;
    }
} // namespace tuposoft::asio::dns
