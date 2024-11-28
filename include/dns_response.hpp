#pragma once

#include "dns_answer.hpp"
#include "dns_query.hpp"

#include <iostream>

namespace tuposoft::asio::dns {
    template<qtype T>
    struct dns_response : dns_query {
        std::vector<dns_answer<T>> answers;
    };

    template<qtype T>
    auto tie_dns_response(const dns_response<T> &response) {
        return std::tie(response.header, response.question, response.answers);
    }

    template<qtype T>
    auto operator==(const dns_response<T> &first, const dns_response<T> &second) -> bool {
        return tie_dns_response(first) == tie_dns_response(second);
    }

    template<qtype T>
    auto operator>>(std::istream &input, dns_response<T> &response) -> decltype(input) {
        input >> response.header;
        input >> response.question;

        const auto ancount = response.header.ancount;
        response.answers = std::vector<dns_answer<T>>(ancount);

        for (int i = 0; i < ancount; ++i) {
            auto answer = dns_answer<T>{};
            input >> answer;
            response.answers[i] = answer;
        }

        return input;
    }
} // namespace tuposoft
