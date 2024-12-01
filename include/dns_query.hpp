#pragma once

#include "common.hpp"
#include "dns_header.hpp"
#include "dns_question.hpp"

namespace tuposoft::asio::dns {
    struct dns_query {
        dns_header header;
        dns_question question;
    };

    auto tie_dns_query(const dns_query &);

    auto operator==(const dns_query &, const dns_query &) -> bool;

    auto operator<<(std::ostream &output, const dns_query &request) -> decltype(output);

    auto operator>>(std::istream &input, dns_query &request) -> decltype(input);
} // namespace tuposoft
