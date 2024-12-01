#pragma once

#include "qclass.hpp"
#include "qtype.hpp"

#include <string>
#include <iostream>

namespace tuposoft::asio::dns {
    struct dns_question {
        std::string qname;
        qtype type;
        qclass cls{qclass::INET};
    };

    auto operator==(const dns_question &, const dns_question &) -> bool;

    auto tie_dns_question(const dns_question &question);

    // Overload << operator to write data to stream
    auto operator<<(std::ostream &output, const dns_question &question) -> decltype(output);

    // Overload >> operator to read data from stream
    auto operator>>(std::istream &input, dns_question &question) -> decltype(input);
} // namespace tuposoft
