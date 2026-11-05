#pragma once

#include "mx_rdata.hpp"
#include "qtype.hpp"
#include "soa_rdata.hpp"

#include <tuple>
#include <variant>

namespace tuposoft::asio::dns {
    using rdata_value = std::variant<std::string, mx_rdata, soa_rdata, std::vector<std::uint8_t>>;

    struct dns_answer {
        std::string name;
        qtype type{};
        std::uint16_t cls{};
        std::uint32_t ttl{};
        std::uint16_t rdlength{};
        rdata_value rdata;
    };

    auto parse_rdata(std::istream &input, qtype type, std::uint16_t cls, std::uint16_t rdlength) -> rdata_value;

    auto operator>>(std::istream &input, dns_answer &answer) -> std::istream &;

    inline auto tie_dns_answer(const dns_answer &answer) {
        return std::tie(answer.name, answer.type, answer.cls, answer.ttl, answer.rdlength, answer.rdata);
    }

    inline auto operator==(const dns_answer &first, const dns_answer &second) -> bool {
        return tie_dns_answer(first) == tie_dns_answer(second);
    }
} // namespace tuposoft::asio::dns
