#pragma once

#include "mx_rdata.hpp"
#include "qtype.hpp"
#include "soa_rdata.hpp"

#include <tuple>

namespace tuposoft::asio::dns {
    template<qtype>
    struct rdata {
        using type = std::string;
    };

    template<>
    struct rdata<qtype::MX> {
        using type = mx_rdata;
    };

    template<>
    struct rdata<qtype::SOA> {
        using type = soa_rdata;
    };

    template<qtype T>
    struct dns_answer {
        std::string name;
        qtype type{T};
        std::uint16_t cls{};
        std::uint32_t ttl{};
        std::uint16_t rdlength{};
        typename rdata<T>::type rdata;
    };

    template<qtype T>
    auto parse_rdata(std::istream &input) -> typename rdata<T>::type {
        return from_dns_label_format(input);
    }

    template<>
    auto parse_rdata<qtype::MX>(std::istream &input) -> rdata<qtype::MX>::type;

    template<>
    auto parse_rdata<qtype::A>(std::istream &input) -> rdata<qtype::A>::type;

    template<>
    auto parse_rdata<qtype::AAAA>(std::istream &input) -> rdata<qtype::AAAA>::type;

    template<>
    auto parse_rdata<qtype::SOA>(std::istream &input) -> rdata<qtype::SOA>::type;

    template<>
    auto parse_rdata<qtype::TXT>(std::istream &input) -> rdata<qtype::TXT>::type;

    template<qtype T>
    auto operator>>(std::istream &input, dns_answer<T> &answer) -> decltype(input) {
        answer.name = from_dns_label_format(input);
        answer.type = static_cast<qtype>(read_big_endian<std::uint16_t>(input));
        answer.cls = read_big_endian<std::uint16_t>(input);
        answer.ttl = read_big_endian<std::uint32_t>(input);
        answer.rdlength = read_big_endian<std::uint16_t>(input);
        answer.rdata = parse_rdata<T>(input);

        return input;
    };

    template<qtype T>
    auto tie_dns_answer(const dns_answer<T> &answer) {
        return std::tie(answer.name, answer.type, answer.cls, answer.ttl, answer.rdlength, answer.rdata);
    };

    template<qtype T>
    auto operator==(const dns_answer<T> &first, const dns_answer<T> &second) -> bool {
        return tie_dns_answer(first) == tie_dns_answer(second);
    };
} // namespace tuposoft
