#include "dns_answer.hpp"

using namespace tuposoft::asio::dns;

template<>
auto tuposoft::asio::dns::parse_rdata<qtype::MX>(std::istream &input) -> rdata<qtype::MX>::type {
    return {read_big_endian<std::uint16_t>(input), from_dns_label_format(input)};
}

template<>
auto tuposoft::asio::dns::parse_rdata<qtype::A>(std::istream &input) -> rdata<qtype::A>::type {
    constexpr auto IPV4_SIZE = 4;

    auto binary_ipv4 = std::array<char, IPV4_SIZE>{};
    input.read(binary_ipv4.data(), binary_ipv4.size());

    auto str_ipv4 = std::array<char, INET_ADDRSTRLEN>{};
    inet_ntop(AF_INET, binary_ipv4.data(), str_ipv4.data(), str_ipv4.size());

    return str_ipv4.data();
}

template<>
auto tuposoft::asio::dns::parse_rdata<qtype::AAAA>(std::istream &input) -> rdata<qtype::AAAA>::type {
    constexpr auto IPV6_SIZE = 16;

    auto binary_ipv6 = std::array<char, IPV6_SIZE>{};
    input.read(binary_ipv6.data(), binary_ipv6.size());

    auto str_ipv6 = std::array<char, INET6_ADDRSTRLEN>{};
    inet_ntop(AF_INET6, binary_ipv6.data(), str_ipv6.data(), str_ipv6.size());

    return str_ipv6.data();
}

template<>
auto tuposoft::asio::dns::parse_rdata<qtype::SOA>(std::istream &input) -> rdata<qtype::SOA>::type {
    return {
            from_dns_label_format(input),          from_dns_label_format(input),
            read_big_endian<std::uint32_t>(input), read_big_endian<std::uint32_t>(input),
            read_big_endian<std::uint32_t>(input), read_big_endian<std::uint32_t>(input),
            read_big_endian<std::uint32_t>(input),
    };
}

template<>
auto tuposoft::asio::dns::parse_rdata<qtype::TXT>(std::istream &input) -> rdata<qtype::TXT>::type {
    const auto txt_length = input.get();
    auto buffer = std::vector<char>(txt_length);
    input.read(buffer.data(), txt_length);
    return {buffer.begin(), buffer.end()};
}
