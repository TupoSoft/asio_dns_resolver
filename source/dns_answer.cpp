#include "dns_answer.hpp"
#include "qclass.hpp"

#include <utility>

using namespace tuposoft::asio::dns;

namespace {
    auto rdata_end(std::istream &input, const std::uint16_t length) -> std::streampos {
        const auto start = input.tellg();
        if (start == std::streampos{-1} || !input.seekg(0, std::ios::end)) {
            throw std::runtime_error("DNS parsing requires a seekable message");
        }

        if (const auto message_end = input.tellg();
            !input.seekg(start) || message_end == std::streampos{-1} || length > message_end - start) {
            throw std::runtime_error("Truncated DNS RDATA");
        }

        return start + static_cast<std::streamoff>(length);
    }

    auto read_bytes(std::istream &input, char *buffer, const std::streamsize length, const std::streampos end)
            -> void {
        require_dns_bytes(input, length, end);
        if (length != 0 && !input.read(buffer, length)) {
            throw std::runtime_error("Truncated DNS RDATA");
        }
    }

    template<typename Address>
    auto read_address(std::istream &input, const std::uint16_t length, const std::streampos end) -> std::string {
        auto bytes = typename Address::bytes_type{};
        if (length != bytes.size()) {
            throw std::runtime_error("Invalid DNS address RDATA length");
        }

        for (auto &byte: bytes) {
            byte = read_big_endian<std::uint8_t>(input, end);
        }
        return Address{bytes}.to_string();
    }
} // namespace

auto tuposoft::asio::dns::parse_rdata(std::istream &input, const qtype type, const std::uint16_t cls,
                                    const std::uint16_t rdlength) -> rdata_value {
    const auto end = rdata_end(input, rdlength);
    const auto decode = [&] -> rdata_value {
        if (cls == std::to_underlying(qclass::INET)) {
            switch (type) {
                case qtype::A:
                    return read_address<boost::asio::ip::address_v4>(input, rdlength, end);
                case qtype::AAAA:
                    return read_address<boost::asio::ip::address_v6>(input, rdlength, end);
                case qtype::CNAME:
                case qtype::NS:
                case qtype::PTR:
                    return from_dns_label_format(input, end);
                case qtype::MX:
                    return mx_rdata{
                            .preference = read_big_endian<std::uint16_t>(input, end),
                            .mx = from_dns_label_format(input, end),
                    };
                case qtype::SOA:
                    return soa_rdata{
                            .mname = from_dns_label_format(input, end),
                            .rname = from_dns_label_format(input, end),
                            .serial = read_big_endian<std::uint32_t>(input, end),
                            .refresh = read_big_endian<std::uint32_t>(input, end),
                            .retry = read_big_endian<std::uint32_t>(input, end),
                            .expire = read_big_endian<std::uint32_t>(input, end),
                            .minimum = read_big_endian<std::uint32_t>(input, end),
                    };
                case qtype::TXT: {
                    if (rdlength == 0) {
                        throw std::runtime_error("Empty DNS TXT RDATA");
                    }

                    auto text = std::string{};
                    while (input.tellg() < end) {
                        const auto length = read_big_endian<std::uint8_t>(input, end);
                        auto part = std::string(length, '\0');
                        read_bytes(input, part.data(), length, end);
                        text += part;
                    }
                    return text;
                }
                default:
                    break;
            }
        }

        auto bytes = std::vector<std::uint8_t>(rdlength);
        for (auto &byte: bytes) {
            byte = read_big_endian<std::uint8_t>(input, end);
        }

        return bytes;
    };

    auto result = decode();
    if (input.tellg() != end) {
        throw std::runtime_error("DNS RDATA length does not match decoded data");
    }

    return result;
}

auto tuposoft::asio::dns::operator>>(std::istream &input, dns_answer &answer) -> std::istream & {
    auto parsed = dns_answer{};

    parsed.name = from_dns_label_format(input);
    parsed.type = static_cast<qtype>(read_big_endian<std::uint16_t>(input));
    parsed.cls = read_big_endian<std::uint16_t>(input);
    parsed.ttl = read_big_endian<std::uint32_t>(input);
    parsed.rdlength = read_big_endian<std::uint16_t>(input);
    parsed.rdata = parse_rdata(input, parsed.type, parsed.cls, parsed.rdlength);
    answer = std::move(parsed);

    return input;
}
