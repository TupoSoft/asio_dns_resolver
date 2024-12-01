#include "dns_header.hpp"

#include <boost/asio.hpp>

constexpr unsigned SINGLE_BIT_MASK = 1U;
constexpr unsigned OPCODE_MASK = 0xFU;
constexpr unsigned RCODE_MASK = 0xFU;

namespace tuposoft::asio::dns {
    auto header_flags_to_short(const dns_header &header) -> std::uint16_t {
        return header.rd << RD_POSITION | header.tc << TC_POSITION | header.aa << AA_POSITION |
               header.opcode << OPCODE_POSITION | header.qr << QR_POSITION | header.rcode << RCODE_POSITION |
               header.cd << CD_POSITION | header.ad << AD_POSITION | header.z << Z_POSITION | header.ra << RA_POSITION;
    }

    auto tie_dns_header(const dns_header &header) {
        return std::tie(header.id, *std::make_unique<std::uint16_t>(header_flags_to_short(header)), header.qdcount,
                        header.ancount, header.nscount, header.arcount);
    }

    auto operator==(const dns_header &first, const dns_header &second) -> bool {
        return tie_dns_header(first) == tie_dns_header(second);
    }

    auto operator>>(std::istream &input, dns_header &header) -> decltype(input) {
        header.id = read_big_endian(input);
        const unsigned short flags = read_big_endian(input);

        header.rd = flags >> RD_POSITION & SINGLE_BIT_MASK;
        header.tc = flags >> TC_POSITION & SINGLE_BIT_MASK;
        header.aa = flags >> AA_POSITION & SINGLE_BIT_MASK;
        header.opcode = flags >> OPCODE_POSITION & OPCODE_MASK;
        header.qr = flags >> QR_POSITION & SINGLE_BIT_MASK;
        header.rcode = flags & RCODE_MASK;
        header.cd = flags >> CD_POSITION & SINGLE_BIT_MASK;
        header.ad = flags >> AD_POSITION & SINGLE_BIT_MASK;
        header.z = flags >> Z_POSITION & SINGLE_BIT_MASK;
        header.ra = flags >> RA_POSITION & SINGLE_BIT_MASK;

        header.qdcount = read_big_endian(input);
        header.ancount = read_big_endian(input);
        header.nscount = read_big_endian(input);
        header.arcount = read_big_endian(input);

        return input;
    }

    auto operator<<(std::ostream &output, const dns_header &header) -> decltype(output) {
        const auto flags = header_flags_to_short(header);

        write_big_endian(output, header.id);
        write_big_endian(output, flags);
        write_big_endian(output, header.qdcount);
        write_big_endian(output, header.ancount);
        write_big_endian(output, header.nscount);
        write_big_endian(output, header.arcount);

        return output;
    }
} // namespace tuposoft
