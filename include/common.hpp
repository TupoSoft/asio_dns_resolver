#pragma once

#include <boost/asio.hpp>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace tuposoft::asio::dns {
    constexpr auto BYTE_SIZE = static_cast<std::uint8_t>(0x08);
    constexpr auto FULL_BYTE = static_cast<std::uint8_t>(0xFF);
    constexpr auto UPPER_TWO_BITS_MASK = static_cast<std::uint8_t>(0xC0);
    constexpr auto LOWER_SIX_BITS_MASK = static_cast<std::uint8_t>(0x3F);

    auto to_dns_label_format(const std::string &domain) -> std::vector<std::uint8_t>;

    // The bound limits bytes at the encoded location; compression targets use the full message.
    auto from_dns_label_format(std::istream &input, std::optional<std::streampos> end = std::nullopt) -> std::string;

    auto require_dns_bytes(std::istream &input, std::streamsize count,
                           std::optional<std::streampos> end = std::nullopt) -> void;

    template<typename T = std::uint16_t>
    auto read_big_endian(std::istream &input, std::optional<std::streampos> end = std::nullopt) -> T {
        require_dns_bytes(input, sizeof(T), end);

        T result{};
        for (int i = 0; i < sizeof(T); ++i) {
            const auto byte = input.get();
            if (byte == std::char_traits<char>::eof()) {
                throw std::runtime_error("Truncated DNS integer");
            }

            result <<= BYTE_SIZE;
            result |= static_cast<T>(byte) & FULL_BYTE;
        }
        return result;
    }

    template<typename T = std::uint16_t>
    auto write_big_endian(std::ostream &output, T val) -> decltype(output) {
        std::array<char, sizeof(val)> buffer{};
        const auto val_be = htons(val);
        std::memcpy(buffer.data(), &val_be, sizeof(val));
        output.write(buffer.data(), buffer.size());
        return output;
    }

    enum struct message_byte_offsets : std::uint8_t {
        HEADER = 0,
        ANCOUNT = 6,
        QUESTION = 12,
        ANSWERS = 30,
    };
} // namespace tuposoft::asio::dns
