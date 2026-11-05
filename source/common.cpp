#include "common.hpp"

#include <ranges>
#include <stdexcept>
#include <unordered_set>

namespace {
    auto calculate_new_position(std::istream &input, const std::uint16_t next_byte,
                                const std::optional<std::streampos> &end) -> std::uint16_t {
        tuposoft::asio::dns::require_dns_bytes(input, 1, end);
        const auto low_byte = input.get();

        if (low_byte == std::char_traits<char>::eof()) {
            throw std::runtime_error("Truncated DNS compression pointer");
        }

        const auto low = static_cast<unsigned>(low_byte);
        const auto high = static_cast<unsigned>(next_byte);

        return static_cast<std::uint16_t>(
                (high & tuposoft::asio::dns::LOWER_SIX_BITS_MASK) << tuposoft::asio::dns::BYTE_SIZE | low);
    }

    auto read_label_from_stream(std::istream &input, const std::uint8_t len, const std::optional<std::streampos> end)
            -> std::string {
        tuposoft::asio::dns::require_dns_bytes(input, len, end);
        std::vector<char> buffer(len);

        if (!input.read(buffer.data(), len)) {
            throw std::runtime_error("Truncated DNS label");
        }

        return std::string{buffer.begin(), buffer.end()} + '.';
    }
} // namespace

using namespace tuposoft::asio::dns;

auto tuposoft::asio::dns::to_dns_label_format(const std::string &domain) -> std::vector<std::uint8_t> {
    auto label_format = std::vector<std::uint8_t>{};
    auto start = std::size_t{};

    for (auto end = std::size_t{}; (end = domain.find('.', start)) != std::string::npos; start = end + 1) {
        auto length = static_cast<std::uint8_t>(end - start);
        label_format.push_back(length);
        label_format.insert(label_format.end(), domain.begin() + static_cast<std::string::difference_type>(start),
                            domain.begin() + static_cast<std::string::difference_type>(end));
    }

    if ((static_cast<unsigned>(domain.at(0)) & UPPER_TWO_BITS_MASK) == UPPER_TWO_BITS_MASK) {
        label_format.insert(label_format.end(), domain.begin() + static_cast<std::string::difference_type>(start),
                            domain.end());
    } else {
        // Last label
        const auto length = static_cast<std::uint8_t>(domain.size() - start);
        label_format.push_back(length);
        label_format.insert(label_format.end(), domain.begin() + static_cast<std::string::difference_type>(start),
                            domain.end());
        // Null terminator for the qname
        label_format.push_back(0);
    }

    return label_format;
}

auto tuposoft::asio::dns::require_dns_bytes(std::istream &input, const std::streamsize count,
                                            const std::optional<std::streampos> &end) -> void {
    if (end) {
        if (const auto position = input.tellg();
            position == std::streampos{-1} || position > *end || count > *end - position) {
            throw std::runtime_error("DNS data exceeds RDATA boundary");
        }
    }
}

auto tuposoft::asio::dns::from_dns_label_format(std::istream &input, std::optional<std::streampos> end) -> std::string {
    auto result = std::string{};
    auto first_ptr_pos = std::optional<std::streampos>{};
    auto visited_pointer_targets = std::unordered_set<std::uint16_t>{};

    while (true) {
        require_dns_bytes(input, 1, end);
        const auto next_byte = input.get();
        if (next_byte == std::char_traits<char>::eof()) {
            throw std::runtime_error("Unexpected end of DNS name");
        }
        if (next_byte == 0) {
            break;
        }

        if (const auto next_byte_u = static_cast<std::uint8_t>(next_byte); (next_byte_u & UPPER_TWO_BITS_MASK) == 0) {
            result += read_label_from_stream(input, next_byte_u, end);
        } else if ((next_byte_u & UPPER_TWO_BITS_MASK) == UPPER_TWO_BITS_MASK) {
            const auto next_pos = calculate_new_position(input, next_byte_u, end);

            if (!visited_pointer_targets.insert(next_pos).second) {
                throw std::runtime_error("DNS compression pointer cycle");
            }

            if (!first_ptr_pos) {
                first_ptr_pos = input.tellg();
                // Only the pointer's encoded bytes belong to this RDATA field.
                end.reset();
            }

            if (!input.seekg(next_pos)) {
                throw std::runtime_error("Invalid DNS compression pointer target");
            }
        } else {
            throw std::runtime_error("Invalid DNS label type");
        }
    }

    if (first_ptr_pos && !input.seekg(*first_ptr_pos)) {
        throw std::runtime_error("Invalid DNS name continuation");
    }

    if (!result.empty()) {
        result.pop_back();
    }

    return result;
}
