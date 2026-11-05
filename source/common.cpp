#include "common.hpp"

#include <ranges>
#include <stdexcept>
#include <unordered_set>

namespace {
    auto calculate_new_position(std::istream &input, const std::uint16_t next_byte) -> std::uint16_t {
        const auto low_byte = input.get();
        if (low_byte == std::char_traits<char>::eof()) {
            throw std::runtime_error("Truncated DNS compression pointer");
        }

        return (next_byte & tuposoft::asio::dns::LOWER_SIX_BITS_MASK) << tuposoft::asio::dns::BYTE_SIZE |
               static_cast<std::uint8_t>(low_byte);
    }

    auto read_label_from_stream(std::istream &input, const std::uint8_t len) -> std::string {
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

auto tuposoft::asio::dns::from_dns_label_format(std::istream &input) -> std::string {
    auto result = std::string{};
    constexpr auto UNSET_PTR_POS = -1;
    auto first_ptr_pos{UNSET_PTR_POS};
    auto visited_pointer_targets = std::unordered_set<std::uint16_t>{};

    for (auto next_byte = input.get(); next_byte != 0; next_byte = input.get()) {
        if (next_byte == std::char_traits<char>::eof()) {
            throw std::runtime_error("Unexpected end of DNS name");
        }

        if ((next_byte & UPPER_TWO_BITS_MASK) != UPPER_TWO_BITS_MASK) {
            result += read_label_from_stream(input, static_cast<std::uint8_t>(next_byte));
        } else {
            const auto next_pos = calculate_new_position(input, next_byte);

            if (!visited_pointer_targets.insert(next_pos).second) {
                throw std::runtime_error("DNS compression pointer cycle");
            }

            if (first_ptr_pos == UNSET_PTR_POS) {
                first_ptr_pos = static_cast<int>(input.tellg());
            }

            if (!input.seekg(next_pos)) {
                throw std::runtime_error("Invalid DNS compression pointer target");
            }
        }
    }

    if (first_ptr_pos != UNSET_PTR_POS) {
        input.seekg(first_ptr_pos);
    }

    if (!result.empty()) {
        result.pop_back();
    }

    return result;
}
