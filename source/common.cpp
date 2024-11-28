#include "common.hpp"

#include <ranges>

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

auto read_label_from_stream(std::istream &input, const std::uint8_t len) -> std::string {
    std::vector<char> buffer(len);
    input.read(buffer.data(), len);
    return std::string{buffer.begin(), buffer.end()} + '.';
}

auto calculate_new_position(std::istream &input, const std::uint16_t next_byte) -> std::uint16_t {
    return (next_byte & LOWER_SIX_BITS_MASK) << BYTE_SIZE | static_cast<std::uint8_t>(input.get());
}

auto tuposoft::asio::dns::from_dns_label_format(std::istream &input) -> std::string {
    auto result = std::string{};
    constexpr auto UNSET_PTR_POS = -1;
    auto first_ptr_pos{UNSET_PTR_POS};

    for (auto next_byte = static_cast<std::uint8_t>(input.get()); next_byte != 0; next_byte = input.get()) {
        if ((next_byte & UPPER_TWO_BITS_MASK) != UPPER_TWO_BITS_MASK) {
            result += read_label_from_stream(input, next_byte);
        } else {
            const auto next_pos = calculate_new_position(input, next_byte);

            if (first_ptr_pos == UNSET_PTR_POS) {
                first_ptr_pos = static_cast<int>(input.tellg());
            }

            input.seekg(next_pos);
        }
    }

    if (first_ptr_pos != UNSET_PTR_POS) {
        input.seekg(first_ptr_pos);
    }

    result.pop_back();

    return result;
}
