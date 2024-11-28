#include "dns_query.hpp"

#include <tuple>

namespace tuposoft::asio::dns {
    auto tie_dns_query(const dns_query &query) { return std::tie(query.header, query.question); }

    auto operator==(const dns_query &first, const dns_query &second) -> bool {
        return tie_dns_query(first) == tie_dns_query(second);
    }

    auto operator<<(std::ostream &output, const dns_query &request) -> decltype(output) {
        return output << request.header << request.question;
    }

    auto operator>>(std::istream &input, dns_query &request) -> decltype(input) {
        input >> request.header;
        input >> request.question;
        return input;
    }
} // namespace tuposoft
