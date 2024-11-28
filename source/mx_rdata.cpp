#include "mx_rdata.hpp"

#include <tuple>

namespace tuposoft::asio::dns {
    auto tie_mx_rdata(const mx_rdata &rdata) { return std::tie(rdata.preference, rdata.mx); }

    auto operator==(const mx_rdata &first, const mx_rdata &second) -> bool {
        return tie_mx_rdata(first) == tie_mx_rdata(second);
    }
} // namespace tuposoft
