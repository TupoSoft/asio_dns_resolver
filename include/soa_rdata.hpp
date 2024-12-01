#pragma once

#include <string>
#include <cstdint>

namespace tuposoft::asio::dns {
    struct soa_rdata {
        std::string mname;
        std::string rname;
        std::uint32_t serial;
        std::uint32_t refresh;
        std::uint32_t retry;
        std::uint32_t expire;
        std::uint32_t minimum;
    };

    auto tie_soa_rdata(const soa_rdata &);

    auto operator==(const soa_rdata &, const soa_rdata &) -> bool;
}; // namespace tuposoft
