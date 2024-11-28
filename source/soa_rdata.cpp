#include "soa_rdata.hpp"
#include "common.hpp"

#include <tuple>

auto tuposoft::asio::dns::tie_soa_rdata(const soa_rdata &rdata) {
    return std::tie(rdata.mname, rdata.rname, rdata.serial, rdata.refresh, rdata.retry, rdata.expire, rdata.minimum);
}

auto tuposoft::asio::dns::operator==(const soa_rdata &lhs, const soa_rdata &rhs) -> bool {
    return tie_soa_rdata(lhs) == tie_soa_rdata(rhs);
}
