#pragma once

#include "dns_transport.hpp"

#include <memory>

namespace tuposoft::asio::dns {
    auto create_udp_dns_transport(const asio::any_io_executor &executor) -> std::shared_ptr<dns_transport>;
} // namespace tuposoft::asio::dns
