#pragma once

#include <boost/asio.hpp>

#include <chrono>
#include <cstddef>
#include <span>
#include <utility>

namespace tuposoft::asio::dns {
    namespace asio = boost::asio;

    class dns_transport {
    public:
        dns_transport() = default;
        dns_transport(const dns_transport&) = default;
        dns_transport(dns_transport&&) = default;
        auto operator=(const dns_transport&) -> dns_transport& = default;
        auto operator=(dns_transport&&) -> dns_transport& = default;
        virtual ~dns_transport() = default;
        virtual auto connect(asio::ip::udp::endpoint) -> asio::awaitable<void> = 0;
        virtual auto send(std::span<const std::byte>) -> asio::awaitable<void> = 0;
        virtual auto receive(std::span<std::byte>, std::chrono::milliseconds)
                -> asio::awaitable<std::pair<boost::system::error_code, std::size_t>> = 0;
    };
} // namespace tuposoft::asio::dns
