#pragma once

#include "dns_transport.hpp"
#include "gmock/gmock-function-mocker.h"

namespace tuposoft::asio::dns {
    class mock_dns_transport final : public dns_transport {
    public:
        MOCK_METHOD(asio::awaitable<void>, connect, (asio::ip::udp::endpoint), (override));

        MOCK_METHOD(asio::awaitable<void>, send, (std::span<const std::byte>), (override));

        MOCK_METHOD((asio::awaitable<std::pair<boost::system::error_code, std::size_t>>), receive,
                    (std::span<std::byte>, std::chrono::milliseconds), (override));
    };
} // namespace tuposoft::asio::dns