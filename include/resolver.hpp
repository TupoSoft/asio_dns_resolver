#pragma once

#include "boost/asio/buffer.hpp"
#include "dns_query.hpp"
#include "dns_response.hpp"
#include "qtype.hpp"

#include "dns_transport.hpp"

#include <fmt/format.h>

#include <array>
#include <cstddef>
#include <memory>
#include <ranges>
#include <sstream>
#include <string>
#include <vector>

namespace tuposoft::asio::dns {
    namespace asio = boost::asio;
    class resolver {
    public:
        explicit resolver(const asio::any_io_executor &executor);
        explicit resolver(std::shared_ptr<dns_transport> transport) : transport_(std::move(transport)) {}

        auto connect(std::string server) const -> asio::awaitable<void>;

        template<qtype T>
        auto query(const std::string domain) -> asio::awaitable<std::vector<dns_answer>> {
            static constexpr auto timeout_seconds = std::chrono::seconds(3);
            static constexpr auto input_buffer_size = 2048;
            static constexpr auto max_retry_count = 10;

            const auto query = create_query<T>(domain);
            auto buf = asio::streambuf{};
            auto out = std::ostream{&buf};
            out << query;

            auto outgoing = std::vector<std::byte>(buf.size());
            asio::buffer_copy(asio::buffer(outgoing), buf.data());

            auto input = std::array<std::byte, input_buffer_size>{};
            auto curr_retry_count = 0;
            while (curr_retry_count++ < max_retry_count) {
                co_await transport_->send(outgoing);

                auto [error_code, received] = co_await transport_->receive(
                        input, std::chrono::duration_cast<std::chrono::milliseconds>(timeout_seconds));

                if (error_code == asio::error::timed_out) {
                    continue;
                }

                if (error_code) {
                    throw std::runtime_error(fmt::format("UDP receive failed: {}", error_code.message()));
                }

                auto response = dns_response{};

                auto chars =
                        input | std::views::take(received) | std::views::transform([](const std::byte byte) -> auto {
                            return static_cast<char>(std::to_integer<unsigned char>(byte));
                        });

                auto instream = std::istringstream{std::string{chars.begin(), chars.end()}, std::ios::binary};
                instream >> response;

                if (!response_matches_query(response, query)) {
                    throw std::runtime_error("Query-Response Mismatch. See RFC5452 #9.1");
                }

                co_return response.answers;
            }

            throw std::runtime_error(fmt::format("Timeout while waiting for UDP response"));
        }

    private:
        static auto response_matches_query(const dns_response& response, const dns_query& query) -> bool;

        static auto generate_id() -> std::uint16_t;

        template<qtype T>
        auto create_query(const std::string &name) {
            return dns_query{
                    .header =
                            {
                                    .id = generate_id(),
                                    .rd = 0x01,
                                    .qdcount = 0x01,
                            },
                    .question =
                            {
                                    .qname = name,
                                    .type = T,
                                    .cls = qclass::INET,
                            },
            };
        }

        static auto reverse_qname(const std::string &name) -> std::string;

        std::shared_ptr<dns_transport> transport_;
    };

    template<>
    inline auto resolver::create_query<qtype::PTR>(const std::string &name) {
        static constexpr auto REVERSE_LOOKUP_DOMAIN = "in-addr.arpa";

        const auto qname = reverse_qname(name) + REVERSE_LOOKUP_DOMAIN;

        return dns_query{
                .header =
                        {
                                .id = generate_id(),
                                .rd = 0x01,
                                .qdcount = 0x01,
                        },
                .question =
                        {
                                .qname = qname,
                                .type = qtype::PTR,
                                .cls = qclass::INET,
                        },
        };
    }
} // namespace tuposoft::asio::dns
