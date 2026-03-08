#pragma once

#include "boost/asio/buffer.hpp"
#include "dns_query.hpp"
#include "dns_response.hpp"
#include "qtype.hpp"

#include "dns_transport.hpp"

#include <fmt/core.h>

#include <array>
#include <cstddef>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace tuposoft::asio::dns {
    namespace asio = boost::asio;
    class resolver {
    public:
        explicit resolver(const asio::any_io_executor &executor);
        explicit resolver(std::shared_ptr<dns_transport> transport) : transport_(std::move(transport)) {}

        auto connect(const std::string server) const -> asio::awaitable<void> {
            constexpr auto DNS_PORT = 53;
            co_await transport_->connect({asio::ip::address::from_string(server), DNS_PORT});
        }

        template<qtype T>
        auto query(const std::string domain) -> asio::awaitable<std::vector<dns_answer<T>>> {
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
            while (curr_retry_count < max_retry_count) {
                co_await transport_->send(outgoing);
                ++curr_retry_count;
                auto [error_code, received] = co_await transport_->receive(
                        input, std::chrono::duration_cast<std::chrono::milliseconds>(timeout_seconds));

                if (error_code == asio::error::timed_out) {
                    continue;
                }

                if (error_code) {
                    throw std::runtime_error(fmt::format("UDP receive failed: {}", error_code.message()));
                }

                auto dns_response = tuposoft::asio::dns::dns_response<T>{};
                auto instream =
                        std::istringstream{std::string({input.begin(), input.end()}, received), std::ios::binary};
                instream >> dns_response;
                co_return dns_response.answers;
            }

            throw std::runtime_error(fmt::format("Timeout while waiting for UDP response"));
        }

    private:
        static auto generate_id() -> std::uint16_t;

        template<qtype T>
        auto create_query(const std::string &name) {
            return dns_query{.header =
                                     {
                                             .id = generate_id(),
                                             .rd = 0x01,
                                             .qdcount = 0x01,
                                     },
                             .question = {
                                     .qname = name,
                                     .type = T,
                                     .cls = qclass::INET,
                             }};
        }

        static auto reverse_qname(const std::string &name) -> std::string {
            auto iss = std::istringstream{name};
            auto segment = std::string{};
            auto segments = std::vector<std::string>{};

            while (std::getline(iss, segment, '.')) {
                segments.push_back(segment);
            }

            std::ranges::reverse(segments);

            auto reversed_ip = std::string{};
            for (const auto &seg: segments) {
                reversed_ip += seg + '.';
            }

            return reversed_ip;
        }

        std::shared_ptr<dns_transport> transport_;
    };

    template<>
    inline auto resolver::create_query<qtype::PTR>(const std::string &name) {
        const auto qname = reverse_qname(name) + "in-addr.arpa";
        return dns_query{.header =
                                 {
                                         .id = generate_id(),
                                         .rd = 0x01,
                                         .qdcount = 0x01,
                                 },
                         .question = {
                                 .qname = qname,
                                 .type = qtype::PTR,
                                 .cls = qclass::INET,
                         }};
    }
} // namespace tuposoft::asio::dns
