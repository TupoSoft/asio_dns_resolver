#pragma once

#include "boost/asio/steady_timer.hpp"
#include "dns_query.hpp"
#include "dns_response.hpp"
#include "qtype.hpp"

#include "boost/asio/experimental/as_tuple.hpp"
#include "boost/asio/experimental/awaitable_operators.hpp"
#include "boost/asio/experimental/parallel_group.hpp"
#include "boost/asio/use_awaitable.hpp"

#include <fmt/core.h>

#include <sstream>

namespace tuposoft::asio::dns {
    namespace asio = boost::asio;
    class resolver {
    private:
        static constexpr auto use_nothrow_awaitable = as_tuple(asio::use_awaitable);
        static auto timeout(std::chrono::seconds timeout_duration_s) -> asio::awaitable<void> {
            auto timer = asio::steady_timer{co_await asio::this_coro::executor};
            timer.expires_after(timeout_duration_s);
            co_await timer.async_wait(use_nothrow_awaitable);
        }

    public:
        explicit resolver(const asio::any_io_executor &executor) : socket_(executor) {}

        auto connect(const std::string server) -> asio::awaitable<void> {
            constexpr auto DNS_PORT = 53;
            co_await socket_.async_connect({asio::ip::address::from_string(server), DNS_PORT}, asio::use_awaitable);
        }

        template<qtype T>
        auto query(const std::string domain) -> asio::awaitable<std::vector<dns_answer<T>>> {
            using namespace boost::asio::experimental::awaitable_operators;
            static constexpr auto timeout_seconds = std::chrono::seconds(3);
            static constexpr auto input_buffer_size = 2048;
            static constexpr auto max_retry_count = 10;
            const auto query = create_query<T>(domain);
            auto buf = asio::streambuf{};
            auto out = std::ostream{&buf};
            out << query;

            auto input = std::array<char, input_buffer_size>{};
            auto curr_retry_count = 0;
            while (curr_retry_count < max_retry_count) {
                co_await socket_.async_send(buffer(buf.data(), buf.size()), asio::use_awaitable);
                ++curr_retry_count;
                auto result = co_await ((socket_.async_receive(asio::buffer(input), use_nothrow_awaitable)) or
                                        timeout(timeout_seconds));

                if (result.index() == 0) {
                    auto dns_response = tuposoft::asio::dns::dns_response<T>{};
                    auto instream = std::istringstream{{input.begin(), input.end()}, std::ios::binary};
                    instream >> dns_response;
                    co_return dns_response.answers;
                }
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

        asio::ip::udp::socket socket_;
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
