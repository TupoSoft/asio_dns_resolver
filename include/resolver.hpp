#pragma once

#include "dns_query.hpp"
#include "dns_response.hpp"
#include "qtype.hpp"

#include "dns_transport.hpp"

#include <fmt/format.h>

#include <memory>
#include <ranges>
#include <string>
#include <vector>

namespace tuposoft::asio::dns {
    namespace asio = boost::asio;

    struct query_params {
        std::string name;
        std::string type;
    };

    class resolver {
    public:
        using id_generator = std::function<std::uint16_t()>;

        explicit resolver(const asio::any_io_executor &executor);
        explicit resolver(std::shared_ptr<dns_transport> transport, id_generator generator = &resolver::generate_id) :
            transport_(std::move(transport)), generate_id_(std::move(generator)) {}

        auto connect(std::string) const -> asio::awaitable<void>;

        auto query(query_params) const -> asio::awaitable<std::vector<dns_answer>>;

        template<qtype T>
        auto query(const std::string domain) -> asio::awaitable<std::vector<dns_answer>> {
            const auto query = create_query<T>(domain);
            co_return co_await exchange_with_retries(query);
        }

    private:
        static constexpr auto timeout_seconds = std::chrono::seconds(3);
        static constexpr auto input_buffer_size = 2048;
        static constexpr auto max_retry_count = 10;

        static auto response_matches_query(const dns_response &response, const dns_query &query) -> bool;

        static auto generate_id() -> std::uint16_t;

        static constexpr auto parse_query_type(std::string_view) -> std::optional<qtype>;

        [[nodiscard]] auto create_query(const query_params &) const -> dns_query;

        template<qtype T>
        auto create_query(const std::string &name) {
            return dns_query{
                    .header =
                            {
                                    .id = generate_id_(),
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

        auto exchange_with_retries(dns_query) const -> asio::awaitable<std::vector<dns_answer>>;

        static auto reverse_qname(const std::string &name) -> std::string;

        std::shared_ptr<dns_transport> transport_;

        id_generator generate_id_;
    };

    template<>
    inline auto resolver::create_query<qtype::PTR>(const std::string &name) {
        static constexpr auto REVERSE_LOOKUP_DOMAIN = "in-addr.arpa";

        const auto qname = reverse_qname(name) + REVERSE_LOOKUP_DOMAIN;

        return dns_query{
                .header =
                        {
                                .id = generate_id_(),
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
