#include "resolver.hpp"
#include "udp_dns_transport.hpp"

#include <random>

using namespace tuposoft::asio::dns;

auto resolver::connect(const std::string server) const -> asio::awaitable<void> {
    constexpr auto DNS_PORT = 53;
    co_await transport_->connect({asio::ip::address::from_string(server), DNS_PORT});
}

auto resolver::response_matches_query(const dns_response &response, const dns_query &query) -> bool {
    return response.header.id == query.header.id && response.question == query.question;
}

auto resolver::generate_id() -> decltype(generate_id()) {
    static std::random_device rand;
    static std::mt19937 gen(rand());
    return std::uniform_int_distribution<std::uint16_t>(0, std::numeric_limits<std::uint16_t>::max())(gen);
}

auto resolver::reverse_qname(const std::string &name) -> std::string {
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

resolver::resolver(const asio::any_io_executor &executor) : resolver(create_udp_dns_transport(executor)) {}
