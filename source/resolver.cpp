#include "resolver.hpp"
#include "udp_dns_transport.hpp"

#include <random>

using namespace tuposoft::asio::dns;

auto resolver::generate_id() -> decltype(generate_id()) {
    static std::random_device rand;
    static std::mt19937 gen(rand());
    return std::uniform_int_distribution<std::uint16_t>(0, std::numeric_limits<std::uint16_t>::max())(gen);
}

resolver::resolver(const asio::any_io_executor &executor) : resolver(create_udp_dns_transport(executor)) {}
