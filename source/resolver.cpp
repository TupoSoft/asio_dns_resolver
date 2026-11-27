#include "resolver.hpp"
#include "udp_dns_transport.hpp"

#include <random>

using namespace tuposoft::asio::dns;

auto resolver::connect(const std::string server) const -> asio::awaitable<void> {
    constexpr auto DNS_PORT = 53;
    co_await transport_->connect({asio::ip::address::from_string(server), DNS_PORT});
}

auto resolver::query(const query_params params) const -> asio::awaitable<std::vector<dns_answer>> {
    const auto &[name, type] = params;
    const auto query = create_query(params);
    co_return co_await exchange_with_retries(query);
}

auto resolver::response_matches_query(const dns_response &response, const dns_query &query) -> bool {
    return response.header.id == query.header.id && response.question == query.question;
}

auto resolver::generate_id() -> decltype(generate_id()) {
    static std::random_device rand;
    static std::mt19937 gen(rand());
    return std::uniform_int_distribution<std::uint16_t>(0, std::numeric_limits<std::uint16_t>::max())(gen);
}

constexpr auto resolver::parse_query_type(const std::string_view value) -> std::optional<qtype> {
    constexpr auto mapping = std::to_array<std::pair<std::string_view, qtype>>({
            {"A", qtype::A},
            {"AAAA", qtype::AAAA},
            {"CNAME", qtype::CNAME},
            {"DNSKEY", qtype::DNSKEY},
            {"DS", qtype::DS},
            {"MX", qtype::MX},
            {"NS", qtype::NS},
            {"NSEC", qtype::NSEC},
            {"PTR", qtype::PTR},
            {"RRSIG", qtype::RRSIG},
            {"SOA", qtype::SOA},
            {"SRV", qtype::SRV},
            {"TXT", qtype::TXT},
    });

    for (const auto &[name, type]: mapping) {
        if (name == value) {
            return type;
        }
    }

    return std::nullopt;
}

auto resolver::create_query(const query_params &params) const -> dns_query {
    const auto &[name, type] = params;

    const auto parsed_type = parse_query_type(type);
    if (!parsed_type) {
        throw std::invalid_argument{"Unsupported DNS record type"};
    }

    return {
            .header =
                    {
                            .id = generate_id_(),
                            .rd = 0x01,
                            .qdcount = 0x01,
                    },
            .question =
                    {
                            .qname = name,
                            .type = *parsed_type,
                            .cls = qclass::INET,
                    },
    };
}

auto resolver::exchange_with_retries(dns_query query) const -> asio::awaitable<std::vector<dns_answer>> {
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

        auto chars = input | std::views::take(received) | std::views::transform([](const std::byte byte) -> auto {
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
