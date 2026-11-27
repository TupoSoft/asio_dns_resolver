#include "resolver.hpp"

#include "boost/beast.hpp"

#include <sstream>

#include "boost/url/parse.hpp"
#include "boost/url/url.hpp"

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace dns = tuposoft::asio::dns;

namespace {
    using request_type = http::request<http::string_body>;
    using response_type = http::response<http::string_body>;

    constexpr auto SERVER = "TupoSoft ASIO DNS Resolver Example";
    constexpr auto CONTENT_TYPE = "text/plain";

    auto text_response(const request_type &request, const http::status status, std::string body) -> response_type {
        auto response = response_type{status, request.version()};
        response.set(http::field::server, SERVER);
        response.set(http::field::content_type, CONTENT_TYPE);
        response.keep_alive(false);

        if (request.method() != http::verb::head) {
            response.body() = std::move(body);
            response.prepare_payload();
        }

        return response;
    }

    auto resolve_request(request_type request, std::shared_ptr<dns::resolver> resolver)
            -> asio::awaitable<response_type> {
        if (request.method() != http::verb::get) {
            co_return text_response(request, http::status::method_not_allowed, "Use GET");
        }

        auto const url = boost::urls::parse_origin_form(request.target());

        if (url->encoded_path() != "/resolve") {
            co_return text_response(request, http::status::not_found, "Unknown path");
        }

        auto const params = url->params();
        if (params.count("name") != 1 || params.count("type") != 1) {
            co_return text_response(request, http::status::bad_request, "Expected one name and one type");
        }

        auto domain = *params.find("name");
        auto type = *params.find("type");

        if (domain.value.empty() || type.value.empty()) {
            co_return text_response(request, http::status::bad_request, "Name and type must be nonempty");
        }

        auto const answers = co_await resolver->query({.name = std::move(domain.value), .type = std::move(type.value)});

        auto output = std::ostringstream{};
        for (const auto &[name, qtype, cls, ttl, rdlength, rdata]: answers) {
            output << std::format("{} type={} class={} ttl={}", name, std::to_underlying(qtype), cls, ttl) << '\n';
        }

        co_return text_response(request, http::status::ok, output.str());
    }

    auto handle_session(asio::ip::tcp::socket socket, const std::shared_ptr<dns::resolver> resolver)
            -> asio::awaitable<void> {
        try {
            auto buffer = beast::flat_buffer{};
            auto request = http::request<http::string_body>{};
            co_await http::async_read(socket, buffer, request, asio::use_awaitable);

            const auto response = co_await resolve_request(request, resolver);

            co_await http::async_write(socket, response, asio::use_awaitable);

            socket.shutdown(asio::ip::tcp::socket::shutdown_send);
        } catch (std::exception &e) {
            std::cerr << "Error: " << e.what() << '\n';
        }
    }

    auto listener(asio::ip::tcp::acceptor acceptor) -> asio::awaitable<void> {
        const auto resolver = std::make_shared<dns::resolver>(acceptor.get_executor());
        co_await resolver->connect("1.1.1.1");

        for (;;) {
            auto socket = co_await acceptor.async_accept(asio::use_awaitable);
            co_spawn(acceptor.get_executor(), handle_session(std::move(socket), resolver), asio::detached);
        }
    }
} // namespace

auto main() -> int {
    constexpr auto PORT = 8080;

    auto io_context = asio::io_context{};
    auto acceptor = asio::ip::tcp::acceptor{io_context, {asio::ip::tcp::v4(), PORT}};
    co_spawn(io_context, listener(std::move(acceptor)), asio::detached);
    io_context.run();

    return {};
}
