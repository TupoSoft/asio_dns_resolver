#include "resolver.hpp"

#include "boost/beast.hpp"

#include <sstream>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace dns = tuposoft::asio::dns;

auto handle_session(asio::ip::tcp::socket socket, std::shared_ptr<dns::resolver> resolver) -> asio::awaitable<void> {
    try {
        auto buffer = beast::flat_buffer{};
        auto request = http::request<http::string_body>{};
        co_await http::async_read(socket, buffer, request, asio::use_awaitable);

        if (request.method() == http::verb::get and request.target().starts_with("/resolve?")) {
            const auto params = request.target().substr(9);
            if (const auto pos = params.find("&"); pos != std::string::npos) {
                const auto domain = params.substr(0, pos);
                const auto query_type = params.substr(pos + 1);

                auto result = co_await resolver->query<dns::qtype::MX>(domain);

                auto response = http::response<http::string_body>{http::status::ok, request.version()};
                response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
                response.set(http::field::content_type, "text/plain");

                auto output = std::ostringstream{};
                for (const auto &answer: result) {
                    auto [preference, domain] = answer.rdata;
                    output << "Preference: " << preference << ", ";
                    output << "MX: " << domain << ";\n";
                }

                response.body() = output.str();
                response.prepare_payload();
                co_await http::async_write(socket, response, asio::use_awaitable);
            }
        }

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

auto main() -> int {
    constexpr auto PORT = 8080;

    auto io_context = asio::io_context{};
    auto acceptor = asio::ip::tcp::acceptor{io_context, {asio::ip::tcp::v4(), PORT}};
    co_spawn(io_context, listener(std::move(acceptor)), asio::detached);
    io_context.run();

    return {};
}
