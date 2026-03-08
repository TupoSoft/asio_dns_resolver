#include "udp_dns_transport.hpp"

#include "boost/asio/experimental/awaitable_operators.hpp"

#include <utility>

namespace tuposoft::asio::dns {
    namespace asio = boost::asio;

    class udp_dns_transport final : public dns_transport {
    public:
        explicit udp_dns_transport(const asio::any_io_executor &executor) : socket_(executor) {}

        auto connect(const asio::ip::udp::endpoint remote) -> asio::awaitable<void> override {
            co_await socket_.async_connect(remote, asio::use_awaitable);
        }

        auto send(std::span<const std::byte> bytes) -> asio::awaitable<void> override {
            co_await socket_.async_send(asio::buffer(bytes), asio::use_awaitable);
        }

        auto receive(std::span<std::byte> buffer, std::chrono::milliseconds timeout)
                -> asio::awaitable<std::pair<boost::system::error_code, std::size_t>> override {
            using asio::experimental::awaitable_operators::operator||;

            asio::steady_timer timer{socket_.get_executor(), timeout};

            auto recv = socket_.async_receive(asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
            auto wait = timer.async_wait(asio::as_tuple(asio::use_awaitable));

            auto result = co_await (std::move(recv) || std::move(wait));

            if (result.index() == 1) {
                socket_.cancel();
                co_return std::pair<boost::system::error_code, std::size_t>{
                        asio::error::timed_out,
                        std::size_t{0},
                };
            }

            auto [error_code, buf_size] = std::get<0>(result);
            timer.cancel();

            co_return std::pair{error_code, buf_size};
        }

    private:
        asio::ip::udp::socket socket_;
    };

    auto create_udp_dns_transport(const asio::any_io_executor &executor) -> std::shared_ptr<dns_transport> {
        return std::make_shared<udp_dns_transport>(executor);
    }
} // namespace tuposoft::asio::dns
