#include "resolver.hpp"

#include "gtest/gtest.h"
#include "mock_dns_transport.hpp"

using namespace tuposoft::asio::dns;
using namespace boost::asio;
using namespace testing;

namespace {
    auto ok() -> awaitable<void> { co_return; }

    auto recv_with(const std::span<const char> chars, std::span<std::byte> dst)
            -> awaitable<std::pair<boost::system::error_code, std::size_t>> {
        const auto bytes = std::as_bytes(chars);
        const auto size = std::min(bytes.size(), dst.size());
        std::copy_n(bytes.begin(), size, dst.begin());
        co_return std::pair{boost::system::error_code{}, size};
    }
} // namespace

class resolver_test : public Test {
protected:
    io_context context_;

    template<qtype T>
    auto
    query_test(std::tuple<std::string, std::size_t, std::vector<typename rdata<T>::type>, std::span<const char>> data)
            -> awaitable<void> {
        auto [name, size, expected, raw] = data;
        const auto transport = std::make_shared<mock_dns_transport>();

        EXPECT_CALL(*transport, connect(_)).WillOnce(Invoke([](const auto &) -> auto { return ok(); }));
        EXPECT_CALL(*transport, send(_)).WillOnce(Invoke([](const auto &) -> auto { return ok(); }));
        EXPECT_CALL(*transport, receive(_, _)).WillOnce(Invoke([raw](auto dst, auto) -> auto {
            return recv_with(raw, dst);
        }));

        auto resolv = resolver{transport};
        co_await resolv.connect("1.1.1.1");
        const auto result = co_await resolv.query<T>(name);
        EXPECT_EQ(result.size(), size);
        for (int i = 0; i < result.size(); ++i) {
            auto found_it = std::find(expected.begin(), expected.end(), result[i].rdata);
            EXPECT_NE(found_it, expected.end());
        }
    }
};

TEST_F(resolver_test, a) {
    constexpr auto recv = std::span<const char>{
            "[N\201\200\000\001\000\002\000\000\000\000\aexample\003com\000\000\001\000\001\300\f\000\001\000\001\000"
            "\000\0008\000\004h\022\032x\300\f\000\001\000\001\000\000\0008\000\004h\022\033x"};

    co_spawn(context_, query_test<qtype::A>({"example.com", 2, {"104.18.26.120", "104.18.27.120"}, recv}), detached);
    context_.run();
}

TEST_F(resolver_test, mx) {
    static constexpr auto size = 5;
    static constexpr auto alt2_preference = 20;
    static constexpr auto alt3_preference = 30;
    static constexpr auto alt4_preference = 40;
    static constexpr auto gmail_preference = 5;
    static constexpr auto alt1_preference = 10;

    static constexpr auto recv =
            std::span<const char>{"Lw\201\200\000\001\000\005\000\000\000\000\005gmail\003com\000\000\017\000\001\300\f"
                                  "\000\017\000\001\000\000\003\024\000\033\000\005\rgmail-smtp-"
                                  "in\001l\006google\300\022\300\f\000\017\000\001\000\000\003\024\000\t\000\036\004alt"
                                  "3\300)\300\f\000\017\000\001\000\000\003\024\000\t\000\n\004alt1\300)"
                                  "\300\f\000\017\000\001\000\000\003\024\000\t\000\024\004alt2\300)"
                                  "\300\f\000\017\000\001\000\000\003\024\000\t\000(\004alt4\300)"};

    co_spawn(context_,
             query_test<qtype::MX>({"gmail.com",
                                    size,
                                    {
                                            {.preference = alt2_preference, .mx = "alt2.gmail-smtp-in.l.google.com"},
                                            {.preference = alt3_preference, .mx = "alt3.gmail-smtp-in.l.google.com"},
                                            {.preference = alt4_preference, .mx = "alt4.gmail-smtp-in.l.google.com"},
                                            {.preference = gmail_preference, .mx = "gmail-smtp-in.l.google.com"},
                                            {.preference = alt1_preference, .mx = "alt1.gmail-smtp-in.l.google.com"},
                                    },
                                    recv}),
             detached);
    context_.run();
}

TEST_F(resolver_test, ptr) {
    static constexpr auto recv = std::span<const char>{
            "u\361\201\200\000\001\000\001\000\000\000\000\0011\0011\0011\0011\ain-"
            "addr\004arpa\000\000\f\000\001\300\f\000\f\000\001\000\000\002M\000\021\003one\003one\003one\003one\000"};

    co_spawn(context_, query_test<qtype::PTR>({"1.1.1.1", 1, {"one.one.one.one"}, recv}), detached);
    context_.run();
}

TEST_F(resolver_test, ns) {
    static constexpr auto recv =
            std::span<const char>{"\350\224\201\200\000\001\000\002\000\000\000\000\btuposoft\003com\000\000\002\000"
                                  "\001\300\f\000\002\000\001\000\001Q\200\000\031\bbenedict\002ns\ncloudflare\300\025"
                                  "\300\f\000\002\000\001\000\001Q\200\000\f\tgabriella\3003"};

    co_spawn(context_,
             query_test<qtype::NS>(
                     {"tuposoft.com", 2, {"benedict.ns.cloudflare.com", "gabriella.ns.cloudflare.com"}, recv}),
             detached);
    context_.run();
}

TEST_F(resolver_test, cname) {
    static constexpr auto recv =
            std::span<const char>{"\323\371\201\200\000\001\000\001\000\000\000\000\nbucketname\002s3\tamazonaws\003com"
                                  "\000\000\005\000\001\300\f\000\005\000\001\000\000\247E\000\t\006s3-1-w\300\032"};

    co_spawn(context_, query_test<qtype::CNAME>({"bucketname.s3.amazonaws.com", 1, {"s3-1-w.amazonaws.com"}, recv}),
             detached);
    context_.run();
}
