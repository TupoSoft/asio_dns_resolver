# ASIO DNS Resolver

## Description

An Asynchronous DNS Resolver written in C++ based on ASIO.

## Query results

`resolver::query<T>()` selects the requested DNS type and returns `std::vector<dns_answer>`.
Answers retain their wire order and actual record types, including CNAMEs returned alongside the requested records.

`dns_answer::rdata` is a `rdata_value` variant: `std::string` for A, AAAA, CNAME, NS, PTR, and TXT;
`mx_rdata` for MX; `soa_rdata` for SOA; and `std::vector<std::uint8_t>` for unsupported types or classes.
Check `answer.type` and use `std::get_if` or `std::visit` to access the value. Multiple TXT character-strings are concatenated.

This replaces the previous `dns_answer<T>`, `dns_response<T>`, and `rdata<T>` API.
Direct parsing requires a seekable stream containing the full DNS message so compression offsets remain valid.
Malformed headers or RDATA throw `std::runtime_error`; a failed response parse does not publish partial answers.
