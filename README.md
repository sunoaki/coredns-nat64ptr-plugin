# coredns-nat64ptr-plugin

`coredns-nat64ptr-plugin` is a CoreDNS plugin named `nat64ptr`. It rewrites PTR lookups under a configured NAT64 `/96` IPv6 reverse zone into the embedded IPv4 address's `in-addr.arpa.` PTR lookup, forwards the request to the next plugin, then rewrites response owner names back to the original `ip6.arpa.` name.

This is useful when IPv6-only clients behind NAT64 need reverse DNS for IPv4 destinations represented inside a NAT64 prefix.

## Project Name

- Project/module name: `coredns-nat64ptr-plugin`
- CoreDNS plugin directive: `nat64ptr`
- Go module path: `github.com/sunoaki/coredns-nat64ptr-plugin`

## Corefile

```corefile
. {
    nat64ptr 2602:2a3:4:9b64:2::/96
    forward . 172.16.0.53
}
```

Only PTR questions below the configured `/96` reverse zone are handled. Other requests are passed to the next plugin unchanged. A second optional argument configures the backend reverse suffix; it defaults to `in-addr.arpa.`.

```corefile
nat64ptr 2602:2a3:4:9b64:2::/96 in-addr.arpa.
```

## Query Flow

For `2602:2a3:4:9b64:2::172.23.0.53`, the IPv6 reverse name starts with the embedded IPv4 nibbles:

```text
5.3.0.0.7.1.c.a...
```

`nat64ptr` converts those nibbles into `53.0.23.172.in-addr.arpa.`, forwards the rewritten request to the next plugin, then rewrites the response `Question` and `Answer` owner names back to the original IPv6 `ip6.arpa.` name.

## CoreDNS Integration

Add this plugin to CoreDNS `plugin.cfg` before the plugin that should receive the rewritten IPv4 PTR query, usually before `forward`:

```text
nat64ptr:github.com/sunoaki/coredns-nat64ptr-plugin
```

Then rebuild CoreDNS with the normal CoreDNS build process.

## Development

Run the unit tests with:

```sh
go test ./...
```

## Files

- `setup.go`: CoreDNS registration and Corefile parsing.
- `nat64ptr.go`: PTR request matching, IPv4 extraction, downstream forwarding, and response rewriting.
- `nat64ptr_test.go`: Unit tests for extraction and end-to-end rewrite behavior.
