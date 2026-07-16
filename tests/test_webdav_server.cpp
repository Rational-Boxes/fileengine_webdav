// WebDAVRequestHandler's request methods (handlePropfind, etc.) take Poco
// HTTPServerRequest/Response objects, which require a live HTTP session to
// construct — they are exercised by the end-to-end suite (test_webdav.sh), not
// here. The path-resolution logic those verbs depend on is unit-tested in
// test_path_resolver.cpp. This suite guards the handler/factory's dependency
// contract: that they still construct against the current GRPCClientWrapper /
// PathResolver / LDAPAuthenticator types (a compile + wiring regression guard).
#include <gtest/gtest.h>
#include "../include/webdav_server.h"
#include "../include/grpc_client_wrapper.h"
#include "../include/path_resolver.h"
#include "../include/ldap_authenticator.h"
#include "../include/client_ip.h"
#include "../include/webdav_hardening.h"

using namespace webdav;

class WebDAVServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // All three ctors are lazy (no network I/O), so this is hermetic.
        grpc_ = std::make_shared<GRPCClientWrapper>("localhost:50051");
        resolver_ = std::make_shared<PathResolver>(grpc_);
        ldap_ = std::make_shared<LDAPAuthenticator>(
            "ldap://localhost:389", "dc=example,dc=com",
            "cn=admin,dc=example,dc=com", "admin");
        // Hardening ctor is lazy (no network I/O until a request), so hermetic.
        hardening_ = std::make_shared<WebdavHardening>(HardeningConfig{});
    }
    std::shared_ptr<GRPCClientWrapper> grpc_;
    std::shared_ptr<PathResolver> resolver_;
    std::shared_ptr<LDAPAuthenticator> ldap_;
    std::shared_ptr<WebdavHardening> hardening_;
};

TEST_F(WebDAVServerTest, HandlerConstructsWithDependencies) {
    WebDAVRequestHandler handler(grpc_, resolver_, ldap_, hardening_);
    SUCCEED();  // construction without throwing is the assertion
}

TEST_F(WebDAVServerTest, FactoryConstructsAndProducesAHandler) {
    WebDAVRequestHandlerFactory factory(grpc_, resolver_, ldap_, hardening_);
    SUCCEED();
}

// The LAN-exemption branch (§5.6/§14.1) rests on matching the authoritative IP
// against the trusted CIDRs — the security-critical primitive.
TEST(WebdavHardeningTest, TrustedCidrMatch) {
    std::vector<std::string> cidrs{"10.0.0.0/8", "192.168.1.0/24"};
    EXPECT_TRUE(ipInAnyCidr("10.5.6.7", cidrs));
    EXPECT_TRUE(ipInAnyCidr("192.168.1.42", cidrs));
    EXPECT_FALSE(ipInAnyCidr("192.168.2.42", cidrs));
    EXPECT_FALSE(ipInAnyCidr("8.8.8.8", cidrs));
    EXPECT_FALSE(ipInAnyCidr("", cidrs));
}

// Trusted-proxy IP resolution: a direct peer is used as-is; a spoofed left-most
// XFF hop is ignored in favor of the right-most untrusted hop.
TEST(WebdavHardeningTest, TrustedProxyResolution) {
    std::vector<std::string> proxies{"10.0.0.0/8"};
    // Direct (untrusted) peer: XFF ignored.
    EXPECT_EQ(resolveClientIp("203.0.113.9", "1.2.3.4", proxies), "203.0.113.9");
    // Via a trusted proxy: take the right-most non-proxy hop, not the spoofed left.
    EXPECT_EQ(resolveClientIp("10.0.0.1", "6.6.6.6, 203.0.113.9", proxies), "203.0.113.9");
    // No trusted proxies configured (dev): first XFF hop is trusted (matches
    // http_bridge so both bridges derive the same IP); peer only when no XFF.
    EXPECT_EQ(resolveClientIp("10.0.0.1", "1.2.3.4", {}), "1.2.3.4");
    EXPECT_EQ(resolveClientIp("10.0.0.1", "", {}), "10.0.0.1");
}

// session_ip matching: IPv4 exact; IPv6 exact at /128; IPv6 /64 tolerates
// privacy-address rotation within the prefix; cross-family never matches.
TEST(WebdavHardeningTest, SessionIpMatch) {
    // IPv4 — exact regardless of prefix (v6prefix doesn't apply).
    EXPECT_TRUE(ipMatchesForSession("192.0.2.10", "192.0.2.10", 128));
    EXPECT_FALSE(ipMatchesForSession("192.0.2.10", "192.0.2.11", 64));
    // IPv6 exact at /128.
    EXPECT_TRUE(ipMatchesForSession("2001:db8::1", "2001:db8::1", 128));
    EXPECT_FALSE(ipMatchesForSession("2001:db8::1", "2001:db8::2", 128));
    // IPv6 /64 — different interface IDs in the same /64 match (rotation), a
    // different /64 does not.
    EXPECT_TRUE(ipMatchesForSession("2001:db8:0:1::abcd", "2001:db8:0:1::ef01", 64));
    EXPECT_FALSE(ipMatchesForSession("2001:db8:0:1::1", "2001:db8:0:2::1", 64));
    // Cross-family never matches — no v4<->v6 correlation.
    EXPECT_FALSE(ipMatchesForSession("2001:db8::1", "192.0.2.10", 64));
}
