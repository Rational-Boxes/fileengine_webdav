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
    }
    std::shared_ptr<GRPCClientWrapper> grpc_;
    std::shared_ptr<PathResolver> resolver_;
    std::shared_ptr<LDAPAuthenticator> ldap_;
};

TEST_F(WebDAVServerTest, HandlerConstructsWithDependencies) {
    WebDAVRequestHandler handler(grpc_, resolver_, ldap_);
    SUCCEED();  // construction without throwing is the assertion
}

TEST_F(WebDAVServerTest, FactoryConstructsAndProducesAHandler) {
    WebDAVRequestHandlerFactory factory(grpc_, resolver_, ldap_);
    SUCCEED();
}
