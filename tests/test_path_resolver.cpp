// Copyright (C) 2026 James Hickman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Hermetic unit tests for PathResolver::resolvePath — the path->UID resolution
// that every WebDAV verb depends on. resolvePath walks the tree via the gRPC
// ListDirectory RPC (matching each segment by name) and caches resolved
// prefixes; it needs no database. We mock GRPCClientWrapper's listDirectory so
// the whole test runs offline with a scripted directory tree.
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <utility>
#include "../include/path_resolver.h"
#include "../include/grpc_client_wrapper.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using namespace webdav;

namespace {

fileengine_rpc::ListDirectoryResponse listing(
    std::initializer_list<std::pair<const char*, const char*>> entries) {
    fileengine_rpc::ListDirectoryResponse resp;
    resp.set_success(true);
    for (const auto& entry : entries) {
        auto* e = resp.add_entries();
        e->set_name(entry.first);
        e->set_uid(entry.second);
    }
    return resp;
}

fileengine_rpc::AuthenticationContext auth(const std::string& tenant = "default") {
    fileengine_rpc::AuthenticationContext a;
    a.set_user("tester");
    a.set_tenant(tenant);
    a.add_roles("users");
    return a;
}

// Overrides only the RPCs resolvePath uses (listDirectory for the walk, stat for
// the cache-hit verify path).
class MockGrpc : public GRPCClientWrapper {
public:
    MockGrpc() : GRPCClientWrapper("localhost:50051") {}
    MOCK_METHOD(fileengine_rpc::ListDirectoryResponse, listDirectory,
                (const fileengine_rpc::ListDirectoryRequest&), (override));
    MOCK_METHOD(fileengine_rpc::StatResponse, stat,
                (const fileengine_rpc::StatRequest&), (override));
};

}  // namespace

class PathResolverTest : public ::testing::Test {
protected:
    void SetUp() override {
        grpc_ = std::make_shared<MockGrpc>();
        resolver_ = std::make_unique<PathResolver>(grpc_);
    }
    std::shared_ptr<MockGrpc> grpc_;
    std::unique_ptr<PathResolver> resolver_;
};

TEST_F(PathResolverTest, RootResolvesToEmptyUid) {
    // No RPC needed for the root.
    auto r = resolver_->resolvePath("/", auth());
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, "");
}

TEST_F(PathResolverTest, ResolvesByWalkingTheTree) {
    // Scripted tree:  / -> {MyDocuments=uid-md, Test1=uid-t1};  uid-md -> {Report.txt=uid-rep}
    EXPECT_CALL(*grpc_, listDirectory(_)).WillRepeatedly(Invoke(
        [](const fileengine_rpc::ListDirectoryRequest& req) {
            if (req.uid().empty())     return listing({{"MyDocuments", "uid-md"}, {"Test1", "uid-t1"}});
            if (req.uid() == "uid-md") return listing({{"Report.txt", "uid-rep"}});
            return listing({});
        }));

    EXPECT_EQ(resolver_->resolvePath("/MyDocuments", auth()).value_or("<none>"), "uid-md");
    EXPECT_EQ(resolver_->resolvePath("/Test1", auth()).value_or("<none>"), "uid-t1");
    EXPECT_EQ(resolver_->resolvePath("/MyDocuments/Report.txt", auth()).value_or("<none>"), "uid-rep");
}

TEST_F(PathResolverTest, MissingSegmentReturnsNullopt) {
    EXPECT_CALL(*grpc_, listDirectory(_)).WillRepeatedly(Invoke(
        [](const fileengine_rpc::ListDirectoryRequest& req) {
            if (req.uid().empty()) return listing({{"MyDocuments", "uid-md"}});
            return listing({});  // uid-md has no children
        }));

    EXPECT_FALSE(resolver_->resolvePath("/Nope", auth()).has_value());
    EXPECT_FALSE(resolver_->resolvePath("/MyDocuments/missing.txt", auth()).has_value());
}

TEST_F(PathResolverTest, ListDirectoryFailureReturnsNullopt) {
    fileengine_rpc::ListDirectoryResponse fail;
    fail.set_success(false);
    fail.set_error("permission denied");
    EXPECT_CALL(*grpc_, listDirectory(_)).WillRepeatedly(Return(fail));

    EXPECT_FALSE(resolver_->resolvePath("/anything", auth()).has_value());
}
