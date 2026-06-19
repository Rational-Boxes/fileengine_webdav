#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../include/path_resolver.h"
#include "../include/grpc_client_wrapper.h"

class MockGRPCClientWrapperForPathResolver : public webdav::GRPCClientWrapper {
public:
    MockGRPCClientWrapperForPathResolver(const std::string& server_address) 
        : GRPCClientWrapper(server_address) {}
    
    MOCK_METHOD(fileengine::GetFileInfoResponse, getFileInfo,
                (const fileengine::GetFileInfoRequest&), (override));
};

class PathResolverTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Using a mock connection string for testing
        mock_grpc = std::make_shared<MockGRPCClientWrapperForPathResolver>("localhost:50051");
        resolver = std::make_unique<webdav::PathResolver>(mock_grpc, "host=localhost port=5432 dbname=test_db user=test password=test");
    }

    void TearDown() override {
        resolver.reset();
        mock_grpc.reset();
    }

    std::shared_ptr<MockGRPCClientWrapperForPathResolver> mock_grpc;
    std::unique_ptr<webdav::PathResolver> resolver;
};

TEST_F(PathResolverTest, ResolvePathToUUIDTest) {
    std::string path = "/test/path/file.txt";
    std::string tenant = "test-tenant";
    std::string expected_uuid = "test-uuid-12345";

    // Create the path mapping first
    bool created = resolver->createPathMapping(path, expected_uuid, tenant);
    EXPECT_TRUE(created);

    // Now resolve the path to UUID
    std::string result_uuid = resolver->resolvePathToUUID(path, tenant);
    EXPECT_EQ(result_uuid, expected_uuid);
}

TEST_F(PathResolverTest, ResolveUUIDToPathTest) {
    std::string path = "/test/path/file.txt";
    std::string tenant = "test-tenant";
    std::string uuid = "test-uuid-12345";

    // Create the path mapping first
    bool created = resolver->createPathMapping(path, uuid, tenant);
    EXPECT_TRUE(created);

    // Now resolve the UUID to path
    std::string result_path = resolver->resolveUUIDToPath(uuid, tenant);
    EXPECT_EQ(result_path, path);
}

TEST_F(PathResolverTest, PathExistsTest) {
    std::string path = "/test/path/existing_file.txt";
    std::string tenant = "test-tenant";
    std::string uuid = "existing-uuid-12345";

    // Create the path mapping first
    bool created = resolver->createPathMapping(path, uuid, tenant);
    EXPECT_TRUE(created);

    // Check that the path exists
    bool exists = resolver->pathExists(path, tenant);
    EXPECT_TRUE(exists);

    // Check that a non-existent path doesn't exist
    bool not_exists = resolver->pathExists("/non/existent/path", tenant);
    EXPECT_FALSE(not_exists);
}

TEST_F(PathResolverTest, GetParentUUIDTest) {
    std::string parent_path = "/test/";
    std::string child_path = "/test/child.txt";
    std::string tenant = "test-tenant";
    std::string parent_uuid = "parent-uuid-12345";
    std::string child_uuid = "child-uuid-67890";

    // Create parent and child path mappings
    bool parent_created = resolver->createPathMapping(parent_path, parent_uuid, tenant);
    bool child_created = resolver->createPathMapping(child_path, child_uuid, tenant);
    EXPECT_TRUE(parent_created);
    EXPECT_TRUE(child_created);

    // Get the parent UUID of the child path
    std::string result_parent_uuid = resolver->getParentUUID(child_path, tenant);
    EXPECT_EQ(result_parent_uuid, parent_uuid);
}