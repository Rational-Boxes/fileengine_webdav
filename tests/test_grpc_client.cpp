#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../include/grpc_client_wrapper.h"

class MockGRPCClientWrapper : public webdav::GRPCClientWrapper {
public:
    MockGRPCClientWrapper() : GRPCClientWrapper("localhost:50051") {}

    // Directory operations
    MOCK_METHOD(fileengine::MakeDirectoryResponse, makeDirectory,
                (const fileengine::MakeDirectoryRequest&), (override));
    MOCK_METHOD(fileengine::RemoveDirectoryResponse, removeDirectory,
                (const fileengine::RemoveDirectoryRequest&), (override));
    MOCK_METHOD(fileengine::ListDirectoryResponse, listDirectory,
                (const fileengine::ListDirectoryRequest&), (override));

    // File operations
    MOCK_METHOD(fileengine::CreateFileResponse, createFile,
                (const fileengine::CreateFileRequest&), (override));
    MOCK_METHOD(fileengine::DeleteFileResponse, deleteFile,
                (const fileengine::DeleteFileRequest&), (override));
    MOCK_METHOD(fileengine::UndeleteFileResponse, undeleteFile,
                (const fileengine::UndeleteFileRequest&), (override));
    MOCK_METHOD(fileengine::WriteFileResponse, writeFile,
                (const fileengine::WriteFileRequest&), (override));
    MOCK_METHOD(fileengine::ReadFileResponse, readFile,
                (const fileengine::ReadFileRequest&), (override));

    // File information
    MOCK_METHOD(fileengine::GetFileInfoResponse, getFileInfo,
                (const fileengine::GetFileInfoRequest&), (override));
    MOCK_METHOD(fileengine::FileExistsResponse, fileExists,
                (const fileengine::FileExistsRequest&), (override));

    // File manipulation operations
    MOCK_METHOD(fileengine::RenameFileResponse, renameFile,
                (const fileengine::RenameFileRequest&), (override));
    MOCK_METHOD(fileengine::MoveFileResponse, moveFile,
                (const fileengine::MoveFileRequest&), (override));
    MOCK_METHOD(fileengine::CopyFileResponse, copyFile,
                (const fileengine::CopyFileRequest&), (override));

    // Version operations
    MOCK_METHOD(fileengine::ListVersionsResponse, listVersions,
                (const fileengine::ListVersionsRequest&), (override));
    MOCK_METHOD(fileengine::ReadVersionResponse, readVersion,
                (const fileengine::ReadVersionRequest&), (override));

    // Metadata operations
    MOCK_METHOD(fileengine::SetMetadataResponse, setMetadata,
                (const fileengine::SetMetadataRequest&), (override));
    MOCK_METHOD(fileengine::GetMetadataResponse, getMetadata,
                (const fileengine::GetMetadataRequest&), (override));
    MOCK_METHOD(fileengine::GetAllMetadataResponse, getAllMetadata,
                (const fileengine::GetAllMetadataRequest&), (override));
    MOCK_METHOD(fileengine::DeleteMetadataResponse, deleteMetadata,
                (const fileengine::DeleteMetadataRequest&), (override));
    MOCK_METHOD(fileengine::GetMetadataForVersionResponse, getMetadataForVersion,
                (const fileengine::GetMetadataForVersionRequest&), (override));
    MOCK_METHOD(fileengine::GetAllMetadataForVersionResponse, getAllMetadataForVersion,
                (const fileengine::GetAllMetadataForVersionRequest&), (override));

    // Path resolution
    MOCK_METHOD(fileengine::ResolvePathResponse, resolvePath,
                (const fileengine::ResolvePathRequest&), (override));

    // ACL operations
    MOCK_METHOD(fileengine::EvaluateACLResponse, evaluateACL,
                (const fileengine::EvaluateACLRequest&), (override));
};

class GRPCClientWrapperTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<MockGRPCClientWrapper>();
    }

    void TearDown() override {
        client.reset();
    }

    std::unique_ptr<MockGRPCClientWrapper> client;
};

TEST_F(GRPCClientWrapperTest, MakeDirectoryTest) {
    // Create a mock request
    fileengine::MakeDirectoryRequest request;
    request.set_parent_uid("parent-uuid");
    request.set_name("test-dir");

    fileengine::AuthContext* auth = request.mutable_auth();
    auth->set_user("test-user");
    auth->set_tenant("test-tenant");
    auth->add_roles("users");

    // Create a mock response
    fileengine::MakeDirectoryResponse response;
    response.set_success(true);
    response.set_uid("new-dir-uuid");

    // Set up the expectation
    EXPECT_CALL(*client, makeDirectory(::testing::_))
        .WillOnce(::testing::Return(response));

    // Call the method
    auto result = client->makeDirectory(request);

    // Verify the result
    EXPECT_TRUE(result.success());
    EXPECT_EQ(result.uid(), "new-dir-uuid");
}

TEST_F(GRPCClientWrapperTest, ReadFileTest) {
    // Create a mock request
    fileengine::ReadFileRequest request;
    request.set_uid("file-uuid");

    fileengine::AuthContext* auth = request.mutable_auth();
    auth->set_user("test-user");
    auth->set_tenant("test-tenant");
    auth->add_roles("users");

    // Create a mock response
    fileengine::ReadFileResponse response;
    response.set_success(true);
    std::string testData = "test file content";
    response.set_data(testData);

    // Set up the expectation
    EXPECT_CALL(*client, readFile(::testing::_))
        .WillOnce(::testing::Return(response));

    // Call the method
    auto result = client->readFile(request);

    // Verify the result
    EXPECT_TRUE(result.success());
    EXPECT_EQ(result.data(), testData);
}
