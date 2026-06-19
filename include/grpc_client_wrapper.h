#ifndef GRPC_CLIENT_WRAPPER_H
#define GRPC_CLIENT_WRAPPER_H

#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>

#include "fileservice.grpc.pb.h"
#include "utils.h"  // For logging functions

namespace webdav {

struct AuthenticationContext {
    std::string user;
    std::vector<std::string> roles;
    std::string tenant;
    std::map<std::string, std::string> claims;
};

// Thin client wrapper over the fileengine FileService gRPC interface
// (file_engine_cpp/proto/fileservice.proto, package `fileengine`).
class GRPCClientWrapper {
public:
    GRPCClientWrapper(const std::string& server_address);
    ~GRPCClientWrapper();

    // Directory operations
    fileengine::MakeDirectoryResponse makeDirectory(const fileengine::MakeDirectoryRequest& request);
    fileengine::RemoveDirectoryResponse removeDirectory(const fileengine::RemoveDirectoryRequest& request);
    fileengine::ListDirectoryResponse listDirectory(const fileengine::ListDirectoryRequest& request);

    // File operations
    fileengine::CreateFileResponse createFile(const fileengine::CreateFileRequest& request);
    fileengine::DeleteFileResponse deleteFile(const fileengine::DeleteFileRequest& request);
    fileengine::UndeleteFileResponse undeleteFile(const fileengine::UndeleteFileRequest& request);
    fileengine::WriteFileResponse writeFile(const fileengine::WriteFileRequest& request);
    fileengine::ReadFileResponse readFile(const fileengine::ReadFileRequest& request);

    // File information
    fileengine::GetFileInfoResponse getFileInfo(const fileengine::GetFileInfoRequest& request);
    fileengine::FileExistsResponse fileExists(const fileengine::FileExistsRequest& request);

    // File manipulation operations
    fileengine::RenameFileResponse renameFile(const fileengine::RenameFileRequest& request);
    fileengine::MoveFileResponse moveFile(const fileengine::MoveFileRequest& request);
    fileengine::CopyFileResponse copyFile(const fileengine::CopyFileRequest& request);

    // Version operations
    fileengine::ListVersionsResponse listVersions(const fileengine::ListVersionsRequest& request);
    fileengine::ReadVersionResponse readVersion(const fileengine::ReadVersionRequest& request);

    // Metadata operations
    fileengine::SetMetadataResponse setMetadata(const fileengine::SetMetadataRequest& request);
    fileengine::GetMetadataResponse getMetadata(const fileengine::GetMetadataRequest& request);
    fileengine::GetAllMetadataResponse getAllMetadata(const fileengine::GetAllMetadataRequest& request);
    fileengine::DeleteMetadataResponse deleteMetadata(const fileengine::DeleteMetadataRequest& request);
    fileengine::GetMetadataForVersionResponse getMetadataForVersion(const fileengine::GetMetadataForVersionRequest& request);
    fileengine::GetAllMetadataForVersionResponse getAllMetadataForVersion(const fileengine::GetAllMetadataForVersionRequest& request);

    // Path resolution
    fileengine::ResolvePathResponse resolvePath(const fileengine::ResolvePathRequest& request);

    // ACL operations
    fileengine::EvaluateACLResponse evaluateACL(const fileengine::EvaluateACLRequest& request);

private:
    std::unique_ptr<fileengine::FileService::Stub> stub_;
    grpc::ChannelArguments channel_args_;
};

} // namespace webdav

#endif // GRPC_CLIENT_WRAPPER_H
