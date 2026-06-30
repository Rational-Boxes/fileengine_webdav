#ifndef GRPC_CLIENT_WRAPPER_H
#define GRPC_CLIENT_WRAPPER_H

#include <grpcpp/grpcpp.h>
#include <functional>
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

// Thin client wrapper over the canonical FileEngine FileService gRPC interface
// (file_engine_core/proto/fileservice.proto, package `fileengine_rpc`).
//
// The server is UID-based: there is no path->UID RPC. Path resolution is done
// in the bridge (PathResolver) by walking ListDirectory from the root.
class GRPCClientWrapper {
public:
    GRPCClientWrapper(const std::string& server_address);
    // virtual so tests can subclass with a gmock for the path-resolution RPCs
    // (listDirectory/stat) without a live core; see tests/test_path_resolver.cpp.
    virtual ~GRPCClientWrapper();

    // Directory operations
    fileengine_rpc::MakeDirectoryResponse makeDirectory(const fileengine_rpc::MakeDirectoryRequest& request);
    fileengine_rpc::RemoveDirectoryResponse removeDirectory(const fileengine_rpc::RemoveDirectoryRequest& request);
    virtual fileengine_rpc::ListDirectoryResponse listDirectory(const fileengine_rpc::ListDirectoryRequest& request);
    fileengine_rpc::ListDirectoryWithDeletedResponse listDirectoryWithDeleted(const fileengine_rpc::ListDirectoryWithDeletedRequest& request);

    // File operations
    fileengine_rpc::TouchResponse touch(const fileengine_rpc::TouchRequest& request);
    fileengine_rpc::RemoveFileResponse removeFile(const fileengine_rpc::RemoveFileRequest& request);
    fileengine_rpc::UndeleteFileResponse undeleteFile(const fileengine_rpc::UndeleteFileRequest& request);
    fileengine_rpc::PutFileResponse putFile(const fileengine_rpc::PutFileRequest& request);
    // Client-streaming upload: `nextChunk` is pulled repeatedly to fill `out`
    // with the next slice of body bytes; returning false ends the stream. The
    // whole file is never held in memory — chunks flow straight to the core.
    fileengine_rpc::PutFileResponse streamFileUpload(
        const std::string& uid,
        const fileengine_rpc::AuthenticationContext& auth,
        const std::function<bool(std::string&)>& nextChunk);
    fileengine_rpc::GetFileResponse getFile(const fileengine_rpc::GetFileRequest& request);
    // Server-streaming download: `onChunk` is invoked for each chunk; return
    // false to abort early. The whole file is never buffered in the bridge.
    struct DownloadResult { bool success; std::string error; };
    DownloadResult streamFileDownload(
        const fileengine_rpc::GetFileRequest& request,
        const std::function<bool(const std::string&)>& onChunk);

    // File information
    virtual fileengine_rpc::StatResponse stat(const fileengine_rpc::StatRequest& request);
    fileengine_rpc::ExistsResponse exists(const fileengine_rpc::ExistsRequest& request);

    // File manipulation operations
    fileengine_rpc::RenameResponse rename(const fileengine_rpc::RenameRequest& request);
    fileengine_rpc::MoveResponse move(const fileengine_rpc::MoveRequest& request);
    fileengine_rpc::CopyResponse copy(const fileengine_rpc::CopyRequest& request);

    // Version operations
    fileengine_rpc::ListVersionsResponse listVersions(const fileengine_rpc::ListVersionsRequest& request);
    fileengine_rpc::GetVersionResponse getVersion(const fileengine_rpc::GetVersionRequest& request);
    fileengine_rpc::RestoreToVersionResponse restoreToVersion(const fileengine_rpc::RestoreToVersionRequest& request);

    // Metadata operations
    fileengine_rpc::SetMetadataResponse setMetadata(const fileengine_rpc::SetMetadataRequest& request);
    fileengine_rpc::GetMetadataResponse getMetadata(const fileengine_rpc::GetMetadataRequest& request);
    fileengine_rpc::GetAllMetadataResponse getAllMetadata(const fileengine_rpc::GetAllMetadataRequest& request);
    fileengine_rpc::DeleteMetadataResponse deleteMetadata(const fileengine_rpc::DeleteMetadataRequest& request);

    // ACL operations
    fileengine_rpc::CheckPermissionResponse checkPermission(const fileengine_rpc::CheckPermissionRequest& request);

private:
    std::unique_ptr<fileengine_rpc::FileService::Stub> stub_;
    grpc::ChannelArguments channel_args_;
};

} // namespace webdav

#endif // GRPC_CLIENT_WRAPPER_H
