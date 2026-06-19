#include "grpc_client_wrapper.h"
#include <iostream>
#include <memory>

namespace webdav {

GRPCClientWrapper::GRPCClientWrapper(const std::string& server_address) {
    webdav::debugLog("GRPCClientWrapper: Creating gRPC channel to: " + server_address);
    auto channel = grpc::CreateCustomChannel(server_address, grpc::InsecureChannelCredentials(), channel_args_);
    webdav::debugLog("GRPCClientWrapper: Channel created, creating stub");
    stub_ = fileengine::FileService::NewStub(channel);
    webdav::debugLog("GRPCClientWrapper: gRPC client initialized successfully");
}

GRPCClientWrapper::~GRPCClientWrapper() = default;

// Directory operations
fileengine::MakeDirectoryResponse GRPCClientWrapper::makeDirectory(const fileengine::MakeDirectoryRequest& request) {
    webdav::debugLog("gRPC MakeDirectory called with parent_uid: " + request.parent_uid() +
                     ", name: " + request.name() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine::MakeDirectoryResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->MakeDirectory(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("MakeDirectory failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("MakeDirectory succeeded, returned uid: " + response.uid());
        response.set_success(true);
    }

    return response;
}

fileengine::RemoveDirectoryResponse GRPCClientWrapper::removeDirectory(const fileengine::RemoveDirectoryRequest& request) {
    webdav::debugLog("gRPC RemoveDirectory called with uid: " + request.uid() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine::RemoveDirectoryResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->RemoveDirectory(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("RemoveDirectory failed: " + std::string(status.error_message()));
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("RemoveDirectory succeeded for uid: " + request.uid());
    }

    return response;
}

fileengine::ListDirectoryResponse GRPCClientWrapper::listDirectory(const fileengine::ListDirectoryRequest& request) {
    webdav::debugLog("gRPC ListDirectory called with uid: " + request.uid() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user() +
                     ", roles count: " + std::to_string(request.auth().roles_size()));

    // Log all roles in the request
    for (int i = 0; i < request.auth().roles_size(); i++) {
        webdav::debugLog("gRPC ListDirectory - role[" + std::to_string(i) + "]: " + request.auth().roles(i));
    }

    fileengine::ListDirectoryResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->ListDirectory(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("ListDirectory failed: " + std::string(status.error_message()) +
                         ", error code: " + std::to_string(status.error_code()));

        // Check if this is a permission error that might be resolved by checking ACLs
        if (status.error_code() == grpc::PERMISSION_DENIED || status.error_code() == grpc::NOT_FOUND) {
            webdav::debugLog("ListDirectory failed with permission error, this might be resolved by proper ACL configuration");
        }

        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("ListDirectory succeeded, returned " + std::to_string(response.entries_size()) + " entries");
        response.set_success(true);
    }

    return response;
}

// File operations
fileengine::CreateFileResponse GRPCClientWrapper::createFile(const fileengine::CreateFileRequest& request) {
    fileengine::CreateFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->CreateFile(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("CreateFile failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        response.set_success(true);
    }

    return response;
}

fileengine::DeleteFileResponse GRPCClientWrapper::deleteFile(const fileengine::DeleteFileRequest& request) {
    fileengine::DeleteFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->DeleteFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "DeleteFile failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::UndeleteFileResponse GRPCClientWrapper::undeleteFile(const fileengine::UndeleteFileRequest& request) {
    fileengine::UndeleteFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->UndeleteFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "UndeleteFile failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::WriteFileResponse GRPCClientWrapper::writeFile(const fileengine::WriteFileRequest& request) {
    webdav::debugLog("gRPC WriteFile called with uid: " + request.uid() +
                     ", data size: " + std::to_string(request.data().size()) + " bytes" +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine::WriteFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->WriteFile(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("WriteFile failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("WriteFile succeeded for uid: " + request.uid());
        response.set_success(true);
    }

    return response;
}

fileengine::ReadFileResponse GRPCClientWrapper::readFile(const fileengine::ReadFileRequest& request) {
    webdav::debugLog("gRPC ReadFile called with uid: " + request.uid() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine::ReadFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->ReadFile(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("ReadFile failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("ReadFile succeeded, returned data of size: " + std::to_string(response.data().size()) + " bytes");
        response.set_success(true);
    }

    return response;
}

// File information
fileengine::GetFileInfoResponse GRPCClientWrapper::getFileInfo(const fileengine::GetFileInfoRequest& request) {
    fileengine::GetFileInfoResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->GetFileInfo(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("GetFileInfo failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        response.set_success(true);
    }

    return response;
}

fileengine::FileExistsResponse GRPCClientWrapper::fileExists(const fileengine::FileExistsRequest& request) {
    fileengine::FileExistsResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->FileExists(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "FileExists failed: " << status.error_message() << std::endl;
    }

    return response;
}

// File manipulation operations
fileengine::RenameFileResponse GRPCClientWrapper::renameFile(const fileengine::RenameFileRequest& request) {
    fileengine::RenameFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->RenameFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "RenameFile failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::MoveFileResponse GRPCClientWrapper::moveFile(const fileengine::MoveFileRequest& request) {
    fileengine::MoveFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->MoveFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "MoveFile failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::CopyFileResponse GRPCClientWrapper::copyFile(const fileengine::CopyFileRequest& request) {
    fileengine::CopyFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->CopyFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "CopyFile failed: " << status.error_message() << std::endl;
    }

    return response;
}

// Version operations
fileengine::ListVersionsResponse GRPCClientWrapper::listVersions(const fileengine::ListVersionsRequest& request) {
    fileengine::ListVersionsResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->ListVersions(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "ListVersions failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::ReadVersionResponse GRPCClientWrapper::readVersion(const fileengine::ReadVersionRequest& request) {
    fileengine::ReadVersionResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->ReadVersion(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "ReadVersion failed: " << status.error_message() << std::endl;
    }

    return response;
}

// Metadata operations
fileengine::SetMetadataResponse GRPCClientWrapper::setMetadata(const fileengine::SetMetadataRequest& request) {
    fileengine::SetMetadataResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->SetMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "SetMetadata failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::GetMetadataResponse GRPCClientWrapper::getMetadata(const fileengine::GetMetadataRequest& request) {
    fileengine::GetMetadataResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->GetMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetMetadata failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::GetAllMetadataResponse GRPCClientWrapper::getAllMetadata(const fileengine::GetAllMetadataRequest& request) {
    fileengine::GetAllMetadataResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->GetAllMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetAllMetadata failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::DeleteMetadataResponse GRPCClientWrapper::deleteMetadata(const fileengine::DeleteMetadataRequest& request) {
    fileengine::DeleteMetadataResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->DeleteMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "DeleteMetadata failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::GetMetadataForVersionResponse GRPCClientWrapper::getMetadataForVersion(const fileengine::GetMetadataForVersionRequest& request) {
    fileengine::GetMetadataForVersionResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->GetMetadataForVersion(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetMetadataForVersion failed: " << status.error_message() << std::endl;
    }

    return response;
}

fileengine::GetAllMetadataForVersionResponse GRPCClientWrapper::getAllMetadataForVersion(const fileengine::GetAllMetadataForVersionRequest& request) {
    fileengine::GetAllMetadataForVersionResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->GetAllMetadataForVersion(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetAllMetadataForVersion failed: " << status.error_message() << std::endl;
    }

    return response;
}

// Path resolution
fileengine::ResolvePathResponse GRPCClientWrapper::resolvePath(const fileengine::ResolvePathRequest& request) {
    fileengine::ResolvePathResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->ResolvePath(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "ResolvePath failed: " << status.error_message() << std::endl;
    }

    return response;
}

// ACL operations
fileengine::EvaluateACLResponse GRPCClientWrapper::evaluateACL(const fileengine::EvaluateACLRequest& request) {
    fileengine::EvaluateACLResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->EvaluateACL(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "EvaluateACL failed: " << status.error_message() << std::endl;
    }

    return response;
}

} // namespace webdav
