#include "webdav_server.h"
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTMLForm.h>
#include <Poco/StreamCopier.h>
#include <Poco/Path.h>
#include <Poco/URI.h>
#include <Poco/Exception.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Base64Encoder.h>
#include <Poco/Base64Decoder.h>
#include <Poco/MD5Engine.h>
#include <Poco/DigestEngine.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/DateTimeFormat.h>
#include <Poco/Timestamp.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctime>
#include <set>

namespace webdav {

namespace {
// WebDAV date helpers. getlastmodified must be an RFC 1123 HTTP-date and
// creationdate an ISO 8601 timestamp (RFC 4918 §15); emitting raw epochs (or a
// malformed "<epoch>Z") makes strict clients such as cadaver mis-parse or crash.
std::string httpDate(std::int64_t epoch_seconds) {
    Poco::Timestamp ts = Poco::Timestamp::fromEpochTime(static_cast<std::time_t>(epoch_seconds));
    return Poco::DateTimeFormatter::format(ts, Poco::DateTimeFormat::HTTP_FORMAT);
}
std::string isoDate(std::int64_t epoch_seconds) {
    Poco::Timestamp ts = Poco::Timestamp::fromEpochTime(static_cast<std::time_t>(epoch_seconds));
    return Poco::DateTimeFormatter::format(ts, Poco::DateTimeFormat::ISO8601_FORMAT);
}

// Recursively delete a directory tree: depth-first remove all children (files
// directly, sub-directories via recursion), then the directory itself. The core
// RemoveDirectory refuses a non-empty directory, so WebDAV DELETE on a
// collection must clear it first. Returns false and sets `err` on the first
// failure.
bool removeTreeRecursive(GRPCClientWrapper* grpc,
                         const std::string& dir_uid,
                         const fileengine_rpc::AuthenticationContext& auth,
                         std::string& err) {
    fileengine_rpc::ListDirectoryRequest lr;
    lr.set_uid(dir_uid);
    *lr.mutable_auth() = auth;
    auto listing = grpc->listDirectory(lr);
    if (!listing.success()) { err = listing.error(); return false; }

    for (const auto& entry : listing.entries()) {
        if (entry.type() == fileengine_rpc::DIRECTORY) {
            if (!removeTreeRecursive(grpc, entry.uid(), auth, err)) return false;
        } else {
            fileengine_rpc::RemoveFileRequest rf;
            rf.set_uid(entry.uid());
            *rf.mutable_auth() = auth;
            auto rr = grpc->removeFile(rf);
            if (!rr.success()) { err = rr.error(); return false; }
        }
    }

    fileengine_rpc::RemoveDirectoryRequest rd;
    rd.set_uid(dir_uid);
    *rd.mutable_auth() = auth;
    auto rdr = grpc->removeDirectory(rd);
    if (!rdr.success()) { err = rdr.error(); return false; }
    return true;
}
}  // namespace

void WebDAVRequestHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string method = request.getMethod();
    std::string uri = request.getURI();

    webdav::debugLog("WebDAVRequestHandler: Processing request - Method: " + method + ", URI: " + uri + ", Client: " + request.clientAddress().toString());

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);

    // Set default tenant if none found
    if (tenant.empty()) {
        tenant = "default";
    }

    webdav::debugLog("WebDAVRequestHandler: Resolved tenant: " + tenant + " from host: " + host);

    // Route to appropriate handler based on method
    if (method == "GET" || method == "HEAD") {
        webdav::debugLog("WebDAVRequestHandler: Routing to GET/HEAD handler");
        handleGet(request, response);
    } else if (method == "PUT") {
        webdav::debugLog("WebDAVRequestHandler: Routing to PUT handler");
        handlePut(request, response);
    } else if (method == "MKCOL") {
        webdav::debugLog("WebDAVRequestHandler: Routing to MKCOL handler");
        handleMkcol(request, response);
    } else if (method == "DELETE") {
        webdav::debugLog("WebDAVRequestHandler: Routing to DELETE handler");
        handleDelete(request, response);
    } else if (method == "PROPFIND") {
        webdav::debugLog("WebDAVRequestHandler: Routing to PROPFIND handler");
        handlePropfind(request, response);
    } else if (method == "PROPPATCH") {
        webdav::debugLog("WebDAVRequestHandler: Routing to PROPPATCH handler");
        handleProppatch(request, response);
    } else if (method == "COPY") {
        webdav::debugLog("WebDAVRequestHandler: Routing to COPY handler");
        handleCopy(request, response);
    } else if (method == "MOVE") {
        webdav::debugLog("WebDAVRequestHandler: Routing to MOVE handler");
        handleMove(request, response);
    } else if (method == "LOCK") {
        webdav::debugLog("WebDAVRequestHandler: Routing to LOCK handler");
        handleLock(request, response);
    } else if (method == "UNLOCK") {
        webdav::debugLog("WebDAVRequestHandler: Routing to UNLOCK handler");
        handleUnlock(request, response);
    } else if (method == "OPTIONS") {
        webdav::debugLog("WebDAVRequestHandler: Routing to OPTIONS handler");
        handleOptions(request, response);
    } else {
        webdav::debugLog("WebDAVRequestHandler: Unsupported method: " + method + " for URI: " + uri);
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
        response.setReason("Method Not Implemented");
        response.setContentType("text/plain");
        response.setContentLength(0);
        response.send();
    }

    webdav::debugLog("WebDAVRequestHandler: Completed request processing - Method: " + method + ", URI: " + uri);
}

void WebDAVRequestHandler::handleGet(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // Create authentication context for gRPC
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx.add_roles(role);
    }

    // Resolve path to UUID (walks the tree on a cache miss).
    std::optional<std::string> resolved = path_resolver_->resolvePath(path, auth_ctx);
    if (!resolved) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
        response.setReason("Not Found");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "File not found: " << path;
        return;
    }
    std::string file_uuid = *resolved;

    // Create gRPC request to get file
    fileengine_rpc::GetFileRequest get_req;
    get_req.set_uid(file_uuid);
    *get_req.mutable_auth() = auth_ctx;

    // Call gRPC service to get file content
    fileengine_rpc::GetFileResponse get_resp;
    try {
        get_resp = grpc_client_->getFile(get_req);
    } catch (const std::exception& e) {
        webdav::errorLog("Exception during gRPC GetFile call: " + std::string(e.what()));
        response.setStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);
        response.setReason("Service Unavailable");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "gRPC service unavailable";
        return;
    }

    if (!get_resp.success()) {
        webdav::errorLog("Failed to get file: " + get_resp.error());
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to retrieve file: " << get_resp.error();
        return;
    }

    // Return the file content
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    response.setContentType("application/octet-stream"); // Default content type
    response.setContentLength(get_resp.data().size());
    std::ostream& ostr = response.send();
    ostr.write(get_resp.data().c_str(), get_resp.data().size());
}

void WebDAVRequestHandler::handlePut(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // Create authentication context for gRPC
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx.add_roles(role);
    }

    // Get request body
    std::istream& istr = request.stream();
    std::string content;
    Poco::StreamCopier::copyToString(istr, content);

    // Check if the parent directory exists by resolving the parent path
    // Remove trailing slash if present (but keep root as "/")
    std::string clean_path = path;
    if (clean_path.length() > 1 && clean_path.back() == '/') {
        clean_path.pop_back();
    }

    // Find parent path by getting everything up to the last slash
    std::string parent_path;
    size_t last_slash = clean_path.find_last_of('/');
    if (last_slash == 0) {
        parent_path = "/";  // Parent of "/something" is root
    } else if (last_slash != std::string::npos) {
        parent_path = clean_path.substr(0, last_slash);
        if (parent_path.empty()) {
            parent_path = "/";  // Handle edge case
        }
    } else {
        parent_path = "/";  // Default to root if no slash found
    }

    // Resolve the parent (walks the tree on a cache miss). Root resolves to the
    // empty UID; only a non-existent parent is a 409.
    std::optional<std::string> parent_resolved = path_resolver_->resolvePath(parent_path, auth_ctx);
    if (!parent_resolved) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT); // 409 Conflict - parent doesn't exist
        response.setReason("Conflict");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Parent directory does not exist: " << parent_path;
        return;
    }
    std::string parent_uuid = *parent_resolved;

    // Extract filename from path
    std::string filename = clean_path.substr(clean_path.find_last_of('/') + 1);

    // Create gRPC request to put file
    fileengine_rpc::PutFileRequest put_req;
    put_req.set_data(content);
    put_req.set_uid(""); // Will be assigned by the server
    *put_req.mutable_auth() = auth_ctx;

    // Create the file via touch if it does not already exist, then write content.
    std::optional<std::string> file_resolved = path_resolver_->resolvePath(path, auth_ctx);
    std::string file_uuid = file_resolved.value_or("");
    if (!file_resolved) {
        // File doesn't exist, create it first
        fileengine_rpc::TouchRequest touch_req;
        touch_req.set_parent_uid(parent_uuid);
        touch_req.set_name(filename);
        *touch_req.mutable_auth() = auth_ctx;

        fileengine_rpc::TouchResponse touch_resp = grpc_client_->touch(touch_req);
        if (!touch_resp.success()) {
            webdav::errorLog("Failed to create file: " + touch_resp.error());
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Internal Server Error");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Failed to create file: " << touch_resp.error();
            return;
        }
        file_uuid = touch_resp.uid();
    }

    // Update the file content
    put_req.set_uid(file_uuid);
    fileengine_rpc::PutFileResponse put_resp = grpc_client_->putFile(put_req);

    if (!put_resp.success()) {
        webdav::errorLog("Failed to put file: " + put_resp.error());
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to store file: " << put_resp.error();
        return;
    }

    // Create path mapping for the new file
    path_resolver_->createPathMapping(path, file_uuid, tenant);

    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "Successfully stored file: " << path << " (size: " << content.length() << " bytes)";
}

void WebDAVRequestHandler::handleMkcol(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // Create authentication context for gRPC
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx.add_roles(role);
    }

    // Check if the parent directory exists by resolving the parent path
    // Remove trailing slash if present (but keep root as "/")
    std::string clean_path = path;
    if (clean_path.length() > 1 && clean_path.back() == '/') {
        clean_path.pop_back();
    }

    // Find parent path by getting everything up to the last slash
    std::string parent_path;
    size_t last_slash = clean_path.find_last_of('/');
    if (last_slash == 0) {
        parent_path = "/";  // Parent of "/something" is root
    } else if (last_slash != std::string::npos) {
        parent_path = clean_path.substr(0, last_slash);
        if (parent_path.empty()) {
            parent_path = "/";  // Handle edge case
        }
    } else {
        parent_path = "/";  // Default to root if no slash found
    }

    // Resolve the parent (walks the tree on a cache miss). Root resolves to the
    // empty UID; only a non-existent parent is a 409.
    std::optional<std::string> parent_resolved = path_resolver_->resolvePath(parent_path, auth_ctx);
    if (!parent_resolved) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT); // 409 Conflict - parent doesn't exist
        response.setReason("Conflict");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Parent directory does not exist: " << parent_path;
        return;
    }
    std::string parent_uuid = *parent_resolved;

    // Extract directory name from path
    std::string dirname = clean_path.substr(clean_path.find_last_of('/') + 1);

    // Create gRPC request to make directory
    fileengine_rpc::MakeDirectoryRequest mkcol_req;
    mkcol_req.set_parent_uid(parent_uuid);
    mkcol_req.set_name(dirname);
    *mkcol_req.mutable_auth() = auth_ctx;

    // Call gRPC service to create directory
    fileengine_rpc::MakeDirectoryResponse mkcol_resp = grpc_client_->makeDirectory(mkcol_req);

    if (!mkcol_resp.success()) {
        webdav::errorLog("Failed to create directory: " + mkcol_resp.error());
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to create directory: " << mkcol_resp.error();
        return;
    }

    // Create path mapping for the new directory
    path_resolver_->createPathMapping(path, mkcol_resp.uid(), tenant);

    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "Successfully created directory: " << path;
}

void WebDAVRequestHandler::handleDelete(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // Create authentication context for gRPC
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx.add_roles(role);
    }

    // Resolve path to UUID (walks the tree on a cache miss).
    std::optional<std::string> resolved = path_resolver_->resolvePath(path, auth_ctx);
    if (!resolved || resolved->empty()) {
        // Not found, or the root itself (which cannot be deleted) => 404.
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
        response.setReason("Not Found");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Resource not found: " << path;
        return;
    }
    std::string resource_uuid = *resolved;

    // Determine if it's a file or directory by getting its info
    fileengine_rpc::StatRequest stat_req;
    stat_req.set_uid(resource_uuid);
    *stat_req.mutable_auth() = auth_ctx;

    fileengine_rpc::StatResponse stat_resp = grpc_client_->stat(stat_req);

    if (!stat_resp.success()) {
        webdav::errorLog("Failed to get resource info: " + stat_resp.error());
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to get resource info: " << stat_resp.error();
        return;
    }

    // Delete based on type. Collections are removed recursively (the core's
    // RemoveDirectory refuses a non-empty directory), per RFC 4918 §9.6.
    if (stat_resp.info().type() == fileengine_rpc::DIRECTORY) {
        std::string err;
        if (!removeTreeRecursive(grpc_client_.get(), resource_uuid, auth_ctx, err)) {
            webdav::errorLog("Failed to delete directory tree: " + err);
            Poco::Net::HTTPResponse::HTTPStatus status = Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR;
            if (err.find("permission") != std::string::npos) status = Poco::Net::HTTPResponse::HTTP_FORBIDDEN;
            response.setStatus(status);
            response.setReason("Delete Failed");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Failed to delete directory: " << err;
            return;
        }
    } else {
        // It's a file, use RemoveFile
        fileengine_rpc::RemoveFileRequest rm_req;
        rm_req.set_uid(resource_uuid);
        *rm_req.mutable_auth() = auth_ctx;

        fileengine_rpc::RemoveFileResponse rm_resp = grpc_client_->removeFile(rm_req);

        if (!rm_resp.success()) {
            webdav::errorLog("Failed to delete file: " + rm_resp.error());
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Internal Server Error");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Failed to delete file: " << rm_resp.error();
            return;
        }
    }

    // Remove path mapping from cache
    path_resolver_->removePathMapping(path, tenant);

    response.setStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT);
    response.setReason("No Content");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "Successfully deleted: " << path;
}

void WebDAVRequestHandler::handlePropfind(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();
    // WebDAV clients enter a collection by requesting it with a trailing slash
    // ("/Test1/"); drop it so the path matches the cached mapping ("/Test1") and
    // child hrefs/cache keys below are built without a doubled slash. Root stays "/".
    if (path.size() > 1 && path.back() == '/') path.pop_back();
    // RFC 4918 §9.1 Depth: "0" = the resource only, "1" = resource + children.
    // Clients (e.g. cadaver) issue a Depth:0 PROPFIND on connect and expect a
    // single <D:response>; returning children there overflows their parser.
    std::string depth = request.get("Depth", "1");
    webdav::debugLog("handlePropfind: Processing PROPFIND request for path: " + path + ", Depth: " + depth);

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    webdav::debugLog("handlePropfind: Resolved tenant: " + tenant);

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    webdav::debugLog("handlePropfind: Starting authentication process");
    if (!authenticateUser(request, user, tenant, roles)) {
        webdav::debugLog("handlePropfind: Authentication failed");
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("application/xml");
        std::ostream& ostr = response.send();
        ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        ostr << "<D:error xmlns:D=\"DAV:\"/>";
        return;
    }
    webdav::debugLog("handlePropfind: Authentication successful for user: " + user + " with " + std::to_string(roles.size()) + " roles");

    // Create authentication context for gRPC
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    webdav::debugLog("handlePropfind: Building authentication context with user: " + user + ", tenant: " + tenant);

    for (const auto& role : roles) {
        auth_ctx.add_roles(role);
        webdav::debugLog("handlePropfind: Added role to auth context: " + role);
    }
    webdav::debugLog("handlePropfind: Auth context built with " + std::to_string(auth_ctx.roles_size()) + " roles");

    // Resolve path to UUID (walks the tree on a cache miss). A genuinely missing
    // path now returns 404 instead of silently falling back to the root listing.
    webdav::debugLog("handlePropfind: Resolving path to UUID: " + path);
    std::optional<std::string> resolved = path_resolver_->resolvePath(path, auth_ctx);
    if (!resolved) {
        webdav::debugLog("handlePropfind: path not found: " + path);
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
        response.setReason("Not Found");
        response.setContentType("application/xml");
        std::ostream& ostr = response.send();
        ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        ostr << "<D:error xmlns:D=\"DAV:\"/>";
        return;
    }
    std::string dir_uuid = *resolved;
    webdav::debugLog("handlePropfind: Path resolution result - UUID: " + dir_uuid);

    // If the target is a file (not the root, and Stat says it is not a
    // directory), respond with a single file resource and stop. Otherwise the
    // code below would advertise it as a <D:collection/> and list its (non-
    // existent) children, so WebDAV clients render the file as an empty folder.
    if (path != "/" && !dir_uuid.empty()) {
        fileengine_rpc::StatRequest stat_req;
        stat_req.set_uid(dir_uuid);
        *stat_req.mutable_auth() = auth_ctx;
        fileengine_rpc::StatResponse stat_resp;
        try {
            stat_resp = grpc_client_->stat(stat_req);
        } catch (const std::exception& e) {
            webdav::errorLog("handlePropfind: Stat threw: " + std::string(e.what()));
        }
        if (stat_resp.success() && stat_resp.info().type() != fileengine_rpc::DIRECTORY) {
            const auto& info = stat_resp.info();
            webdav::debugLog("handlePropfind: target is a file, returning single file response");
            response.setStatus(Poco::Net::HTTPResponse::HTTP_MULTI_STATUS);
            response.setReason("Multi-Status");
            response.setContentType("application/xml; charset=utf-8");
            std::ostream& ostr = response.send();
            ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
            ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
            ostr << "  <D:response>\n";
            ostr << "    <D:href>" << path << "</D:href>\n";
            ostr << "    <D:propstat>\n";
            ostr << "      <D:prop>\n";
            ostr << "        <D:displayname>" << info.name() << "</D:displayname>\n";
            ostr << "        <D:resourcetype/>\n";
            ostr << "        <D:getcontenttype>application/octet-stream</D:getcontenttype>\n";
            ostr << "        <D:getcontentlength>" << std::to_string(info.size()) << "</D:getcontentlength>\n";
            ostr << "        <D:creationdate>" << isoDate(info.created_at()) << "</D:creationdate>\n";
            ostr << "        <D:getlastmodified>" << httpDate(info.modified_at()) << "</D:getlastmodified>\n";
            ostr << "      </D:prop>\n";
            ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
            ostr << "    </D:propstat>\n";
            ostr << "  </D:response>\n";
            ostr << "</D:multistatus>\n";
            return;
        }
    }

    // Create gRPC request to list directory
    fileengine_rpc::ListDirectoryRequest list_req;
    list_req.set_uid(dir_uuid);
    *list_req.mutable_auth() = auth_ctx;
    webdav::debugLog("handlePropfind: Created gRPC ListDirectory request with UUID: " + dir_uuid +
                     ", auth user: " + auth_ctx.user() + ", auth tenant: " + auth_ctx.tenant() +
                     ", auth roles count: " + std::to_string(auth_ctx.roles_size()));

    // Call gRPC service to list directory contents
    webdav::debugLog("handlePropfind: Making gRPC ListDirectory call");
    fileengine_rpc::ListDirectoryResponse list_resp;
    try {
        list_resp = grpc_client_->listDirectory(list_req);
        webdav::debugLog("handlePropfind: gRPC ListDirectory call completed successfully");
    } catch (const std::exception& e) {
        webdav::errorLog("Exception during gRPC ListDirectory call: " + std::string(e.what()));
        response.setStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);
        response.setReason("Service Unavailable");
        response.setContentType("application/xml");
        std::ostream& ostr = response.send();
        ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        ostr << "<D:error xmlns:D=\"DAV:\">gRPC service unavailable</D:error>";
        return;
    }

    if (!list_resp.success()) {
        webdav::errorLog("handlePropfind: gRPC ListDirectory failed: " + list_resp.error());
        // If gRPC call failed, return an empty directory listing instead of error to allow cadaver to work
        response.setStatus(Poco::Net::HTTPResponse::HTTP_MULTI_STATUS);
        response.setReason("Multi-Status");
        response.setContentType("application/xml; charset=utf-8");
        std::ostream& ostr = response.send();

        ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
        ostr << "  <D:response>\n";
        ostr << "    <D:href>" << path << "</D:href>\n";
        ostr << "    <D:propstat>\n";
        ostr << "      <D:prop>\n";
        ostr << "        <D:displayname>" << (path.empty() || path == "/" ? "Root Directory" : path.substr(path.find_last_of('/') + 1)) << "</D:displayname>\n";
        ostr << "        <D:resourcetype><D:collection/></D:resourcetype>\n";
        ostr << "        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n";
        ostr << "        <D:creationdate>" << isoDate(std::time(nullptr)) << "</D:creationdate>\n";
        ostr << "        <D:getlastmodified>" << httpDate(std::time(nullptr)) << "</D:getlastmodified>\n";
        ostr << "      </D:prop>\n";
        ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
        ostr << "    </D:propstat>\n";
        ostr << "  </D:response>\n";
        ostr << "</D:multistatus>\n";
        return;
    }

    webdav::debugLog("handlePropfind: gRPC ListDirectory succeeded, got " + std::to_string(list_resp.entries_size()) + " entries");

    // Build XML response with actual directory contents from gRPC
    response.setStatus(Poco::Net::HTTPResponse::HTTP_MULTI_STATUS);
    response.setReason("Multi-Status");
    response.setContentType("application/xml; charset=utf-8");
    std::ostream& ostr = response.send();

    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";

    // Add the requested directory itself
    ostr << "  <D:response>\n";
    ostr << "    <D:href>" << path << "</D:href>\n";
    ostr << "    <D:propstat>\n";
    ostr << "      <D:prop>\n";
    ostr << "        <D:displayname>" << (path.empty() || path == "/" ? "Root Directory" : path.substr(path.find_last_of('/') + 1)) << "</D:displayname>\n";
    ostr << "        <D:resourcetype><D:collection/></D:resourcetype>\n";
    ostr << "        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n";
    ostr << "        <D:creationdate>" << isoDate(std::time(nullptr)) << "</D:creationdate>\n";
    ostr << "        <D:getlastmodified>" << httpDate(std::time(nullptr)) << "</D:getlastmodified>\n";
    ostr << "      </D:prop>\n";
    ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
    ostr << "    </D:propstat>\n";
    ostr << "  </D:response>\n";

    // Add directory entries from gRPC response (Depth: 0 => target only).
    for (const auto& entry : list_resp.entries()) {
        if (depth == "0") break;
        std::string entry_path = path.empty() || path == "/" ? "/" + entry.name() : path + "/" + entry.name();

        ostr << "  <D:response>\n";
        ostr << "    <D:href>" << entry_path << "</D:href>\n";
        ostr << "    <D:propstat>\n";
        ostr << "      <D:prop>\n";
        ostr << "        <D:displayname>" << entry.name() << "</D:displayname>\n";

        // Set resource type based on entry type
        if (entry.type() == fileengine_rpc::DIRECTORY) {
            ostr << "        <D:resourcetype><D:collection/></D:resourcetype>\n";
        } else {
            ostr << "        <D:resourcetype></D:resourcetype>\n";
        }

        // Set content type based on entry type
        if (entry.type() == fileengine_rpc::DIRECTORY) {
            ostr << "        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n";
        } else {
            ostr << "        <D:getcontenttype>application/octet-stream</D:getcontenttype>\n";
        }

        ostr << "        <D:creationdate>" << isoDate(entry.created_at()) << "</D:creationdate>\n";
        ostr << "        <D:getlastmodified>" << httpDate(entry.modified_at()) << "</D:getlastmodified>\n";
        if (entry.type() != fileengine_rpc::DIRECTORY) {
            ostr << "        <D:getcontentlength>" << std::to_string(entry.size()) << "</D:getcontentlength>\n";
        }
        ostr << "      </D:prop>\n";
        ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
        ostr << "    </D:propstat>\n";
        ostr << "  </D:response>\n";

        // Create path mapping for future reference
        path_resolver_->createPathMapping(entry_path, entry.uid(), tenant);
        webdav::debugLog("handlePropfind: Created path mapping - path: " + entry_path + ", UUID: " + entry.uid());
    }

    ostr << "</D:multistatus>\n";
    webdav::debugLog("handlePropfind: Completed PROPFIND request for path: " + path);
}

void WebDAVRequestHandler::handleProppatch(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // For now, return a simple response
    // In a real implementation, this would handle property updates
    response.setStatus(Poco::Net::HTTPResponse::HTTP_MULTI_STATUS);
    response.setReason("Multi-Status");
    response.setContentType("application/xml; charset=utf-8");
    std::ostream& ostr = response.send();

    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
    ostr << "  <D:response>\n";
    ostr << "    <D:href>" << path << "</D:href>\n";
    ostr << "    <D:propstat>\n";
    ostr << "      <D:prop>\n";
    ostr << "        <D:displayname/>\n";
    ostr << "      </D:prop>\n";
    ostr << "      <D:status>HTTP/1.1 424 Failed Dependency</D:status>\n";
    ostr << "    </D:propstat>\n";
    ostr << "  </D:response>\n";
    ostr << "</D:multistatus>\n";
}

void WebDAVRequestHandler::handleCopy(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string destination = request.get("Destination", "");
    if (destination.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        response.setReason("Bad Request");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Missing Destination header";
        return;
    }

    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string source_path = poco_uri.getPath();

    Poco::URI dest_uri(destination);
    std::string dest_path = dest_uri.getPath();

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // Build the gRPC auth context.
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    for (const auto& role : roles) auth_ctx.add_roles(role);

    auto strip_slash = [](std::string p) {
        if (p.size() > 1 && p.back() == '/') p.pop_back();
        return p;
    };
    source_path = strip_slash(source_path);
    dest_path = strip_slash(dest_path);

    auto split_path = [](const std::string& p, std::string& parent, std::string& name) {
        size_t pos = p.find_last_of('/');
        parent = (pos == std::string::npos || pos == 0) ? "/" : p.substr(0, pos);
        name = (pos == std::string::npos) ? p : p.substr(pos + 1);
    };
    std::string src_parent, src_name, dst_parent, dst_name;
    split_path(source_path, src_parent, src_name);
    split_path(dest_path, dst_parent, dst_name);
    if (dst_name.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        response.setReason("Bad Request");
        std::ostream& ostr = response.send();
        ostr << "Invalid Destination";
        return;
    }

    // Resolve source and destination parent.
    std::optional<std::string> src = path_resolver_->resolvePath(source_path, auth_ctx);
    if (!src || src->empty()) {
        webdav::debugLog("handleCopy: source not found: " + source_path);
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
        response.setReason("Not Found");
        std::ostream& ostr = response.send();
        ostr << "Source not found";
        return;
    }
    std::optional<std::string> dparent = path_resolver_->resolvePath(dst_parent, auth_ctx);
    if (!dparent) {
        webdav::debugLog("handleCopy: destination parent not found: " + dst_parent);
        response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT);
        response.setReason("Conflict");
        std::ostream& ostr = response.send();
        ostr << "Destination parent does not exist";
        return;
    }

    // The core copies a node into a parent keeping the source name, and
    // CopyResponse carries no uid. To support a renamed copy (and stay correct
    // when names collide), snapshot the destination parent's child uids, copy,
    // then diff to find the new node and rename it.
    auto list_uids = [&](const std::string& dir_uid, std::set<std::string>& out) -> bool {
        fileengine_rpc::ListDirectoryRequest lr;
        lr.set_uid(dir_uid);
        *lr.mutable_auth() = auth_ctx;
        auto resp = grpc_client_->listDirectory(lr);
        if (!resp.success()) return false;
        for (const auto& e : resp.entries()) out.insert(e.uid());
        return true;
    };
    std::set<std::string> before;
    bool need_rename = (dst_name != src_name);
    if (need_rename) list_uids(*dparent, before);

    auto map_error = [](const std::string& err) {
        if (err.find("permission") != std::string::npos) return Poco::Net::HTTPResponse::HTTP_FORBIDDEN;
        if (err.find("not exist") != std::string::npos || err.find("not found") != std::string::npos)
            return Poco::Net::HTTPResponse::HTTP_NOT_FOUND;
        if (err.find("already") != std::string::npos) return Poco::Net::HTTPResponse::HTTP_CONFLICT;
        return Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR;
    };

    webdav::debugLog("handleCopy: copy '" + source_path + "' -> parent '" + dst_parent + "'");
    fileengine_rpc::CopyRequest cq;
    cq.set_source_uid(*src);
    cq.set_destination_parent_uid(*dparent);
    *cq.mutable_auth() = auth_ctx;
    auto cr = grpc_client_->copy(cq);
    if (!cr.success()) {
        webdav::errorLog("handleCopy: copy failed: " + cr.error());
        response.setStatus(map_error(cr.error()));
        response.setReason("Copy Failed");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Copy failed: " << cr.error();
        return;
    }

    if (need_rename) {
        std::set<std::string> after;
        list_uids(*dparent, after);
        std::string new_uid;
        for (const auto& u : after) {
            if (!before.count(u)) { new_uid = u; break; }
        }
        if (new_uid.empty()) {
            webdav::errorLog("handleCopy: could not identify the copied node to rename");
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Copy Incomplete");
            std::ostream& ostr = response.send();
            ostr << "Copy succeeded but the new node could not be renamed";
            return;
        }
        fileengine_rpc::RenameRequest rq;
        rq.set_uid(new_uid);
        rq.set_new_name(dst_name);
        *rq.mutable_auth() = auth_ctx;
        auto rr = grpc_client_->rename(rq);
        if (!rr.success()) {
            webdav::errorLog("handleCopy: rename of copy failed: " + rr.error());
            response.setStatus(map_error(rr.error()));
            response.setReason("Copy Failed");
            std::ostream& ostr = response.send();
            ostr << "Copy rename failed: " << rr.error();
            return;
        }
        path_resolver_->createPathMapping(dest_path, new_uid, tenant);
    }

    webdav::debugLog("handleCopy: completed '" + source_path + "' -> '" + dest_path + "'");
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentLength(0);
    response.send();
}

void WebDAVRequestHandler::handleMove(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string destination = request.get("Destination", "");
    if (destination.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        response.setReason("Bad Request");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Missing Destination header";
        return;
    }

    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string source_path = poco_uri.getPath();

    Poco::URI dest_uri(destination);
    std::string dest_path = dest_uri.getPath();

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // Build the gRPC auth context.
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    for (const auto& role : roles) auth_ctx.add_roles(role);

    // Normalize: drop a trailing slash (clients address collections as "/x/").
    auto strip_slash = [](std::string p) {
        if (p.size() > 1 && p.back() == '/') p.pop_back();
        return p;
    };
    source_path = strip_slash(source_path);
    dest_path = strip_slash(dest_path);

    // Split a path into (parent, name).
    auto split_path = [](const std::string& p, std::string& parent, std::string& name) {
        size_t pos = p.find_last_of('/');
        parent = (pos == std::string::npos || pos == 0) ? "/" : p.substr(0, pos);
        name = (pos == std::string::npos) ? p : p.substr(pos + 1);
    };

    std::string src_parent, src_name, dst_parent, dst_name;
    split_path(source_path, src_parent, src_name);
    split_path(dest_path, dst_parent, dst_name);
    if (dst_name.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        response.setReason("Bad Request");
        std::ostream& ostr = response.send();
        ostr << "Invalid Destination";
        return;
    }

    // Resolve the source node.
    std::optional<std::string> src = path_resolver_->resolvePath(source_path, auth_ctx);
    if (!src || src->empty()) {
        webdav::debugLog("handleMove: source not found: " + source_path);
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
        response.setReason("Not Found");
        std::ostream& ostr = response.send();
        ostr << "Source not found";
        return;
    }
    const std::string source_uid = *src;

    bool ok = false;
    std::string err;
    if (src_parent == dst_parent) {
        // Same parent → a pure rename.
        webdav::debugLog("handleMove: rename '" + source_path + "' -> '" + dst_name + "'");
        fileengine_rpc::RenameRequest rq;
        rq.set_uid(source_uid);
        rq.set_new_name(dst_name);
        *rq.mutable_auth() = auth_ctx;
        auto r = grpc_client_->rename(rq);
        ok = r.success();
        err = r.error();
    } else {
        // Different parent → move, then rename if the name also changed.
        std::optional<std::string> dparent = path_resolver_->resolvePath(dst_parent, auth_ctx);
        if (!dparent) {
            webdav::debugLog("handleMove: destination parent not found: " + dst_parent);
            response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT);
            response.setReason("Conflict");
            std::ostream& ostr = response.send();
            ostr << "Destination parent does not exist";
            return;
        }
        webdav::debugLog("handleMove: move '" + source_path + "' -> parent '" + dst_parent + "'");
        fileengine_rpc::MoveRequest mq;
        mq.set_source_uid(source_uid);
        mq.set_destination_parent_uid(*dparent);
        *mq.mutable_auth() = auth_ctx;
        auto mr = grpc_client_->move(mq);
        ok = mr.success();
        err = mr.error();
        if (ok && dst_name != src_name) {
            fileengine_rpc::RenameRequest rq;
            rq.set_uid(source_uid);
            rq.set_new_name(dst_name);
            *rq.mutable_auth() = auth_ctx;
            auto r = grpc_client_->rename(rq);
            ok = r.success();
            err = r.error();
        }
    }

    if (!ok) {
        webdav::errorLog("handleMove: failed: " + err);
        // Map the core error to an HTTP status.
        Poco::Net::HTTPResponse::HTTPStatus status = Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR;
        if (err.find("permission") != std::string::npos) status = Poco::Net::HTTPResponse::HTTP_FORBIDDEN;
        else if (err.find("not exist") != std::string::npos || err.find("not found") != std::string::npos)
            status = Poco::Net::HTTPResponse::HTTP_NOT_FOUND;
        else if (err.find("already") != std::string::npos) status = Poco::Net::HTTPResponse::HTTP_CONFLICT;
        response.setStatus(status);
        response.setReason("Move Failed");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Move failed: " << err;
        return;
    }

    // Keep the path cache consistent (uid is unchanged by rename/move).
    path_resolver_->removePathMapping(source_path, tenant);
    path_resolver_->createPathMapping(dest_path, source_uid, tenant);

    webdav::debugLog("handleMove: completed '" + source_path + "' -> '" + dest_path + "'");
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentLength(0);
    response.send();
}

void WebDAVRequestHandler::handleLock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // Since FileEngine is pervasively versioned and immutable, traditional file locking doesn't apply
    // We'll implement a minimal lock response for client compatibility
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    response.setContentType("application/xml");
    std::ostream& ostr = response.send();

    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:prop xmlns:D=\"DAV:\">\n";
    ostr << "  <D:lockdiscovery>\n";
    ostr << "    <D:activelock>\n";
    ostr << "      <D:locktype><D:write/></D:locktype>\n";
    ostr << "      <D:lockscope><D:exclusive/></D:lockscope>\n";
    ostr << "      <D:depth>infinity</D:depth>\n";
    ostr << "      <D:timeout>Second-600</D:timeout>\n";
    ostr << "      <D:locktoken>\n";
    ostr << "        <D:href>opaquelocktoken:" << "dummy-lock-token" << "</D:href>\n";
    ostr << "      </D:locktoken>\n";
    ostr << "      <D:owner>\n";
    ostr << "        <D:href>User</D:href>\n";
    ostr << "      </D:owner>\n";
    ostr << "    </D:activelock>\n";
    ostr << "  </D:lockdiscovery>\n";
    ostr << "</D:prop>\n";
}

void WebDAVRequestHandler::handleUnlock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // Since FileEngine is pervasively versioned and immutable, traditional file unlocking doesn't apply
    // We'll return a success response for client compatibility
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT);
    response.setReason("No Content");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
}

void WebDAVRequestHandler::handleOptions(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // WebDAV requires the OPTIONS method to return specific headers
    // OPTIONS should not require authentication as it's used for discovery
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");

    // Set WebDAV-specific headers
    response.set("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, MKCOL, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK");
    response.set("DAV", "1, 2");
    response.set("MS-Author-Via", "DAV");
    response.set("Accept-Ranges", "bytes");
    response.set("Content-Length", "0");

    // Set CORS headers to allow cross-origin requests
    response.set("Access-Control-Allow-Origin", "*");
    response.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, MKCOL, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK");
    response.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Depth, Overwrite");

    // Send empty response body
    response.setContentType("text/plain");
    response.setContentLength(0);
    response.send();
}

std::string WebDAVRequestHandler::extractTenantFromHost(const std::string& host) {
    return webdav::extractTenantFromHostname(host);
}

bool WebDAVRequestHandler::authenticateUser(Poco::Net::HTTPServerRequest& request, std::string& user, std::string& tenant, std::vector<std::string>& roles) {
    // Check for Authorization header
    std::string auth_header = request.get("Authorization", "");
    webdav::debugLog("authenticateUser: Processing authentication request with auth header length: " + std::to_string(auth_header.length()));

    if (auth_header.empty()) {
        webdav::debugLog("authenticateUser: No Authorization header found in request");
        return false;
    }

    // Handle Basic Authentication
    if (auth_header.substr(0, 5) == "Basic") {
        webdav::debugLog("authenticateUser: Processing Basic authentication for user");
        std::string encoded_credentials = trim(auth_header.substr(6));
        webdav::debugLog("authenticateUser: Encoded credentials: " + encoded_credentials);

        // Decode Base64 credentials
        std::istringstream istr(encoded_credentials);
        std::ostringstream ostr;
        Poco::Base64Decoder b64in(istr);
        Poco::StreamCopier::copyStream(b64in, ostr);
        std::string credentials = ostr.str();
        webdav::debugLog("authenticateUser: Decoded credentials: " + credentials);

        size_t colon_pos = credentials.find(':');
        if (colon_pos == std::string::npos) {
            webdav::debugLog("authenticateUser: Invalid credentials format - no colon found");
            return false;
        }

        std::string username = credentials.substr(0, colon_pos);
        std::string password = credentials.substr(colon_pos + 1);
        webdav::debugLog("authenticateUser: Extracted username: " + username + ", password length: " + std::to_string(password.length()));

        webdav::debugLog("authenticateUser: Attempting to authenticate user: " + username);

        // Authenticate with LDAP
        webdav::debugLog("authenticateUser: Calling LDAP authenticator for user: " + username);
        UserInfo user_info = ldap_auth_->authenticateUser(username, password);
        webdav::debugLog("authenticateUser: LDAP authentication returned - authenticated: " + std::to_string(user_info.authenticated) +
                         ", user_id: " + user_info.user_id + ", tenant: " + user_info.tenant +
                         ", roles count: " + std::to_string(user_info.roles.size()));

        if (!user_info.authenticated) {
            webdav::debugLog("authenticateUser: LDAP authentication failed for user: " + username);
            return false;
        }

        // Log the roles loaded from LDAP
        std::string roles_str = [&user_info]() {
            std::string roles_list;
            for (size_t i = 0; i < user_info.roles.size(); ++i) {
                if (i > 0) roles_list += ", ";
                roles_list += user_info.roles[i];
            }
            return roles_list.empty() ? "none" : roles_list;
        }();

        webdav::debugLog("authenticateUser: LDAP authentication successful for user: " + username +
                         " (tenant: " + user_info.tenant + ")" +
                         " with roles: [" + roles_str + "]");

        user = user_info.user_id;
        // Tenant is host-driven (subdomain -> tenant; "default" in non-subdomain
        // mode). Do NOT override it with the LDAP user-DN OU — the directory
        // layout puts users under ou=users, which is not a tenant. The LDAP
        // authenticator supplies only the user identity and roles.
        roles = user_info.roles;

        webdav::debugLog("authenticateUser: Setting user: " + user + ", tenant: " + tenant + ", roles count: " + std::to_string(roles.size()));

        return true;
    }

    webdav::debugLog("authenticateUser: Unsupported authentication scheme: " + auth_header.substr(0, auth_header.find(' ')));

    // For now, only Basic authentication is supported
    // Digest authentication would be implemented here if needed
    return false;
}

WebDAVServer::WebDAVServer(const std::string& host, int port)
    : host_(host), port_(port),
      grpc_client_(std::make_shared<GRPCClientWrapper>(webdav::getEnvOrDefault("FILEENGINE_GRPC_HOST", "localhost") + ":" + webdav::getEnvOrDefault("FILEENGINE_GRPC_PORT", "50051"))),
      path_resolver_(std::make_shared<PathResolver>(grpc_client_)),
      ldap_auth_(std::make_shared<LDAPAuthenticator>(
          webdav::getEnvOrDefault("FILEENGINE_LDAP_ENDPOINT", "ldap://localhost:1389"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_DOMAIN", "dc=rationalboxes,dc=com"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_DN", "cn=admin,dc=rationalboxes,dc=com"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_PASSWORD", "admin"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_TENANT_BASE", "ou=tenants,dc=rationalboxes,dc=com"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com")
      )),
      socket_(std::make_unique<Poco::Net::ServerSocket>(port)),
      server_params_(new Poco::Net::HTTPServerParams),
      server_(nullptr) {
    webdav::debugLog("WebDAVServer: Initializing server on " + host + ":" + std::to_string(port));
    webdav::debugLog("WebDAVServer: gRPC client created");
    webdav::debugLog("WebDAVServer: Path resolver created");
    webdav::debugLog("WebDAVServer: LDAP authenticator created");
    webdav::debugLog("WebDAVServer: Server socket created on port " + std::to_string(port));
    server_params_->setKeepAlive(true);
    webdav::debugLog("WebDAVServer: Initialization completed");
}


WebDAVServer::~WebDAVServer() {
    stop();
    // Explicitly reset the server to ensure proper cleanup
    server_.reset();
}

void WebDAVServer::start() {
    webdav::debugLog("WebDAVServer: Starting server on " + host_ + ":" + std::to_string(port_));
    try {
        auto* factory = new WebDAVRequestHandlerFactory(grpc_client_, path_resolver_, ldap_auth_);
        webdav::debugLog("WebDAVServer: Created request handler factory");
        server_ = std::make_unique<Poco::Net::HTTPServer>(factory, *socket_, server_params_);
        webdav::debugLog("WebDAVServer: Created HTTP server instance with socket on port " + std::to_string(port_));
        webdav::debugLog("WebDAVServer: About to call server_->start()");
        server_->start();
        webdav::debugLog("WebDAVServer: Started HTTP server successfully");

        std::cout << "WebDAV server listening on " << host_ << ":" << port_ << std::endl;
    } catch (const std::exception& e) {
        webdav::errorLog("WebDAVServer: Exception in start(): " + std::string(e.what()));
        throw; // Re-throw to be caught by main application
    } catch (...) {
        webdav::errorLog("WebDAVServer: Unknown exception in start()");
        throw; // Re-throw to be caught by main application
    }
}

void WebDAVServer::stop() {
    if (server_) {
        server_->stop();
    }
    if (socket_) {
        socket_->close();
    }
}

} // namespace webdav