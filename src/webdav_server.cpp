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

#include "webdav_server.h"
#include "client_ip.h"

namespace {
// Trusted client IP for a request (same derivation as authenticateUser), stamped on
// the AuthenticationContext forwarded to the core so audit rows carry source_addr.
std::string resolveRequestIp(Poco::Net::HTTPServerRequest& request,
                             const std::vector<std::string>& trusted) {
    std::string peer;
    try { peer = request.clientAddress().host().toString(); } catch (...) {}
    return webdav::resolveClientIp(peer, request.get("X-Forwarded-For", ""), trusted);
}
}  // namespace
#include <string>  // std::stod (failover cooldown parsing)
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
#include <Poco/UUIDGenerator.h>
#include <Poco/UUID.h>
#include <algorithm>
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

// A resource's entity-tag: an Apache-style "<mtime>-<size>" strong validator.
// Stable across reads of an unchanged file and changes whenever the content does
// (mtime and/or size move), so GVfs-backed editors (Bluefish, gedit, ...) can
// track the file across a save. It is deliberately derived from mtime+size —
// fields present on BOTH FileInfo (Stat) and DirectoryEntry (listing) — so the
// SAME file yields the SAME ETag on every surface (single-file PROPFIND, parent
// listing, GET/HEAD, PUT); an inconsistent validator is itself a "changed on
// disk" trigger. Quoted per RFC 7232 §2.3.
std::string makeEtag(std::int64_t modified_at, std::int64_t size) {
    std::ostringstream os;
    os << '"' << std::hex << modified_at << '-' << size << '"';
    return os.str();
}

// Escape a string for safe inclusion in XML text/attribute content, preventing
// response/XML injection via paths or node names reflected into PROPFIND/
// PROPPATCH multistatus bodies. (Security review M5.)
std::string xmlEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c;
        }
    }
    return out;
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
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
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

    // Stat the target so GET/HEAD carry the same validators the file's PROPFIND
    // reports (ETag = mtime+size, Last-Modified). Editors read these on load and
    // must see the identical value after their own save — without them a save
    // spuriously reports "changed on disk". Best-effort: a Stat miss just omits
    // the headers (the body still streams).
    {
        fileengine_rpc::StatRequest sreq;
        sreq.set_uid(file_uuid);
        *sreq.mutable_auth() = auth_ctx;
        try {
            fileengine_rpc::StatResponse sresp = grpc_client_->stat(sreq);
            if (sresp.success()) {
                response.set("ETag", makeEtag(sresp.info().modified_at(), sresp.info().size()));
                response.set("Last-Modified", httpDate(sresp.info().modified_at()));
                // HEAD: headers only, no body (Poco does not suppress it for us).
                if (request.getMethod() == "HEAD") {
                    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                    response.setReason("OK");
                    response.setContentType("application/octet-stream");
                    response.setContentLength(sresp.info().size());
                    response.send();
                    return;
                }
            } else if (request.getMethod() == "HEAD") {
                response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
                response.setReason("OK");
                response.setContentType("application/octet-stream");
                response.setContentLength(0);
                response.send();
                return;
            }
        } catch (const std::exception& e) {
            webdav::debugLog(std::string("handleGet: Stat threw: ") + e.what());
        }
    }

    // Create gRPC request to get file
    fileengine_rpc::GetFileRequest get_req;
    get_req.set_uid(file_uuid);
    *get_req.mutable_auth() = auth_ctx;

    // Stream the content from the core straight to the client in chunks (chunked
    // transfer-encoding) — the whole file is never buffered in the bridge. The
    // 200 header is sent lazily on the first chunk so that a failure before any
    // data still yields a proper error status. The ETag/Last-Modified set above
    // ride along on whichever send() fires first.
    bool headerSent = false;
    std::ostream* ostr = nullptr;
    auto sendHeader = [&]() {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
        response.setReason("OK");
        response.setContentType("application/octet-stream");
        response.setChunkedTransferEncoding(true);
        ostr = &response.send();
        headerSent = true;
    };

    GRPCClientWrapper::DownloadResult dl;
    try {
        dl = grpc_client_->streamFileDownload(get_req, [&](const std::string& chunk) -> bool {
            if (!headerSent) sendHeader();
            ostr->write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
            return ostr->good();
        });
    } catch (const std::exception& e) {
        webdav::errorLog("Exception during gRPC StreamFileDownload call: " + std::string(e.what()));
        if (!headerSent) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);
            response.setReason("Service Unavailable");
            response.setContentType("text/plain");
            response.send() << "gRPC service unavailable";
        }
        return;
    }

    if (!headerSent) {
        // No bytes streamed yet: either an empty file (success) or a failure
        // before any chunk — emit the appropriate status with full headers.
        if (dl.success) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
            response.setReason("OK");
            response.setContentType("application/octet-stream");
            response.setContentLength(0);
            response.send();
        } else {
            webdav::errorLog("Failed to get file: " + dl.error);
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Internal Server Error");
            response.setContentType("text/plain");
            response.send() << "Failed to retrieve file: " << dl.error;
        }
    }
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
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
    for (const auto& role : roles) {
        auth_ctx.add_roles(role);
    }

    // NOTE: the request body is NOT read here. It is streamed straight to the
    // core in chunks below (after the target file exists), so the whole file is
    // never buffered in the bridge.

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

    // Create the file via touch if it does not already exist, then write content.
    std::optional<std::string> file_resolved = path_resolver_->resolvePath(path, auth_ctx);
    const bool existed = file_resolved.has_value();  // 201 Created vs 204 (new revision)
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

    // Stream the body straight to the core in 256 KiB chunks via the
    // client-streaming RPC: the whole file is never held in memory, and no
    // single gRPC message approaches the per-message size cap.
    std::istream& body = request.stream();
    std::vector<char> buf(256 * 1024);
    size_t total_bytes = 0;
    fileengine_rpc::PutFileResponse put_resp = grpc_client_->streamFileUpload(
        file_uuid, auth_ctx, [&](std::string& out) -> bool {
            body.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            std::streamsize n = body.gcount();
            if (n <= 0) return false;
            out.assign(buf.data(), static_cast<size_t>(n));
            total_bytes += static_cast<size_t>(n);
            return true;
        });

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

    // Return the NEW version's validators on the PUT response so the client adopts
    // them as its baseline instead of re-reading and seeing an "unexpected" change
    // (the "changed on disk after my own save" symptom). Stat reflects the version
    // just written; best-effort (a miss simply omits the headers).
    try {
        fileengine_rpc::StatRequest sreq;
        sreq.set_uid(file_uuid);
        *sreq.mutable_auth() = auth_ctx;
        fileengine_rpc::StatResponse sresp = grpc_client_->stat(sreq);
        if (sresp.success()) {
            response.set("ETag", makeEtag(sresp.info().modified_at(), sresp.info().size()));
            response.set("Last-Modified", httpDate(sresp.info().modified_at()));
        }
    } catch (const std::exception& e) {
        webdav::debugLog(std::string("handlePut: post-write Stat threw: ") + e.what());
    }

    // RFC 4918 §9.7.1: 201 when the PUT creates the resource, 204 when it writes a
    // new body to an existing one (a new version here). This mirrors the REST
    // bridge (PUT /v1/files/{uid}/content -> 204) so the same save scenario yields
    // the same status on both doors.
    if (existed) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT);
        response.setReason("No Content");
        response.setContentType("text/plain");
        response.send();
    } else {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
        response.setReason("Created");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Successfully stored file: " << path << " (size: " << total_bytes << " bytes)";
    }
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
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
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
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
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
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
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
            ostr << "    <D:href>" << xmlEscape(path) << "</D:href>\n";
            ostr << "    <D:propstat>\n";
            ostr << "      <D:prop>\n";
            ostr << "        <D:displayname>" << xmlEscape(info.name()) << "</D:displayname>\n";
            ostr << "        <D:resourcetype/>\n";
            ostr << "        <D:getcontenttype>application/octet-stream</D:getcontenttype>\n";
            ostr << "        <D:getcontentlength>" << std::to_string(info.size()) << "</D:getcontentlength>\n";
            ostr << "        <D:creationdate>" << isoDate(info.created_at()) << "</D:creationdate>\n";
            ostr << "        <D:getlastmodified>" << httpDate(info.modified_at()) << "</D:getlastmodified>\n";
            // Emitted raw (not xml-escaped): the value is fully server-controlled
            // (quotes + hex + '-') and standard servers emit literal quotes here;
            // escaping them to &quot; trips clients with lax XML parsing.
            ostr << "        <D:getetag>" << makeEtag(info.modified_at(), info.size()) << "</D:getetag>\n";
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
        ostr << "    <D:href>" << xmlEscape(path) << "</D:href>\n";
        ostr << "    <D:propstat>\n";
        ostr << "      <D:prop>\n";
        ostr << "        <D:displayname>" << xmlEscape(path.empty() || path == "/" ? "Root Directory" : path.substr(path.find_last_of('/') + 1)) << "</D:displayname>\n";
        ostr << "        <D:resourcetype><D:collection/></D:resourcetype>\n";
        ostr << "        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n";
        // Degraded listing (core unavailable): emit a STABLE epoch, never now() —
        // a fluctuating mtime here would still trip the "changed on disk" clients.
        ostr << "        <D:creationdate>" << isoDate(0) << "</D:creationdate>\n";
        ostr << "        <D:getlastmodified>" << httpDate(0) << "</D:getlastmodified>\n";
        ostr << "      </D:prop>\n";
        ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
        ostr << "    </D:propstat>\n";
        ostr << "  </D:response>\n";
        ostr << "</D:multistatus>\n";
        return;
    }

    webdav::debugLog("handlePropfind: gRPC ListDirectory succeeded, got " + std::to_string(list_resp.entries_size()) + " entries");

    // The collection's OWN timestamps must be stable too (emitting now() here made
    // every directory PROPFIND look freshly modified). Prefer the directory's
    // DB/version-derived Stat; for the root (empty uid) or a Stat miss, fall back
    // to the newest child mtime — never now().
    std::int64_t dir_created = 0, dir_modified = 0;
    if (!dir_uuid.empty()) {
        fileengine_rpc::StatRequest dstat_req;
        dstat_req.set_uid(dir_uuid);
        *dstat_req.mutable_auth() = auth_ctx;
        try {
            fileengine_rpc::StatResponse dstat = grpc_client_->stat(dstat_req);
            if (dstat.success()) { dir_created = dstat.info().created_at(); dir_modified = dstat.info().modified_at(); }
        } catch (const std::exception& e) {
            webdav::debugLog(std::string("handlePropfind: dir Stat threw: ") + e.what());
        }
    }
    if (dir_modified == 0) {  // root, or Stat unavailable: newest child mtime
        for (const auto& e : list_resp.entries()) {
            if (e.modified_at() > dir_modified) dir_modified = e.modified_at();
            if (dir_created == 0 || (e.created_at() > 0 && e.created_at() < dir_created)) dir_created = e.created_at();
        }
    }
    if (dir_created == 0) dir_created = dir_modified;

    // Build XML response with actual directory contents from gRPC
    response.setStatus(Poco::Net::HTTPResponse::HTTP_MULTI_STATUS);
    response.setReason("Multi-Status");
    response.setContentType("application/xml; charset=utf-8");
    std::ostream& ostr = response.send();

    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";

    // Add the requested directory itself
    ostr << "  <D:response>\n";
    ostr << "    <D:href>" << xmlEscape(path) << "</D:href>\n";
    ostr << "    <D:propstat>\n";
    ostr << "      <D:prop>\n";
    ostr << "        <D:displayname>" << xmlEscape(path.empty() || path == "/" ? "Root Directory" : path.substr(path.find_last_of('/') + 1)) << "</D:displayname>\n";
    ostr << "        <D:resourcetype><D:collection/></D:resourcetype>\n";
    ostr << "        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n";
    ostr << "        <D:creationdate>" << isoDate(dir_created) << "</D:creationdate>\n";
    ostr << "        <D:getlastmodified>" << httpDate(dir_modified) << "</D:getlastmodified>\n";
    ostr << "      </D:prop>\n";
    ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
    ostr << "    </D:propstat>\n";
    ostr << "  </D:response>\n";

    // Add directory entries from gRPC response (Depth: 0 => target only).
    for (const auto& entry : list_resp.entries()) {
        if (depth == "0") break;
        std::string entry_path = path.empty() || path == "/" ? "/" + entry.name() : path + "/" + entry.name();

        ostr << "  <D:response>\n";
        ostr << "    <D:href>" << xmlEscape(entry_path) << "</D:href>\n";
        ostr << "    <D:propstat>\n";
        ostr << "      <D:prop>\n";
        ostr << "        <D:displayname>" << xmlEscape(entry.name()) << "</D:displayname>\n";

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
            // Same mtime+size ETag as the file's own PROPFIND/GET (emitted raw, as
            // above), so a client that cached the listing entry's validator matches
            // on a later direct query.
            ostr << "        <D:getetag>" << makeEtag(entry.modified_at(), entry.size()) << "</D:getetag>\n";
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
    ostr << "    <D:href>" << xmlEscape(path) << "</D:href>\n";
    ostr << "    <D:propstat>\n";
    ostr << "      <D:prop>\n";
    ostr << "        <D:displayname/>\n";
    ostr << "      </D:prop>\n";
    ostr << "      <D:status>HTTP/1.1 424 Failed Dependency</D:status>\n";
    ostr << "    </D:propstat>\n";
    ostr << "  </D:response>\n";
    ostr << "</D:multistatus>\n";
}

bool WebDAVRequestHandler::prepareDestination(Poco::Net::HTTPServerRequest& request,
                                              Poco::Net::HTTPServerResponse& response,
                                              const Poco::URI& dest_uri, const std::string& dest_path,
                                              const fileengine_rpc::AuthenticationContext& auth_ctx,
                                              const std::string& tenant) {
    auto sendErr = [&](Poco::Net::HTTPResponse::HTTPStatus status, const std::string& reason,
                       const std::string& body) {
        response.setStatus(status);
        response.setReason(reason);
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << body;
    };
    auto lower = [](std::string s) {
        for (char& c : s) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
        return s;
    };

    // (1) The Destination authority must match the request host. A Destination
    // that names a different server/tenant is refused (RFC 4918: 502).
    if (!dest_uri.getHost().empty()) {
        std::string reqHost = request.getHost();
        auto colon = reqHost.find(':');
        if (colon != std::string::npos) reqHost = reqHost.substr(0, colon);
        if (lower(reqHost) != lower(dest_uri.getHost())) {
            webdav::errorLog("prepareDestination: Destination host '" + dest_uri.getHost() +
                             "' != request host '" + reqHost + "'");
            sendErr(Poco::Net::HTTPResponse::HTTP_BAD_GATEWAY, "Bad Gateway",
                    "Destination is on a different host");
            return false;
        }
    }

    // (2) Overwrite semantics (RFC 4918 §10.6). If the destination already exists:
    //   Overwrite: F  -> 412 Precondition Failed (never clobber silently)
    //   Overwrite: T  -> remove the existing target first; the core enforces
    //                    DELETE permission, so an unauthorized overwrite -> 403.
    std::optional<std::string> existing = path_resolver_->resolvePath(dest_path, auth_ctx);
    if (existing && !existing->empty()) {
        std::string overwrite = request.get("Overwrite", "T");
        if (!overwrite.empty() && (overwrite[0] == 'F' || overwrite[0] == 'f')) {
            sendErr(Poco::Net::HTTPResponse::HTTP_PRECONDITION_FAILED, "Precondition Failed",
                    "Destination exists and Overwrite is F");
            return false;
        }
        fileengine_rpc::StatRequest sr;
        sr.set_uid(*existing);
        *sr.mutable_auth() = auth_ctx;
        auto st = grpc_client_->stat(sr);
        bool is_dir = st.success() && st.info().type() == fileengine_rpc::DIRECTORY;
        bool ok;
        std::string err;
        if (is_dir) {
            ok = removeTreeRecursive(grpc_client_.get(), *existing, auth_ctx, err);
        } else {
            fileengine_rpc::RemoveFileRequest rr;
            rr.set_uid(*existing);
            *rr.mutable_auth() = auth_ctx;
            auto r = grpc_client_->removeFile(rr);
            ok = r.success();
            err = r.error();
        }
        if (!ok) {
            auto status = (err.find("permission") != std::string::npos)
                              ? Poco::Net::HTTPResponse::HTTP_FORBIDDEN
                              : Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR;
            sendErr(status, "Overwrite Failed", "Could not overwrite destination: " + err);
            return false;
        }
        path_resolver_->removePathMapping(dest_path, tenant);
    }
    return true;
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
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
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

    // Validate Destination authority + enforce Overwrite before copying (M4).
    if (!prepareDestination(request, response, dest_uri, dest_path, auth_ctx, tenant)) return;

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
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
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

    // Validate Destination authority + enforce Overwrite before moving (M4).
    if (!prepareDestination(request, response, dest_uri, dest_path, auth_ctx, tenant)) return;

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

// Parse a WebDAV Timeout request header ("Second-600", "Infinite", or a
// comma-separated preference list) into a bounded seconds value we echo back.
// Real lock lifetime is irrelevant here (locks are advisory no-ops, below), but
// clients expect a concrete Second-N they can renew against.
namespace {
constexpr long kLockTimeoutCapSeconds = 3600;   // upper bound we advertise
constexpr long kLockTimeoutDefaultSeconds = 600;
long parseLockTimeout(const std::string& header) {
    for (const auto& tok : webdav::splitString(header, ',')) {
        std::string t = webdav::trim(tok);
        if (t.rfind("Second-", 0) == 0) {
            try {
                long secs = std::stol(t.substr(7));
                if (secs <= 0) continue;
                return std::min(secs, kLockTimeoutCapSeconds);
            } catch (...) { continue; }
        }
        if (t == "Infinite") return kLockTimeoutCapSeconds;
    }
    return kLockTimeoutDefaultSeconds;
}
}  // namespace

// LOCK/UNLOCK are a compatibility shim, NOT real mutual exclusion. FileEngine is
// pervasively versioned: concurrent saves each append a new version, so there is
// no lost-update to guard against and locks convey no exclusivity (true locking
// only matters on primitive, non-versioning filesystems). We still advertise DAV
// class 2 in OPTIONS because many clients — macOS Finder, the Windows
// mini-redirector, GNOME/KDE, several editors — refuse a read-write mount, or
// abort the *first save of a new file*, unless a LOCK handshake succeeds. So we
// always grant, but the response must be RFC 4918 §9.10-shaped or those clients
// still fail: crucially it MUST carry a Lock-Token header (§9.10.1) — its
// absence was the "IO error on first save" regression, since the client could
// not extract a token for the follow-up PUT's If: header.
void WebDAVRequestHandler::handleLock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();

    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

    // LOCK is a write-class verb: authenticate and pass the session gate exactly
    // like PUT/MKCOL/etc. Before this, LOCK skipped auth entirely (returning 200
    // to anonymous callers and bypassing the §14 gate) — an inconsistency with
    // the rest of the hardened write path.
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

    // Resolve the target so we return the right status: 200 for an existing
    // resource, 201 for locking an as-yet-unmapped URL (a "lock-null" resource,
    // RFC 4918 §7.3 / §9.10.4 — the common new-file-save path). The subsequent
    // PUT is what actually creates the file.
    fileengine_rpc::AuthenticationContext auth_ctx;
    auth_ctx.set_user(user);
    auth_ctx.set_tenant(tenant);
    auth_ctx.set_source_addr(resolveRequestIp(request, hardening_->config().trusted_proxies));
    for (const auto& role : roles) auth_ctx.add_roles(role);
    const bool exists = path_resolver_->resolvePath(path, auth_ctx).has_value();

    // A unique opaque lock token per grant (never a shared constant — clients key
    // their If: preconditions on it). A LOCK with no body is a refresh (§9.10.2);
    // since our locks are stateless we just mint a fresh token either way.
    const std::string token = "urn:uuid:" + Poco::UUIDGenerator::defaultGenerator().createRandom().toString();
    const long timeout = parseLockTimeout(request.get("Timeout", ""));

    response.setStatus(exists ? Poco::Net::HTTPResponse::HTTP_OK
                              : Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason(exists ? "OK" : "Created");
    response.setContentType("application/xml; charset=\"utf-8\"");
    // Mandatory per §9.10.1 — the header (not just the body) is where clients read
    // the token they must quote in the follow-up PUT's If: header.
    response.set("Lock-Token", "<" + token + ">");
    std::ostream& ostr = response.send();

    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:prop xmlns:D=\"DAV:\">\n";
    ostr << "  <D:lockdiscovery>\n";
    ostr << "    <D:activelock>\n";
    ostr << "      <D:locktype><D:write/></D:locktype>\n";
    ostr << "      <D:lockscope><D:exclusive/></D:lockscope>\n";
    ostr << "      <D:depth>infinity</D:depth>\n";
    ostr << "      <D:timeout>Second-" << timeout << "</D:timeout>\n";
    ostr << "      <D:locktoken>\n";
    ostr << "        <D:href>" << xmlEscape(token) << "</D:href>\n";
    ostr << "      </D:locktoken>\n";
    ostr << "      <D:lockroot>\n";
    ostr << "        <D:href>" << xmlEscape(path) << "</D:href>\n";
    ostr << "      </D:lockroot>\n";
    ostr << "      <D:owner>\n";
    ostr << "        <D:href>" << xmlEscape(user) << "</D:href>\n";
    ostr << "      </D:owner>\n";
    ostr << "    </D:activelock>\n";
    ostr << "  </D:lockdiscovery>\n";
    ostr << "</D:prop>\n";
}

void WebDAVRequestHandler::handleUnlock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // The mirror of handleLock: locks are stateless no-ops, so UNLOCK always
    // succeeds. It is still a write-class verb, so it authenticates and passes the
    // session gate for consistency with LOCK and the rest of the write path.
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";

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

    // RFC 4918 §9.11: UNLOCK requires a Lock-Token header. We do not validate the
    // token value (no lock state to match), but a missing header is a malformed
    // request — reject it so clients surface their own bug rather than silently
    // "succeeding".
    if (request.get("Lock-Token", "").empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        response.setReason("Bad Request");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "UNLOCK requires a Lock-Token header";
        return;
    }

    response.setStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT);
    response.setReason("No Content");
    response.setContentType("text/plain");
    response.send();
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
        // NOTE: never log the Authorization value or decoded credentials — they
        // are LDAP passwords reusable beyond WebDAV. (Security review C4.)

        // Decode Base64 credentials
        std::istringstream istr(encoded_credentials);
        std::ostringstream ostr;
        Poco::Base64Decoder b64in(istr);
        Poco::StreamCopier::copyStream(b64in, ostr);
        std::string credentials = ostr.str();

        size_t colon_pos = credentials.find(':');
        if (colon_pos == std::string::npos) {
            webdav::debugLog("authenticateUser: Invalid credentials format - no colon found");
            return false;
        }

        // §15/§16: the Basic credential is a backend-generated key:secret, NOT a
        // directory password. Verify it against ldap_manager's internal endpoint
        // (scope "webdav") and resolve roles via a service-search (no user bind).
        // Any non-key credential — including a real directory password — is
        // rejected: there is no legacy password path (no live deployments).
        const std::string key_id = credentials.substr(0, colon_pos);
        const std::string secret = credentials.substr(colon_pos + 1);

        if (!hardening_) {
            webdav::errorLog("authenticateUser: hardening not configured — refusing");
            return false;
        }

        // Trusted client IP (§3): the authoritative address the LAN exemption and
        // the session gate evaluate against.
        std::string peer;
        try { peer = request.clientAddress().host().toString(); } catch (...) {}
        const std::string ip = webdav::resolveClientIp(
            peer, request.get("X-Forwarded-For", ""), hardening_->config().trusted_proxies);

        std::string uid;
        if (!hardening_->verifyCredential(key_id, secret, tenant, ip, uid)) {
            webdav::debugLog("authenticateUser: key:secret verification failed");
            return false;
        }
        // Roles from LDAP (the authorization authority) via service-search — no
        // password. Tenant stays host-driven (never the LDAP user-DN OU).
        // Redis-cached (TTL, §perf): the LDAP role lookup otherwise runs on EVERY
        // request, so a PROPFIND/save burst hammers the directory. On a cache miss
        // we do the live lookup and populate the cache; the credential itself was
        // already verified above, so a hit safely skips the directory round-trip.
        user = uid;
        if (!hardening_->getCachedRoles(uid, roles)) {
            UserInfo info = ldap_auth_->lookupUser(uid);
            if (!info.authenticated) {
                webdav::errorLog("authenticateUser: verified key but uid not in directory: " + uid);
                return false;
            }
            roles = info.roles;
            hardening_->putCachedRoles(uid, roles);
        }

        // Origin/session gate (§14): allow on the trusted LAN OR with a live Web-UI
        // session. Only when enabled; otherwise the strong credential alone
        // authorizes (§15.6 — the credential and gate are orthogonal layers).
        std::string via = "gate-disabled";
        if (hardening_->config().gate_enabled) {
            if (hardening_->gate(tenant, uid, ip, via) == webdav::GateDecision::Deny) {
                webdav::warnLog("authenticateUser: WebDAV gate denied uid=" + uid +
                                " tenant=" + tenant + " ip=" + ip + " (" + via + ")");
                return false;
            }
        }

        // Log the resolved client IP + gate outcome on every successful WebDAV auth
        // (INFO), so the client's address family (IPv4/IPv6) is observable alongside
        // the browser-session IP recorded by http_bridge.
        webdav::infoLog("authenticateUser: WebDAV access granted uid=" + user +
                        " tenant=" + tenant + " ip=" + ip + " via=" + via +
                        " roles=" + std::to_string(roles.size()));
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
          webdav::getEnvOrDefault("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com"),
          // Read-only replica directory for failover (empty = disabled).
          webdav::getEnvOrDefault("FILEENGINE_LDAP_ENDPOINT_REPLICA", ""),
          std::stod(webdav::getEnvOrDefault("FILEENGINE_FAILOVER_COOLDOWN_S", "30"))
      )),
      hardening_(std::make_shared<WebdavHardening>(webdav::HardeningConfig::fromEnv())),
      socket_(std::make_unique<Poco::Net::ServerSocket>(port)),
      server_params_(new Poco::Net::HTTPServerParams),
      server_(nullptr) {
    webdav::debugLog("WebDAVServer: Initializing server on " + host + ":" + std::to_string(port));
    webdav::debugLog("WebDAVServer: gRPC client created");
    webdav::debugLog("WebDAVServer: Path resolver created");
    webdav::debugLog("WebDAVServer: LDAP authenticator created");
    webdav::debugLog("WebDAVServer: Server socket created on port " + std::to_string(port));
    thread_pool_ = std::stoi(webdav::getEnvOrDefault("WEBDAV_THREAD_POOL", "16"));
    if (thread_pool_ < 1) thread_pool_ = 16;
    monitoring_host_ = webdav::getEnvOrDefault("WEBDAV_MONITORING_HOST", "127.0.0.1");
    monitoring_port_ = std::stoi(webdav::getEnvOrDefault("WEBDAV_MONITORING_PORT", "8089"));
    {
        // Optional comma-separated client-IP allowlist for the unauthenticated
        // monitoring listener (L2). Empty = allow any host reaching the bound addr.
        std::string ips = webdav::getEnvOrDefault("WEBDAV_MONITORING_ALLOW_IPS", "");
        for (auto& ip : webdav::splitString(ips, ',')) {
            std::string t = webdav::trim(ip);
            if (!t.empty()) monitoring_allow_ips_.push_back(t);
        }
    }
    server_params_->setKeepAlive(true);
    server_params_->setMaxThreads(thread_pool_);
    server_params_->setMaxQueued(thread_pool_ * 8);
    webdav::debugLog("WebDAVServer: Initialization completed (threads=" + std::to_string(thread_pool_) + ")");
}


WebDAVServer::~WebDAVServer() {
    stop();
    // Explicitly reset the server to ensure proper cleanup
    server_.reset();
}

// ---- Monitoring / reporting API (consistent across the HTTP services) --------
namespace {
std::string monitorPoolFields(Poco::ThreadPool& pool, int maxQueued) {
    return std::string("\"pool\":{\"capacity\":") + std::to_string(pool.capacity()) +
           ",\"used\":" + std::to_string(pool.used()) +
           ",\"available\":" + std::to_string(pool.available()) +
           ",\"max_queued\":" + std::to_string(maxQueued) + "}";
}
void monitorSendJson(Poco::Net::HTTPServerResponse& resp,
                     Poco::Net::HTTPResponse::HTTPStatus status, const std::string& body) {
    resp.setStatus(status);
    resp.setContentType("application/json");
    resp.setContentLength(static_cast<std::streamsize>(body.size()));
    resp.send() << body;
}

// Served on the reporter's own held-back thread, so these answer even when every
// worker thread is mid-transfer. /healthz = liveness; /readyz = has free worker
// capacity (503 when saturated → LB drains this instance); /poolz = live usage.
class MonitorHandler : public Poco::Net::HTTPRequestHandler {
public:
    MonitorHandler(Poco::ThreadPool* pool, int maxQueued, std::string service,
                   std::vector<std::string> allowIps)
        : pool_(pool), maxQueued_(maxQueued), service_(std::move(service)),
          allowIps_(std::move(allowIps)) {}
    void handleRequest(Poco::Net::HTTPServerRequest& req,
                       Poco::Net::HTTPServerResponse& resp) override {
        using R = Poco::Net::HTTPResponse;
        // Optional IP allowlist (L2), enforced before serving any probe.
        if (!allowIps_.empty()) {
            std::string ip;
            try { ip = req.clientAddress().host().toString(); } catch (...) {}
            bool ok = false;
            for (const auto& a : allowIps_) if (a == ip) { ok = true; break; }
            if (!ok) return monitorSendJson(resp, R::HTTP_FORBIDDEN, "{\"error\":\"forbidden\"}");
        }
        const std::string path = req.getURI();
        const bool hasCapacity = pool_->available() > 0;
        if (path == "/healthz") {
            monitorSendJson(resp, R::HTTP_OK,
                            std::string("{\"status\":\"ok\",\"service\":\"") + service_ + "\"}");
        } else if (path == "/readyz") {
            monitorSendJson(resp, hasCapacity ? R::HTTP_OK : R::HTTP_SERVICE_UNAVAILABLE,
                            std::string("{\"ready\":") + (hasCapacity ? "true" : "false") +
                            "," + monitorPoolFields(*pool_, maxQueued_) + "}");
        } else if (path == "/poolz") {
            monitorSendJson(resp, R::HTTP_OK,
                            std::string("{") + monitorPoolFields(*pool_, maxQueued_) +
                            ",\"saturated\":" + (hasCapacity ? "false" : "true") + "}");
        } else {
            monitorSendJson(resp, R::HTTP_NOT_FOUND, "{\"error\":\"not found\"}");
        }
    }
private:
    Poco::ThreadPool* pool_;
    int maxQueued_;
    std::string service_;
    std::vector<std::string> allowIps_;
};

class MonitorHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    MonitorHandlerFactory(Poco::ThreadPool* pool, int maxQueued, std::string service,
                          std::vector<std::string> allowIps)
        : pool_(pool), maxQueued_(maxQueued), service_(std::move(service)),
          allowIps_(std::move(allowIps)) {}
    Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest&) override {
        return new MonitorHandler(pool_, maxQueued_, service_, allowIps_);
    }
private:
    Poco::ThreadPool* pool_;
    int maxQueued_;
    std::string service_;
    std::vector<std::string> allowIps_;
};
}  // namespace

void WebDAVServer::start() {
    webdav::debugLog("WebDAVServer: Starting server on " + host_ + ":" + std::to_string(port_));
    try {
        auto* factory = new WebDAVRequestHandlerFactory(grpc_client_, path_resolver_, ldap_auth_, hardening_);
        webdav::debugLog("WebDAVServer: Created request handler factory");
        // Dedicated pool sized to thread_pool_ rather than Poco's shared
        // defaultPool() (capacity 16), so WEBDAV_THREAD_POOL actually scales
        // concurrent connections above 16.
        pool_ = std::make_unique<Poco::ThreadPool>(
            std::min(2, thread_pool_), thread_pool_, 60 /* idle seconds */);
        server_ = std::make_unique<Poco::Net::HTTPServer>(factory, *pool_, *socket_, server_params_);
        webdav::debugLog("WebDAVServer: Created HTTP server instance with socket on port " + std::to_string(port_));
        webdav::debugLog("WebDAVServer: About to call server_->start()");
        server_->start();
        webdav::debugLog("WebDAVServer: Started HTTP server successfully");

        std::cout << "WebDAV server listening on " << host_ << ":" << port_ << std::endl;

        // Dedicated reporter: a single held-back thread + listener so pool usage /
        // health stay answerable for the load balancer even at full saturation.
        monitor_pool_ = std::make_unique<Poco::ThreadPool>(1, 1, 60);
        auto* mparams = new Poco::Net::HTTPServerParams;
        mparams->setMaxThreads(1);
        mparams->setMaxQueued(64);
        mparams->setKeepAlive(false);
        Poco::Net::ServerSocket msocket(
            Poco::Net::SocketAddress(monitoring_host_, static_cast<Poco::UInt16>(monitoring_port_)));
        monitor_server_ = std::make_unique<Poco::Net::HTTPServer>(
            new MonitorHandlerFactory(pool_.get(), thread_pool_ * 8, "webdav_bridge", monitoring_allow_ips_),
            *monitor_pool_, msocket, mparams);
        monitor_server_->start();
        std::cout << "WebDAV monitoring (/healthz /readyz /poolz) listening on " << monitoring_host_
                  << ":" << monitoring_port_ << std::endl;
    } catch (const std::exception& e) {
        webdav::errorLog("WebDAVServer: Exception in start(): " + std::string(e.what()));
        throw; // Re-throw to be caught by main application
    } catch (...) {
        webdav::errorLog("WebDAVServer: Unknown exception in start()");
        throw; // Re-throw to be caught by main application
    }
}

void WebDAVServer::stop() {
    if (monitor_server_) {
        monitor_server_->stop();
    }
    if (server_) {
        server_->stop();
    }
    if (socket_) {
        socket_->close();
    }
}

} // namespace webdav