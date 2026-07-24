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

#include "path_resolver.h"
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <mutex>
#include <sstream>

namespace webdav {

namespace {
// Canonicalize a WebDAV path so equivalent forms resolve to the same cache key.
// WebDAV clients request a collection with a trailing slash when navigating
// into it (e.g. "/Test1/"), but mappings are cached without one ("/Test1"). It
// also collapses accidental repeated slashes (e.g. "/Test1//test2"). The root
// ("/" or empty) always normalizes to "/".
std::string normalizePath(const std::string& path) {
    std::string out;
    out.reserve(path.size() + 1);
    out.push_back('/');
    bool prev_slash = true;  // leading slash already emitted
    for (char c : path) {
        if (c == '/') {
            if (prev_slash) continue;  // collapse repeats / drop leading dup
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push_back(c);
    }
    if (out.size() > 1 && out.back() == '/') out.pop_back();  // strip trailing
    return out;
}
}  // namespace

PathResolver::PathResolver(std::shared_ptr<GRPCClientWrapper> grpc_client)
    : grpc_client_(grpc_client) {
    // Initialize with in-memory storage instead of database
    // Initialize root path mapping for both "default" tenant and empty string (default tenant)
    createPathMapping("/", "", "default"); // Empty UUID represents root, "default" tenant
    createPathMapping("/", "", ""); // Also map to empty string tenant for compatibility
}

std::optional<std::string> PathResolver::resolvePath(
        const std::string& raw_path, const fileengine_rpc::AuthenticationContext& auth) {
    const std::string path = normalizePath(raw_path);
    const std::string& tenant = auth.tenant();

    if (path == "/") return std::string();  // root is the empty UID

    // Cache fast-path with verify-on-hit. Check membership explicitly (not
    // emptiness): a non-root entry can legitimately map to "" in some tenants.
    std::string cached;
    bool have_cached = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = path_to_uuid_map_.find(getCacheKey(path, tenant));
        if (it == path_to_uuid_map_.end() && !tenant.empty())
            it = path_to_uuid_map_.find(getCacheKey(path, ""));
        if (it != path_to_uuid_map_.end()) { cached = it->second; have_cached = true; }
    }
    if (have_cached) {
        // A cached uid can be stale: the node may have been deleted, renamed, or
        // deleted-and-recreated at the same path (possibly by another client, the
        // REST bridge, or the rendition service — mutations this process never
        // saw). Verify it still exists and its name still matches before trusting
        // it; otherwise evict and fall through to a fresh walk. (A node moved to a
        // different parent under the same name is not caught here; same-process
        // MOVE updates the cache directly.)
        const std::string base = path.substr(path.find_last_of('/') + 1);
        fileengine_rpc::StatRequest sreq;
        sreq.set_uid(cached);
        *sreq.mutable_auth() = auth;
        try {
            auto sresp = grpc_client_->stat(sreq);
            if (sresp.success() && sresp.info().name() == base) {
                return cached;  // verified cache hit
            }
        } catch (const std::exception& e) {
            webdav::debugLog("PathResolver::resolvePath: verify Stat threw: " + std::string(e.what()));
        }
        webdav::debugLog("PathResolver::resolvePath: stale cache entry for '" + path + "', re-resolving");
        removePathMapping(path, tenant);  // locks internally
    }

    // Cache miss: walk from the root, listing each level and matching the next
    // segment by name, caching every prefix we resolve along the way.
    std::string current_uuid;  // root
    std::string current_path;  // builds up to `path`
    std::string segment;
    std::istringstream segs(path);
    while (std::getline(segs, segment, '/')) {
        if (segment.empty()) continue;  // leading slash / repeats

        fileengine_rpc::ListDirectoryRequest req;
        req.set_uid(current_uuid);
        *req.mutable_auth() = auth;

        fileengine_rpc::ListDirectoryResponse resp;
        try {
            resp = grpc_client_->listDirectory(req);
        } catch (const std::exception& e) {
            webdav::errorLog("PathResolver::resolvePath: ListDirectory threw: " + std::string(e.what()));
            return std::nullopt;
        }
        if (!resp.success()) {
            webdav::debugLog("PathResolver::resolvePath: ListDirectory failed at '" + current_path +
                             "': " + resp.error());
            return std::nullopt;
        }

        bool found = false;
        for (const auto& entry : resp.entries()) {
            if (entry.name() == segment) {
                current_uuid = entry.uid();
                current_path += "/" + segment;
                createPathMapping(current_path, current_uuid, tenant);  // locks internally
                found = true;
                break;
            }
        }
        if (!found) {
            webdav::debugLog("PathResolver::resolvePath: segment '" + segment +
                             "' not found under '" + current_path + "'");
            return std::nullopt;
        }
    }

    return current_uuid;
}

std::string PathResolver::resolvePathToUUID(const std::string& raw_path, const std::string& tenant) {
    std::string path = normalizePath(raw_path);
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = path_to_uuid_map_.find(getCacheKey(path, tenant));
    if (it != path_to_uuid_map_.end()) {
        return it->second;
    }

    // If not found and tenant is not empty, try with empty tenant (for default tenant)
    if (!tenant.empty()) {
        it = path_to_uuid_map_.find(getCacheKey(path, ""));
        if (it != path_to_uuid_map_.end()) {
            return it->second;
        }
    }

    // If not found and tenant is empty, try with "default" tenant
    if (tenant.empty()) {
        it = path_to_uuid_map_.find(getCacheKey(path, "default"));
        if (it != path_to_uuid_map_.end()) {
            return it->second;
        }
    }

    return "";
}

std::string PathResolver::resolveUUIDToPath(const std::string& uuid, const std::string& tenant) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = uuid_to_path_map_.find(getCacheKey(uuid, tenant));
    if (it != uuid_to_path_map_.end()) {
        return it->second;
    }

    // If not found and tenant is not empty, try with empty tenant (for default tenant)
    if (!tenant.empty()) {
        it = uuid_to_path_map_.find(getCacheKey(uuid, ""));
        if (it != uuid_to_path_map_.end()) {
            return it->second;
        }
    }

    // If not found and tenant is empty, try with "default" tenant
    if (tenant.empty()) {
        it = uuid_to_path_map_.find(getCacheKey(uuid, "default"));
        if (it != uuid_to_path_map_.end()) {
            return it->second;
        }
    }

    return "";
}

bool PathResolver::createPathMapping(const std::string& raw_path, const std::string& uuid, const std::string& tenant) {
    std::string path = normalizePath(raw_path);
    std::lock_guard<std::mutex> lock(mutex_);
    std::string path_key = getCacheKey(path, tenant);
    std::string uuid_key = getCacheKey(uuid, tenant);

    path_to_uuid_map_[path_key] = uuid;
    uuid_to_path_map_[uuid_key] = path;

    return true;
}

bool PathResolver::removePathMapping(const std::string& raw_path, const std::string& tenant) {
    std::string path = normalizePath(raw_path);
    std::lock_guard<std::mutex> lock(mutex_);
    std::string path_key = getCacheKey(path, tenant);
    
    auto path_it = path_to_uuid_map_.find(path_key);
    if (path_it != path_to_uuid_map_.end()) {
        std::string uuid = path_it->second;
        std::string uuid_key = getCacheKey(uuid, tenant);
        
        path_to_uuid_map_.erase(path_it);
        uuid_to_path_map_.erase(uuid_key);
    }
    
    return true;
}

bool PathResolver::pathExists(const std::string& path, const std::string& tenant) {
    return !resolvePathToUUID(path, tenant).empty();
}

std::string PathResolver::getParentUUID(const std::string& raw_path, const std::string& tenant) {
    std::string path = normalizePath(raw_path);
    if (path == "/" || path.empty()) {
        return ""; // Root has no parent
    }

    // Find the parent path
    std::string parent_path = path;
    size_t pos = parent_path.find_last_of('/');
    if (pos != std::string::npos) {
        if (pos == 0) {
            parent_path = "/"; // Parent of "/something" is "/"
        } else {
            parent_path = parent_path.substr(0, pos);
        }
    }

    return resolvePathToUUID(parent_path, tenant);
}

std::string PathResolver::getCacheKey(const std::string& path, const std::string& tenant) {
    return tenant + ":" + path;
}

} // namespace webdav