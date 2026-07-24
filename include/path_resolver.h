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

#ifndef PATH_RESOLVER_H
#define PATH_RESOLVER_H

#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <optional>

#include "grpc_client_wrapper.h"

namespace webdav {

class PathResolver {
public:
    PathResolver(std::shared_ptr<GRPCClientWrapper> grpc_client);

    // Resolve a path to a node UID, walking the tree from the root via gRPC
    // ListDirectory when the in-memory cache misses (using the request's auth
    // context for ACL evaluation). Successfully resolved prefixes are cached.
    // Returns:
    //   std::nullopt   - a path segment does not exist (caller should 404/409)
    //   ""             - the root collection
    //   <uuid>         - the resolved node
    // Prefer this over the cache-only resolvePathToUUID: a cache miss there
    // returns "" which is indistinguishable from the root, silently listing the
    // root for any not-yet-cached or non-existent path.
    std::optional<std::string> resolvePath(const std::string& path,
                                           const fileengine_rpc::AuthenticationContext& auth);

    // Resolve a path to a UUID from the in-memory cache only ("" if absent/root).
    std::string resolvePathToUUID(const std::string& path, const std::string& tenant);

    // Resolve a UUID to a path
    std::string resolveUUIDToPath(const std::string& uuid, const std::string& tenant);

    // Create a new path-to-UUID mapping
    bool createPathMapping(const std::string& path, const std::string& uuid, const std::string& tenant);

    // Remove a path-to-UUID mapping
    bool removePathMapping(const std::string& path, const std::string& tenant);

    // Check if a path exists
    bool pathExists(const std::string& path, const std::string& tenant);

    // Get parent UUID from a path
    std::string getParentUUID(const std::string& path, const std::string& tenant);

private:
    std::shared_ptr<GRPCClientWrapper> grpc_client_;

    // In-memory storage for path-to-UUID mappings
    std::unordered_map<std::string, std::string> path_to_uuid_map_; // path -> uuid
    std::unordered_map<std::string, std::string> uuid_to_path_map_; // uuid -> path
    mutable std::mutex mutex_;

    // Helper function to get tenant-specific cache key
    std::string getCacheKey(const std::string& path, const std::string& tenant);
};

} // namespace webdav

#endif // PATH_RESOLVER_H