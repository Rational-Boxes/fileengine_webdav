# WebDAV Bridge for FileEngine

> ⚠️ **Active development — not production-ready.** This project is under active development and should **not** be considered safe for mission-critical use.

This project implements a WebDAV server that exposes the FileEngine gRPC filesystem API. The service allows clients to access the FileEngine filesystem through standard WebDAV protocols.

## Features

- Full WebDAV protocol support (GET, PUT, MKCOL, DELETE, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK)
- Multi-tenancy support based on sub-domains
- LDAP authentication with role-based access control
- Path-to-UUID resolution for the UUID-based FileEngine filesystem
- Persistent storage of path mappings in PostgreSQL
- Support for both Basic and Digest authentication
- Concurrent connections over a dedicated, correctly-sized worker pool
  (`WEBDAV_THREAD_POOL`), so long-lived file transfers don't block one another
- High-availability monitoring endpoints (`/healthz`, `/readyz`, `/poolz`) on a
  separate reporter listener for load-balancer / reverse-proxy health checks

## Architecture

The WebDAV bridge consists of several key components:

1. **WebDAV Server**: Handles HTTP requests and WebDAV protocol implementation
2. **gRPC Client Wrapper**: Communicates with the FileEngine gRPC service
3. **Path Resolver**: Translates between file paths and UUIDs
4. **LDAP Authenticator**: Handles user authentication and role mapping
5. **Utilities**: Common helper functions

## Configuration

The service can be configured using environment variables or a configuration file:

### Environment Variables

- `WEBDAV_HOST` - Listen address for the WebDAV server (default: 0.0.0.0)
- `WEBDAV_PORT` - Listen port for the WebDAV server (default: 8080)
- `WEBDAV_THREAD_POOL` - Max concurrent connections; sizes a dedicated worker
  pool rather than Poco's shared `defaultPool` (capacity 16), so the value
  actually scales (default: 16)
- `WEBDAV_MONITORING_PORT` - Dedicated reporter listener exposing `/healthz`
  (liveness), `/readyz` (503 when no worker is free, so a load balancer drains
  this instance), and `/poolz` (live pool usage + `saturated` flag). One worker
  is held back for this listener so reporting stays responsive under load
  (default: 8089)
- `FILEENGINE_GRPC_HOST` - Host address of the FileEngine gRPC service (default: localhost)
- `FILEENGINE_GRPC_PORT` - Port of the FileEngine gRPC service (default: 50051)
- `FILEENGINE_LDAP_ENDPOINT` - LDAP server endpoint (default: ldap://localhost:1389)
- `FILEENGINE_LDAP_DOMAIN` - LDAP domain/base DN (default: dc=rationalboxes,dc=com)
- `FILEENGINE_LDAP_BIND_DN` - LDAP bind DN for service account (default: cn=admin,dc=rationalboxes,dc=com)
- `FILEENGINE_LDAP_BIND_PASSWORD` - Password for LDAP bind account (default: admin)
- `POSTGRES_HOST` - Host address of the Postgres database (default: localhost)
- `POSTGRES_PORT` - Port of the Postgres database (default: 5432)
- `POSTGRES_DB` - Database name for persistent data storage (default: webdav_bridge)
- `POSTGRES_USER` - Username for Postgres database access (default: postgres)
- `POSTGRES_PASSWORD` - Password for Postgres database access
- `LOG_LEVEL` - Logging level (default: debug); supports standard levels: trace, debug, info, warn, error, fatal; with very detailed logging for the `debug` level including all HTTP requests, authentication attempts, gRPC calls, and database operations
- `LOG_FILE` - Path to the log file where logs will be written (default: stdout)

### Command Line Options

- `-c, --config <file_path>` - Path to a custom configuration file that overrides default settings

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Running

```bash
./webdav_bridge [options]
```

## Testing

Run the unit tests:

```bash
make test
```

## Multi-Tenancy

The service implements multi-tenancy based on sub-domains:
- The tenant name is derived from the sub-domain, excluding `www`
- If the sub-domain includes a hyphen (`-`), only the part before the hyphen is used for the tenant name
- Examples:
  - `tenant1.example.com` → tenant name: `tenant1`
  - `tenant2.example.com` → tenant name: `tenant2`
  - `tenant-dev.example.com` → tenant name: `tenant` (part before hyphen)
  - `www.example.com` → tenant name: (default/main tenant, as www is excluded)

## Special Internal User

- The special internal user `root` has full access to the gRPC back-end regardless of tenant restrictions
- This user bypasses normal permission checks for administrative operations
- The `root` user is NOT allowed to access the system via WebDAV
- The `root` user is only used internally for administrative tasks such as setting initial ACLs when a new tenant is created

When a new tenant is created, the system automatically sets up initial ACLs on the filesystem root for the tenant. Additionally, the system includes logic to detect authorization failures on the filesystem root and check if the ACLs have yet to be set. If ACLs are missing, the system will automatically trigger the initial permissions setup using the `root` user to ensure proper access controls are established.

## Versioning and Immutability

Since FileEngine is pervasively versioned and immutable, traditional file locking concerns do not apply. The LOCK/UNLOCK WebDAV operations are handled at the application level for client-side locking semantics but do not enforce any actual file locks on the backend.

## License

Copyright (C) 2026 James Hickman <james@rationalboxes.com>

This project is licensed under the **GNU General Public License, version 3 (or
later)** — see the [LICENSE](LICENSE) file for the full text.
