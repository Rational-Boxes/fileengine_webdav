# WebDAV Bridge Implementation Plan for FileEngine

## 1. Overview

This document outlines the implementation plan for a WebDAV bridge service that exposes the FileEngine gRPC filesystem API through a WebDAV interface. The service will be implemented in C++ and will integrate with the existing FileEngine infrastructure.

## 2. Architecture Overview

The WebDAV bridge will consist of four main components:

1. **WebDAV HTTP Server** - Handles WebDAV protocol requests and responses
2. **Translation Layer** - Maps WebDAV operations to gRPC calls
3. **Authentication Module** - Integrates with LDAP for user authentication and role mapping
4. **Path Resolution Service** - Translates between file paths and UUIDs

## 3. Technical Approach

### 3.1 WebDAV Server Implementation

We'll implement the server using the PocoProject C++ framework which provides a mature HTTP server implementation with good extensibility. This approach gives us:

- Robust HTTP/HTTPS handling
- Built-in support for HTTP authentication
- Easy extension to support WebDAV-specific methods
- Cross-platform compatibility

### 3.2 gRPC Client Integration

The WebDAV bridge will act as a gRPC client connecting to the FileEngine gRPC service. We'll need to:

1. Generate gRPC client stubs from the existing `.proto` files
2. Implement a client wrapper that handles connection pooling and error handling
3. Map WebDAV operations to corresponding gRPC calls

### 3.3 Translation Layer Design

The translation layer will handle mapping between WebDAV operations and gRPC calls:

#### WebDAV Methods to gRPC Mappings:
- `GET` → `ReadFile` or `ListDirectory`
- `PUT` → `WriteFile` (with `CreateFile` if file doesn't exist)
- `MKCOL` → `MakeDirectory`
- `DELETE` → `DeleteFile` or `RemoveDirectory`
- `PROPFIND` → `GetFileInfo` and metadata operations
- `PROPPATCH` → `SetMetadata` and `DeleteMetadata`
- `COPY` → `CopyFile`
- `MOVE` → `MoveFile` or `RenameFile`
- `LOCK`/`UNLOCK` → Since FileEngine is pervasively versioned and immutable, traditional file locking concerns do not apply. These operations will be handled at the application level if needed for client-side locking semantics, but will not enforce any actual file locks on the backend.

#### Path to UUID Mapping:
- Implement a path resolution service that translates file paths to UUIDs
- Maintain a temporary mapping cache for recently accessed paths
- Handle multi-tenant path structures: `/tenant/user/resource`

## 4. Authentication and Authorization

### 4.1 LDAP Integration
The service will authenticate users against the LDAP directory with the following structure:
- Users stored under `ou=users`
- Tenants defined as organizational units under `ou=tenants`
- Roles implemented as `groupOfNames` entities per tenant

### 4.2 Role Mapping
- `users` group → READ permissions
- `contributors` group → READ/WRITE permissions
- `administrators` group → FULL permissions

### 4.3 Special Internal User
- The special internal user `root` has full access to the gRPC back-end regardless of tenant restrictions
- This user bypasses normal permission checks for administrative operations
- The `root` user is NOT allowed to access the system via WebDAV
- The `root` user is only used internally for administrative tasks such as setting initial ACLs when a new tenant is created

### 4.4 Multi-Tenancy
The service implements multi-tenancy based on sub-domains:
- The tenant name is derived from the sub-domain, excluding `www`
- If the sub-domain includes a hyphen (`-`), only the part before the hyphen is used for the tenant name
- Examples:
  - `tenant1.example.com` → tenant name: `tenant1`
  - `tenant2.example.com` → tenant name: `tenant2`
  - `tenant-dev.example.com` → tenant name: `tenant` (part before hyphen)
  - `www.example.com` → tenant name: (default/main tenant, as www is excluded)

### 4.5 Authentication Flow
1. Extract credentials from WebDAV request (Basic Auth or Digest Auth)
2. Determine tenant from sub-domain following multi-tenancy rules
3. Check if user is the special internal `root` user
4. If not root, authenticate against LDAP directory using connection pool
5. Retrieve user's roles and tenant membership
6. Create AuthenticationContext for gRPC calls with user, roles, and tenant information

## 5. Implementation Phases

### Phase 1: Basic Infrastructure
- Set up C++ project structure with CMake
- Integrate gRPC client for FileEngine
- Implement basic HTTP server with WebDAV route handling
- Create path-to-UUID resolver

### Phase 2: Core Operations
- Implement GET/PUT for file operations
- Implement MKCOL for directory creation
- Implement DELETE for file and directory removal
- Add basic authentication with LDAP

### Phase 3: Advanced Operations
- Implement PROPFIND for property queries
- Implement PROPPATCH for metadata updates
- Implement COPY and MOVE operations
- Implement LOCK/UNLOCK operations for client-side locking semantics (no actual backend locking required due to FileEngine's versioned and immutable nature)

### Phase 4: Optimization and Testing
- Add caching mechanisms
- Implement comprehensive error handling
- Add logging and monitoring
- Perform integration testing

## 6. File Structure for Implementation

```
webdav_bridge/
├── CMakeLists.txt
├── include/
│   ├── webdav_server.h
│   ├── grpc_client_wrapper.h
│   ├── path_resolver.h
│   ├── ldap_authenticator.h
│   └── utils.h
├── src/
│   ├── webdav_server.cpp
│   ├── grpc_client_wrapper.cpp
│   ├── path_resolver.cpp
│   ├── ldap_authenticator.cpp
│   ├── utils.cpp
│   └── main.cpp
├── tests/
│   └── ...
└── config/
    └── webdav_config.json
```

## 7. Dependencies

- gRPC and Protobuf (for communicating with FileEngine)
- PocoProject (for HTTP server functionality)
- OpenLDAP (for LDAP integration)
- CMake (build system)
- OpenSSL (for secure connections)

## 8. Configuration

The WebDAV bridge service will be configured through a combination of command-line options, environment variables, and configuration files. The default configuration values are stored in `.env-default`, with the actual configuration coming from `.env` files or environment variables.

The service supports a command-line option to specify a custom configuration file:

- `-c, --config <file_path>` - Path to a custom configuration file that overrides default settings

When a custom configuration file is specified, it will take precedence over environment variables and default values.

### Configuration Options:

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

## 9. Tenant Initialization

When a new tenant is created, the system must perform the following initialization steps:

- Create the tenant's root directory in the FileEngine filesystem
- Use the special internal `root` user to setup initial ACLs on the filesystem root for the tenant (when the default ACLs have not been created yet)
- Assign appropriate permissions to the tenant's administrator group
- Register the tenant in the persistent storage for tracking

This initialization process ensures that each tenant has the proper access controls and permissions from the start. The `root` user is used exclusively for this internal administrative task and is not accessible via WebDAV.

Additionally, the system includes logic to detect authorization failures on the filesystem root and check if the ACLs have yet to be set. If ACLs are missing, the system will automatically trigger the initial permissions setup using the `root` user to ensure proper access controls are established.

## 10. Persistent Data Storage

The WebDAV bridge will utilize a Postgres database for storing persistent data that needs to survive service restarts. The database will store:

- Path to UUID mappings for efficient path resolution
- User session information (if required)
- Cached LDAP user information to reduce directory queries
- WebDAV-specific metadata that doesn't fit the FileEngine model
- Lock tokens for WebDAV LOCK/UNLOCK operations (for client-side locking semantics, not actual file locks since FileEngine is pervasively versioned and immutable)
- Operation logs for audit purposes

Connection to the database will be managed through a connection pool to ensure efficient resource usage.

## 11. LDAP Authentication Integration Plan

### 11.1 LDAP Connection Management
- Implement an LDAP connection pool to handle multiple concurrent authentication requests
- Create a configuration system for LDAP server details (host, port, bind DN, password)
- Support both direct binding and search+bind authentication methods

### 11.2 User Authentication Flow
- Extract credentials from WebDAV request (supporting both Basic and Digest authentication)
- For Basic Auth: extract username and password from the authorization header
- For Digest Auth: validate the digest response against the stored password hash
- Connect to LDAP server using connection pool
- Attempt to bind with user credentials
- On successful bind, retrieve user's group memberships and tenant association

### 11.3 User Information Retrieval
- Query LDAP for user's distinguished name (DN) using the username
- Search for user's group memberships to determine roles (users, contributors, administrators)
- Identify user's tenant by checking their organizational unit membership
- Validate tenant name against sub-domain following multi-tenancy rules

### 11.4 Role and Permission Mapping
- Map LDAP group memberships to FileEngine permissions:
  - Members of `users` group → READ permissions
  - Members of `contributors` group → READ/WRITE permissions
  - Members of `administrators` group → FULL permissions
- Construct the AuthenticationContext with user ID, roles, and tenant for gRPC calls

### 11.5 Security Considerations
- Use LDAPS (LDAP over SSL/TLS) for secure communication
- Support both Basic and Digest authentication methods for WebDAV access
- When using Basic Auth, ensure connections are encrypted with HTTPS
- Implement proper credential sanitization to prevent injection attacks
- Add rate limiting to prevent brute force attacks
- Cache authentication results temporarily to reduce LDAP load

## 12. Error Handling and Logging

- Implement comprehensive error handling for all WebDAV operations
- Log all authentication attempts and operations for audit purposes
- Return appropriate HTTP status codes for different error conditions
- Implement retry mechanisms for transient failures

## 13. Testing Strategy

- Unit tests for individual components (authentication, path resolution, gRPC client)
- Integration tests for end-to-end WebDAV operations
- Load testing to ensure performance under concurrent access
- Security testing to validate authentication and authorization