# Implement a full integration for WebDAV access to FileEngine

Write a service for WebDAV that exposes the gRPC filesystem API
(the `fileengine` protocol defined in @file_engine_cpp). Implement
this service in C++.

## User information

User authentication information is held in an LDAP directory
structured for multi-tenancy.

Users are under `ou=users` and tenants defined by organizational
units under `ou=tenants`, each tenant contains multiple
groupOfNames for each system role.

### Default roles

- users - read access
- contributors - write access
- administrators - full access
