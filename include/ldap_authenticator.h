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

#ifndef LDAP_AUTHENTICATOR_H
#define LDAP_AUTHENTICATOR_H

#include <ldap.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

#include "circuit_breaker.h"

namespace webdav {

struct UserInfo {
    std::string dn;              // Distinguished Name
    std::string user_id;         // User ID
    std::vector<std::string> roles;  // User roles
    std::string tenant;          // User's tenant
    bool authenticated;          // Whether authentication was successful
};

class LDAPAuthenticator {
public:
    LDAPAuthenticator(
        const std::string& ldap_endpoint,
        const std::string& ldap_domain,
        const std::string& bind_dn,
        const std::string& bind_password,
        const std::string& tenant_base = "",
        const std::string& user_base = "",
        // Read-only replica directory for disconnect fault tolerance
        // (REPLICATION_FAILOVER.md). Empty disables failover.
        const std::string& replica_endpoint = "",
        double failover_cooldown_s = 30.0
    );

    ~LDAPAuthenticator();
    
    // Authenticate user with username and password
    UserInfo authenticateUser(const std::string& username, const std::string& password);

    // Resolve a user's roles WITHOUT a password bind (for key:secret auth, §15):
    // a service-bind search by uid + group-membership role extraction. `authenticated`
    // is true iff the uid exists in the directory. Tenant is host-driven by the
    // caller, so it is left empty here.
    UserInfo lookupUser(const std::string& username);

    
private:
    std::string ldap_endpoint_;
    std::string ldap_domain_;
    std::string bind_dn_;
    std::string bind_password_;
    std::string tenant_base_;
    std::string user_base_;
    std::string replica_endpoint_;       // empty => failover disabled
    CircuitBreaker breaker_;             // master availability (guarded by ldap_mutex_)

    mutable std::mutex ldap_mutex_;  // Protect LDAP operations

    // Connect to the master, or fail over to the read-only replica when the master
    // is unreachable (master-only when no replica is configured).
    LDAP* connectToLDAP();

    // Bind a service connection to a specific endpoint; nullptr on failure.
    LDAP* connectToEndpoint(const std::string& endpoint);
    
    // Helper function to search for a user
    UserInfo searchUser(LDAP* ld, const std::string& username);
    
    // Helper function to extract tenant from user's DN
    std::string extractTenantFromUserDN(const std::string& user_dn);
    
    // Helper function to extract roles from user's group memberships
    std::vector<std::string> extractRolesFromGroups(LDAP* ld, const std::string& user_dn);
};

} // namespace webdav

#endif // LDAP_AUTHENTICATOR_H