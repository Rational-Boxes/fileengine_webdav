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

#include <iostream>
#include <memory>
#include "../include/ldap_authenticator.h"
#include "../include/utils.h"

int main() {
    std::cout << "Testing LDAP Authenticator with live LDAP server..." << std::endl;

    // Create an LDAP authenticator instance with actual configuration from .env-default
    webdav::LDAPAuthenticator ldap_auth(
        webdav::getEnvOrDefault("FILEENGINE_LDAP_ENDPOINT", "ldap://localhost:1389"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_DOMAIN", "dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_DN", "cn=admin,dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_PASSWORD", "admin"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_TENANT_BASE", "ou=tenants,dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com")
    );

    // Test user authentication with a real user from the LDAP directory
    std::cout << "Testing authentication for user 'admin' with password 'admin'..." << std::endl;
    webdav::UserInfo user_info = ldap_auth.authenticateUser("admin", "admin");

    std::cout << "\n=== AUTHENTICATION RESULT ===" << std::endl;
    std::cout << "Authenticated: " << (user_info.authenticated ? "YES" : "NO") << std::endl;
    std::cout << "User ID: " << user_info.user_id << std::endl;
    std::cout << "DN: " << user_info.dn << std::endl;
    std::cout << "Tenant: " << user_info.tenant << std::endl;
    std::cout << "Number of roles: " << user_info.roles.size() << std::endl;

    std::cout << "Roles: ";
    for (size_t i = 0; i < user_info.roles.size(); ++i) {
        std::cout << user_info.roles[i];
        if (i < user_info.roles.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << std::endl;
    std::cout << "=============================" << std::endl;

    if (user_info.authenticated) {
        std::cout << "SUCCESS: User 'admin' was authenticated successfully!" << std::endl;

        // Verify that roles were loaded from tenant groupOfNames entities
        if (!user_info.roles.empty()) {
            std::cout << "SUCCESS: Roles were loaded for the user from tenant groupOfNames entities." << std::endl;
            std::cout << "Loaded roles: ";
            for (size_t i = 0; i < user_info.roles.size(); ++i) {
                std::cout << user_info.roles[i];
                if (i < user_info.roles.size() - 1) {
                    std::cout << ", ";
                }
            }
            std::cout << std::endl;
        } else {
            std::cout << "INFO: No roles were loaded for the user. Check that the user belongs to groupOfNames entities in the LDAP directory." << std::endl;
        }
    } else {
        std::cout << "FAILURE: User 'admin' was not authenticated. Check LDAP server is running and credentials are correct." << std::endl;
    }

    // Try another test with a potential regular user
    std::cout << "\nTesting authentication for user 'testuser' with password 'password'..." << std::endl;
    webdav::UserInfo user_info2 = ldap_auth.authenticateUser("testuser", "password");

    std::cout << "\n=== SECOND AUTHENTICATION RESULT ===" << std::endl;
    std::cout << "Authenticated: " << (user_info2.authenticated ? "YES" : "NO") << std::endl;
    std::cout << "User ID: " << user_info2.user_id << std::endl;
    std::cout << "DN: " << user_info2.dn << std::endl;
    std::cout << "Tenant: " << user_info2.tenant << std::endl;
    std::cout << "Number of roles: " << user_info2.roles.size() << std::endl;

    std::cout << "Roles: ";
    for (size_t i = 0; i < user_info2.roles.size(); ++i) {
        std::cout << user_info2.roles[i];
        if (i < user_info2.roles.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << std::endl;
    std::cout << "=====================================" << std::endl;

    if (user_info2.authenticated) {
        std::cout << "SUCCESS: User 'testuser' was authenticated successfully!" << std::endl;

        if (!user_info2.roles.empty()) {
            std::cout << "SUCCESS: Roles were loaded for the user from tenant groupOfNames entities." << std::endl;
            std::cout << "Loaded roles: ";
            for (size_t i = 0; i < user_info2.roles.size(); ++i) {
                std::cout << user_info2.roles[i];
                if (i < user_info2.roles.size() - 1) {
                    std::cout << ", ";
                }
            }
            std::cout << std::endl;
        } else {
            std::cout << "INFO: No roles were loaded for the user. Check that the user belongs to groupOfNames entities in the LDAP directory." << std::endl;
        }
    } else {
        std::cout << "INFO: User 'testuser' was not authenticated. This is expected if the user doesn't exist." << std::endl;
    }

    std::cout << "\nLDAP Authenticator test completed." << std::endl;
    return 0;
}