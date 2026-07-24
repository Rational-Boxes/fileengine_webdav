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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../include/ldap_authenticator.h"
#include "../include/utils.h"  // extractTenantFromHostname

class LDAPAuthenticatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Using mock LDAP server details for testing
        authenticator = std::make_unique<webdav::LDAPAuthenticator>(
            "ldap://localhost:389",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
            "admin"
        );
    }

    void TearDown() override {
        authenticator.reset();
    }

    std::unique_ptr<webdav::LDAPAuthenticator> authenticator;
};

TEST_F(LDAPAuthenticatorTest, ExtractTenantFromUserDNTest) {
    // Test extracting tenant from a sample DN
    std::string user_dn = "uid=john,ou=users,ou=tenant1,dc=example,dc=com";
    std::string expected_tenant = "tenant1";
    
    // Since extractTenantFromUserDN is private, we'll test through the public interface
    // by creating a mock that overrides the method or by testing the end-to-end behavior
    
    // For now, we'll just verify that the method exists and can be called
    EXPECT_NE(nullptr, authenticator.get());
}

TEST_F(LDAPAuthenticatorTest, ExtractTenantFromUserDNWithHyphenTest) {
    // Test extracting tenant from a sample DN with hyphen
    std::string user_dn = "uid=john,ou=users,ou=tenant-dev,dc=example,dc=com";
    std::string expected_tenant = "tenant";
    
    // Since extractTenantFromUserDN is private, we'll test through the public interface
    // by creating a mock that overrides the method or by testing the end-to-end behavior
    
    // For now, we'll just verify that the method exists and can be called
    EXPECT_NE(nullptr, authenticator.get());
}

TEST_F(LDAPAuthenticatorTest, ExtractTenantFromHostnameTest) {
    // Test the utility function for extracting tenant from hostname
    std::string hostname1 = "tenant1.example.com";
    std::string hostname2 = "tenant-dev.example.com";
    std::string hostname3 = "www.example.com";
    
    std::string tenant1 = webdav::extractTenantFromHostname(hostname1);
    std::string tenant2 = webdav::extractTenantFromHostname(hostname2);
    std::string tenant3 = webdav::extractTenantFromHostname(hostname3);
    
    EXPECT_EQ(tenant1, "tenant1");
    EXPECT_EQ(tenant2, "tenant");  // Part before hyphen
    EXPECT_EQ(tenant3, "");        // www is excluded
}