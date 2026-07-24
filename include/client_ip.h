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

#ifndef WEBDAV_CLIENT_IP_H
#define WEBDAV_CLIENT_IP_H

// Real-client-IP resolution behind a reverse proxy (PROPOSAL §3). The naive "trust
// the first X-Forwarded-For hop" is spoofable, and here it is doubly dangerous: the
// same authoritative IP decides the LAN trusted-CIDR exemption and the session
// gate. Configure FILEENGINE_TRUSTED_PROXIES (comma-separated IPs/CIDRs of the
// reverse proxy). When set, XFF is credible only if the immediate peer is a trusted
// proxy, and the resolved client is the right-most XFF hop that is NOT itself a
// trusted proxy. When unset (development), the first XFF hop is trusted for
// convenience — do NOT run that way in production. Kept identical to
// http_bridge/include/client_ip.h so both bridges resolve the SAME client IP (the
// session gate compares against the IP http_bridge recorded).

#include <string>
#include <vector>

#include <Poco/Net/IPAddress.h>

namespace webdav {

inline bool ipInCidr(const std::string& ip, const std::string& cidr) {
    try {
        Poco::Net::IPAddress addr(ip);
        const auto slash = cidr.find('/');
        if (slash == std::string::npos) return addr == Poco::Net::IPAddress(cidr);
        Poco::Net::IPAddress net(cidr.substr(0, slash));
        const unsigned prefix = static_cast<unsigned>(std::stoul(cidr.substr(slash + 1)));
        if (addr.family() != net.family()) return false;
        Poco::Net::IPAddress mask(prefix, net.family());
        return (addr & mask) == (net & mask);
    } catch (...) {
        return false;
    }
}

inline bool isTrustedProxy(const std::string& ip, const std::vector<std::string>& trusted) {
    for (const auto& c : trusted) if (ipInCidr(ip, c)) return true;
    return false;
}

inline bool ipInAnyCidr(const std::string& ip, const std::vector<std::string>& cidrs) {
    for (const auto& c : cidrs) if (ipInCidr(ip, c)) return true;
    return false;
}

// peer = immediate socket peer; xff = raw X-Forwarded-For; trusted = proxy CIDRs
// (empty => development, return the peer).
inline std::string resolveClientIp(const std::string& peer, const std::string& xff,
                                   const std::vector<std::string>& trusted) {
    auto trim = [](const std::string& s) -> std::string {
        const size_t a = s.find_first_not_of(" \t");
        if (a == std::string::npos) return std::string();
        const size_t b = s.find_last_not_of(" \t");
        return s.substr(a, b - a + 1);
    };
    // Development / no trusted proxies configured: trust the first XFF hop (matches
    // http_bridge so both bridges derive the same client IP). Set
    // FILEENGINE_TRUSTED_PROXIES in production so this convenience can't be spoofed.
    if (trusted.empty()) {
        if (!xff.empty()) {
            const auto c = xff.find(',');
            return trim(c == std::string::npos ? xff : xff.substr(0, c));
        }
        return peer;
    }
    if (!isTrustedProxy(peer, trusted)) return peer;  // direct peer can't spoof via XFF
    if (xff.empty()) return peer;

    std::vector<std::string> hops;
    std::string cur;
    for (char ch : xff) {
        if (ch == ',') { hops.push_back(trim(cur)); cur.clear(); }
        else cur.push_back(ch);
    }
    hops.push_back(trim(cur));
    for (auto it = hops.rbegin(); it != hops.rend(); ++it) {
        if (!it->empty() && !isTrustedProxy(*it, trusted)) return *it;
    }
    return peer;  // every hop was a trusted proxy
}

}  // namespace webdav

#endif  // WEBDAV_CLIENT_IP_H
