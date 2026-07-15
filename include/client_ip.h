#ifndef WEBDAV_CLIENT_IP_H
#define WEBDAV_CLIENT_IP_H

// Real-client-IP resolution behind a reverse proxy (PROPOSAL §3). The naive "trust
// the first X-Forwarded-For hop" is spoofable, and here it is doubly dangerous: the
// same authoritative IP decides the LAN trusted-CIDR exemption and the session
// gate. Configure FILEENGINE_TRUSTED_PROXIES (comma-separated IPs/CIDRs of the
// reverse proxy). When set, XFF is credible only if the immediate peer is a trusted
// proxy, and the resolved client is the right-most XFF hop that is NOT itself a
// trusted proxy. When unset (development), the socket peer is used. Mirrors
// http_bridge/include/client_ip.h.

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
    if (trusted.empty()) return peer;                 // dev: no XFF trust
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
