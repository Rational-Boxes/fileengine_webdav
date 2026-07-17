#ifndef WEBDAV_HARDENING_H
#define WEBDAV_HARDENING_H

#include <map>
#include <mutex>
#include <string>
#include <vector>

struct redisContext;  // forward-declared; hiredis is pulled in only by the .cpp

namespace webdav {

// Config for the WebDAV hardening (PROPOSAL §14/§15), read from the environment.
struct HardeningConfig {
    // --- credential verify (§15) ---
    std::string ldap_manager_url;    // LDAP_MANAGER_URL (e.g. http://127.0.0.1:8093)
    std::string internal_secret;     // SERVICE_CRED_INTERNAL_SECRET (falls back to MFA_INTERNAL_SECRET)
    int verify_cache_ttl = 60;       // WEBDAV_CRED_VERIFY_CACHE_TTL_SECONDS
    int role_cache_ttl = 300;        // WEBDAV_ROLE_CACHE_TTL_SECONDS (LDAP role-lookup cache)

    // --- origin/session gate (§14) ---
    bool gate_enabled = false;       // WEBDAV_IP_BINDING_ENABLED
    bool fail_open = false;          // WEBDAV_IP_BINDING_FAIL_OPEN (external, Redis down)
    bool session_ip = true;          // WEBDAV_EXTERNAL_GATE: session_ip vs session
    // In session_ip mode, IPv6 addresses are matched on their leading /N bits
    // (default 128 = exact). Set to 64 so a client whose IPv6 rotates within its
    // /64 (privacy extensions) still matches its session. IPv4 is always exact,
    // and v4-vs-v6 never matches (no cross-family correlation).
    int session_ip6_prefix = 128;    // WEBDAV_SESSION_IP6_PREFIX (0..128)
    std::vector<std::string> trusted_cidrs;    // WEBDAV_IP_BIND_TRUSTED_CIDRS (LAN exemption)
    std::vector<std::string> trusted_proxies;  // FILEENGINE_TRUSTED_PROXIES

    // --- redis (shared broker) ---
    std::string redis_host = "localhost";
    int redis_port = 6379;
    std::string redis_password;
    int redis_db = 0;

    static HardeningConfig fromEnv();
};

// Compare a session member's IP to the request IP (session_ip mode): IPv4 exact,
// IPv6 on the leading `v6prefix` bits (128 = exact), cross-family never matches.
bool ipMatchesForSession(const std::string& member_ip, const std::string& request_ip,
                         int v6prefix);

enum class GateDecision { Allow, Deny };

// Credential verification (calls ldap_manager's internal verify, cached) + the
// origin-aware session gate (reads the Redis presence set http_bridge writes).
class WebdavHardening {
public:
    explicit WebdavHardening(HardeningConfig cfg);
    ~WebdavHardening();

    const HardeningConfig& config() const { return cfg_; }

    // Verify a Basic key:secret (§15). True + fills out_uid on success; cached for
    // verify_cache_ttl seconds so a PROPFIND storm is one round-trip. `tenant` is
    // the host-derived tenant; scope is always "webdav".
    bool verifyCredential(const std::string& key_id, const std::string& secret,
                          const std::string& tenant, const std::string& source_ip,
                          std::string& out_uid);

    // Origin gate (§14): Allow if the request is inside the trusted LAN CIDRs
    // (static, no Redis — evaluated first) OR the user has a live Web-UI session;
    // Deny otherwise. `via` is set to trusted_cidr / session / denied /
    // redis_unavailable for the audit trail. Only call when gate_enabled.
    GateDecision gate(const std::string& tenant, const std::string& uid,
                      const std::string& ip, std::string& via);

    // Redis-backed cache of a uid's directory role membership (§ perf). The LDAP
    // role lookup runs on EVERY WebDAV request; caching it in the shared broker
    // (TTL = role_cache_ttl, default 5 min) collapses a PROPFIND/save storm to a
    // single LDAP round-trip. Roles are directory-global (LDAP group CNs), so the
    // key is the uid alone. getCachedRoles returns true on a hit (out_roles filled,
    // possibly empty for a role-less user); false on a miss or if Redis is down —
    // the caller then does the live LDAP lookup and calls putCachedRoles.
    bool getCachedRoles(const std::string& uid, std::vector<std::string>& out_roles);
    void putCachedRoles(const std::string& uid, const std::vector<std::string>& roles);

private:
    struct CacheEntry { std::string uid; long expiry; };
    std::mutex cache_mtx_;
    std::map<std::string, CacheEntry> verify_cache_;  // key = key_id + '\0' + secret

    std::mutex redis_mtx_;
    redisContext* ctx_ = nullptr;
    bool ensureConnectedLocked();
    bool hasLiveSessionLocked(const std::string& tenant, const std::string& uid,
                              const std::string& ip, bool& redis_ok);

    HardeningConfig cfg_;
};

}  // namespace webdav

#endif  // WEBDAV_HARDENING_H
