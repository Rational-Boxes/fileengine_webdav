#include "webdav_hardening.h"

#include <ctime>
#include <sstream>

#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/StreamCopier.h>
#include <Poco/Timespan.h>
#include <Poco/URI.h>

#include "client_ip.h"
#include "utils.h"

#ifdef WEBDAV_HAS_HIREDIS
#include <hiredis/hiredis.h>
#endif

namespace webdav {

static std::vector<std::string> splitCidrs(const std::string& csv) {
    std::vector<std::string> out;
    for (auto& s : webdav::splitString(csv, ',')) {
        std::string t = webdav::trim(s);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

// Compare a session member's IP to the request IP for session_ip mode. IPv4 is
// exact; IPv6 matches on the leading `v6prefix` bits (128 = exact). Cross-family
// (v4 vs v6) never matches — there is no correlation between them. Unparseable
// input falls back to exact string equality.
bool ipMatchesForSession(const std::string& a, const std::string& b, int v6prefix) {
    try {
        Poco::Net::IPAddress ia(a), ib(b);
        if (ia.family() != ib.family()) return false;
        if (ia.family() == Poco::Net::IPAddress::IPv6 && v6prefix < 128) {
            Poco::Net::IPAddress mask(static_cast<unsigned>(v6prefix), Poco::Net::IPAddress::IPv6);
            return (ia & mask) == (ib & mask);
        }
        return ia == ib;
    } catch (...) {
        return a == b;
    }
}

HardeningConfig HardeningConfig::fromEnv() {
    HardeningConfig c;
    c.ldap_manager_url = webdav::getEnvOrDefault("LDAP_MANAGER_URL", "");
    c.internal_secret = webdav::getEnvOrDefault("SERVICE_CRED_INTERNAL_SECRET",
                            webdav::getEnvOrDefault("MFA_INTERNAL_SECRET", ""));
    c.verify_cache_ttl = std::stoi(webdav::getEnvOrDefault("WEBDAV_CRED_VERIFY_CACHE_TTL_SECONDS", "60"));
    c.role_cache_ttl = std::stoi(webdav::getEnvOrDefault("WEBDAV_ROLE_CACHE_TTL_SECONDS", "300"));

    std::string en = webdav::getEnvOrDefault("WEBDAV_IP_BINDING_ENABLED", "");
    c.gate_enabled = (en == "1" || en == "true" || en == "yes" || en == "on");
    std::string fo = webdav::getEnvOrDefault("WEBDAV_IP_BINDING_FAIL_OPEN", "");
    c.fail_open = (fo == "1" || fo == "true" || fo == "yes" || fo == "on");
    // session_ip (default) vs session (any-IP). The legacy ip_ttl mode is dropped.
    std::string mode = webdav::getEnvOrDefault("WEBDAV_EXTERNAL_GATE", "session");
    c.session_ip = (mode == "session_ip");
    c.session_ip6_prefix = std::stoi(webdav::getEnvOrDefault("WEBDAV_SESSION_IP6_PREFIX", "128"));
    if (c.session_ip6_prefix < 0) c.session_ip6_prefix = 0;
    if (c.session_ip6_prefix > 128) c.session_ip6_prefix = 128;
    c.trusted_cidrs = splitCidrs(webdav::getEnvOrDefault("WEBDAV_IP_BIND_TRUSTED_CIDRS", ""));
    c.trusted_proxies = splitCidrs(webdav::getEnvOrDefault("FILEENGINE_TRUSTED_PROXIES", ""));

    c.redis_host = webdav::getEnvOrDefault("FILEENGINE_REDIS_HOST", "localhost");
    c.redis_port = std::stoi(webdav::getEnvOrDefault("FILEENGINE_REDIS_PORT", "6379"));
    c.redis_password = webdav::getEnvOrDefault("FILEENGINE_REDIS_PASSWORD",
                           webdav::getEnvOrDefault("REDDIS_PASSWORD", ""));
    c.redis_db = std::stoi(webdav::getEnvOrDefault("FILEENGINE_REDIS_DB", "0"));
    return c;
}

WebdavHardening::WebdavHardening(HardeningConfig cfg) : cfg_(std::move(cfg)) {}

WebdavHardening::~WebdavHardening() {
#ifdef WEBDAV_HAS_HIREDIS
    if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
#endif
}

bool WebdavHardening::verifyCredential(const std::string& key_id, const std::string& secret,
                                       const std::string& tenant, const std::string& source_ip,
                                       std::string& out_uid) {
    if (cfg_.ldap_manager_url.empty() || cfg_.internal_secret.empty()) {
        webdav::errorLog("verifyCredential: LDAP_MANAGER_URL / internal secret unset — cannot verify");
        return false;
    }
    const std::string cacheKey = key_id + std::string(1, '\0') + secret;
    const long now = static_cast<long>(std::time(nullptr));
    {
        std::lock_guard<std::mutex> g(cache_mtx_);
        auto it = verify_cache_.find(cacheKey);
        if (it != verify_cache_.end() && it->second.expiry > now) {
            out_uid = it->second.uid;
            return true;
        }
    }
    try {
        Poco::URI uri(cfg_.ldap_manager_url + "/internal/service-cred/verify");
        Poco::Net::HTTPClientSession session(uri.getHost(), uri.getPort());
        session.setTimeout(Poco::Timespan(3, 0));
        std::string path = uri.getPathAndQuery();
        if (path.empty()) path = "/";
        Poco::Net::HTTPRequest req(Poco::Net::HTTPRequest::HTTP_POST, path,
                                   Poco::Net::HTTPMessage::HTTP_1_1);
        req.setContentType("application/json");
        req.add("X-Internal-Auth", cfg_.internal_secret);

        Poco::JSON::Object body;
        body.set("key_id", key_id);
        body.set("secret", secret);
        body.set("tenant", tenant);
        body.set("scope", "webdav");
        if (!source_ip.empty()) body.set("source_ip", source_ip);
        std::ostringstream os;
        body.stringify(os);
        const std::string bs = os.str();
        req.setContentLength(static_cast<std::streamsize>(bs.size()));
        session.sendRequest(req) << bs;

        Poco::Net::HTTPResponse resp;
        std::istream& rs = session.receiveResponse(resp);
        std::string respBody;
        Poco::StreamCopier::copyToString(rs, respBody);
        if (resp.getStatus() != Poco::Net::HTTPResponse::HTTP_OK) return false;

        Poco::JSON::Parser p;
        auto o = p.parse(respBody).extract<Poco::JSON::Object::Ptr>();
        const std::string uid = o->optValue<std::string>("uid", std::string());
        if (uid.empty()) return false;
        out_uid = uid;
        {
            std::lock_guard<std::mutex> g(cache_mtx_);
            verify_cache_[cacheKey] = {uid, now + cfg_.verify_cache_ttl};
        }
        return true;
    } catch (const std::exception& e) {
        webdav::warnLog(std::string("verifyCredential: ldap_manager call failed: ") + e.what());
        return false;
    } catch (...) {
        return false;
    }
}

GateDecision WebdavHardening::gate(const std::string& tenant, const std::string& uid,
                                   const std::string& ip, std::string& via) {
    // LAN branch first: static config, no Redis — the outage-survival path (§5.7).
    if (webdav::ipInAnyCidr(ip, cfg_.trusted_cidrs)) { via = "trusted_cidr"; return GateDecision::Allow; }

    // Internet branch: require a live Web-UI session (§14).
    bool redis_ok = false;
    std::lock_guard<std::mutex> g(redis_mtx_);
    const bool live = hasLiveSessionLocked(tenant, uid, ip, redis_ok);
    if (!redis_ok) {
        via = "redis_unavailable";
        return cfg_.fail_open ? GateDecision::Allow : GateDecision::Deny;  // fail-closed by default
    }
    if (live) { via = "session"; return GateDecision::Allow; }
    via = "denied";
    return GateDecision::Deny;
}

#ifdef WEBDAV_HAS_HIREDIS
bool WebdavHardening::ensureConnectedLocked() {
    if (ctx_ && !ctx_->err) return true;
    if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
    ctx_ = redisConnect(cfg_.redis_host.c_str(), cfg_.redis_port);
    if (!ctx_ || ctx_->err) { if (ctx_) { redisFree(ctx_); ctx_ = nullptr; } return false; }
    if (!cfg_.redis_password.empty()) {
        auto* r = static_cast<redisReply*>(redisCommand(ctx_, "AUTH %s", cfg_.redis_password.c_str()));
        bool ok = r && r->type != REDIS_REPLY_ERROR;
        if (r) freeReplyObject(r);
        if (!ok) { redisFree(ctx_); ctx_ = nullptr; return false; }
    }
    if (cfg_.redis_db != 0) {
        auto* r = static_cast<redisReply*>(redisCommand(ctx_, "SELECT %d", cfg_.redis_db));
        bool ok = r && r->type != REDIS_REPLY_ERROR;
        if (r) freeReplyObject(r);
        if (!ok) { redisFree(ctx_); ctx_ = nullptr; return false; }
    }
    return true;
}

// redis_mtx_ held. Purge expired members, then test presence (session) or a member
// whose IP suffix matches (session_ip). redis_ok distinguishes "no live session"
// from "couldn't reach Redis" (which drives fail-open/closed).
bool WebdavHardening::hasLiveSessionLocked(const std::string& tenant, const std::string& uid,
                                           const std::string& ip, bool& redis_ok) {
    redis_ok = false;
    if (!ensureConnectedLocked()) return false;
    const std::string key = "webdav:session:" + tenant + ":" + uid;
    const long now = static_cast<long>(std::time(nullptr));

    auto* purge = static_cast<redisReply*>(redisCommand(
        ctx_, "ZREMRANGEBYSCORE %s 0 %ld", key.c_str(), now));
    if (!purge || ctx_->err) {
        if (purge) freeReplyObject(purge);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;
    }
    freeReplyObject(purge);

    auto* r = static_cast<redisReply*>(redisCommand(ctx_, "ZRANGE %s 0 -1", key.c_str()));
    if (!r || ctx_->err) {
        if (r) freeReplyObject(r);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;
    }
    redis_ok = true;
    bool found = false;
    if (r->type == REDIS_REPLY_ARRAY) {
        if (!cfg_.session_ip) {
            found = r->elements > 0;                 // any live session
        } else {
            for (size_t i = 0; i < r->elements && !found; ++i) {
                const auto* e = r->element[i];
                std::string m(e->str, e->len);       // "{jti}|{ip}"
                const auto bar = m.rfind('|');
                if (bar != std::string::npos &&
                    ipMatchesForSession(m.substr(bar + 1), ip, cfg_.session_ip6_prefix)) found = true;
            }
        }
    }
    freeReplyObject(r);
    return found;
}

bool WebdavHardening::getCachedRoles(const std::string& uid, std::vector<std::string>& out_roles) {
    if (uid.empty()) return false;
    std::lock_guard<std::mutex> g(redis_mtx_);
    if (!ensureConnectedLocked()) return false;
    const std::string key = "webdav:roles:" + uid;
    auto* r = static_cast<redisReply*>(redisCommand(ctx_, "GET %s", key.c_str()));
    if (!r || ctx_->err) {
        if (r) freeReplyObject(r);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;                 // Redis error -> treat as a miss (caller hits LDAP)
    }
    bool hit = false;
    if (r->type == REDIS_REPLY_STRING) {   // present (even empty) = hit; NIL = miss
        out_roles.clear();
        const std::string v(r->str, r->len);   // roles are newline-joined; empty = role-less user
        size_t start = 0;
        while (start < v.size()) {
            size_t nl = v.find('\n', start);
            const size_t end = (nl == std::string::npos) ? v.size() : nl;
            if (end > start) out_roles.emplace_back(v.substr(start, end - start));
            if (nl == std::string::npos) break;
            start = nl + 1;
        }
        hit = true;
    }
    freeReplyObject(r);
    return hit;
}

void WebdavHardening::putCachedRoles(const std::string& uid, const std::vector<std::string>& roles) {
    if (uid.empty() || cfg_.role_cache_ttl <= 0) return;
    std::lock_guard<std::mutex> g(redis_mtx_);
    if (!ensureConnectedLocked()) return;
    std::string val;
    for (size_t i = 0; i < roles.size(); ++i) { if (i) val += '\n'; val += roles[i]; }
    const std::string key = "webdav:roles:" + uid;
    auto* r = static_cast<redisReply*>(redisCommand(ctx_, "SETEX %s %d %b",
        key.c_str(), cfg_.role_cache_ttl, val.data(), val.size()));
    if (!r || ctx_->err) {
        if (r) freeReplyObject(r);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return;                       // best-effort; a failed cache write just means a future miss
    }
    freeReplyObject(r);
}
#else
bool WebdavHardening::ensureConnectedLocked() { return false; }
bool WebdavHardening::hasLiveSessionLocked(const std::string&, const std::string&,
                                           const std::string&, bool& redis_ok) {
    redis_ok = false;  // built without hiredis: cannot check → gate() fails closed/open per config
    return false;
}
// No hiredis: no cache -> every request resolves roles via LDAP (correct, just chattier).
bool WebdavHardening::getCachedRoles(const std::string&, std::vector<std::string>&) { return false; }
void WebdavHardening::putCachedRoles(const std::string&, const std::vector<std::string>&) {}
#endif

}  // namespace webdav
