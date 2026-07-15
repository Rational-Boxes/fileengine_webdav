#ifndef WEBSERVICE_SERVER_H
#define WEBSERVICE_SERVER_H

#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/ThreadPool.h>
#include <Poco/Util/ServerApplication.h>
#include <Poco/URI.h>
#include <Poco/Path.h>
#include <Poco/Exception.h>
#include <Poco/SharedPtr.h>
#include <Poco/Format.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <memory>
#include <string>
#include <map>

#include "grpc_client_wrapper.h"
#include "path_resolver.h"
#include "ldap_authenticator.h"
#include "webdav_hardening.h"
#include "utils.h"

namespace webdav {

class WebDAVRequestHandler : public Poco::Net::HTTPRequestHandler {
public:
    WebDAVRequestHandler(
        std::shared_ptr<GRPCClientWrapper> grpc_client,
        std::shared_ptr<PathResolver> path_resolver,
        std::shared_ptr<LDAPAuthenticator> ldap_auth,
        std::shared_ptr<WebdavHardening> hardening)
        : grpc_client_(grpc_client)
        , path_resolver_(path_resolver)
        , ldap_auth_(ldap_auth)
        , hardening_(hardening) {}

    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;

private:
    void handleGet(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handlePut(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleMkcol(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleDelete(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handlePropfind(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleProppatch(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleCopy(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleMove(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleLock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleUnlock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);
    void handleOptions(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response);

    std::string extractTenantFromHost(const std::string& host);
    bool authenticateUser(Poco::Net::HTTPServerRequest& request, std::string& user, std::string& tenant, std::vector<std::string>& roles);

    // COPY/MOVE destination guard (security review M4). Validates the Destination
    // authority against the request host and enforces RFC 4918 Overwrite: an
    // existing target with Overwrite:F yields 412; with Overwrite:T (default) the
    // target is deleted first, which the core permission-checks (403 if denied).
    // On any failure it emits the response and returns false; true means proceed.
    bool prepareDestination(Poco::Net::HTTPServerRequest& request,
                            Poco::Net::HTTPServerResponse& response,
                            const Poco::URI& dest_uri, const std::string& dest_path,
                            const fileengine_rpc::AuthenticationContext& auth_ctx,
                            const std::string& tenant);

    std::shared_ptr<GRPCClientWrapper> grpc_client_;
    std::shared_ptr<PathResolver> path_resolver_;
    std::shared_ptr<LDAPAuthenticator> ldap_auth_;
    std::shared_ptr<WebdavHardening> hardening_;
};

class WebDAVRequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    WebDAVRequestHandlerFactory(
        std::shared_ptr<GRPCClientWrapper> grpc_client,
        std::shared_ptr<PathResolver> path_resolver,
        std::shared_ptr<LDAPAuthenticator> ldap_auth,
        std::shared_ptr<WebdavHardening> hardening)
        : grpc_client_(grpc_client)
        , path_resolver_(path_resolver)
        , ldap_auth_(ldap_auth)
        , hardening_(hardening) {}

    Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest& request) override {
        return new WebDAVRequestHandler(grpc_client_, path_resolver_, ldap_auth_, hardening_);
    }

private:
    std::shared_ptr<GRPCClientWrapper> grpc_client_;
    std::shared_ptr<PathResolver> path_resolver_;
    std::shared_ptr<LDAPAuthenticator> ldap_auth_;
    std::shared_ptr<WebdavHardening> hardening_;
};

class WebDAVServer {
public:
    WebDAVServer(const std::string& host, int port);
    ~WebDAVServer();

    void start();
    void stop();

private:
    std::string host_;
    int port_;
    int thread_pool_ = 16;       // WEBDAV_THREAD_POOL — max concurrent connections
    // Unauthenticated reporter listener — binds to loopback by default so it is
    // protected by network isolation rather than auth (WEBDAV_MONITORING_HOST).
    std::string monitoring_host_ = "127.0.0.1";
    int monitoring_port_ = 8089; // WEBDAV_MONITORING_PORT — dedicated reporter listener
    std::vector<std::string> monitoring_allow_ips_; // optional client-IP allowlist for the monitor (security review L2)
    std::unique_ptr<Poco::Net::ServerSocket> socket_;
    Poco::Net::HTTPServerParams::Ptr server_params_;
    // Dedicated worker pool sized to thread_pool_; declared before server_ so it
    // outlives the server (each long-lived transfer pins one of these threads).
    std::unique_ptr<Poco::ThreadPool> pool_;
    std::unique_ptr<Poco::Net::HTTPServer> server_;
    // Dedicated reporter: a single held-back thread + listener, so pool usage /
    // health stay answerable even when every worker thread is mid-transfer.
    std::unique_ptr<Poco::ThreadPool> monitor_pool_;
    std::unique_ptr<Poco::Net::HTTPServer> monitor_server_;
    std::shared_ptr<GRPCClientWrapper> grpc_client_;
    std::shared_ptr<PathResolver> path_resolver_;
    std::shared_ptr<LDAPAuthenticator> ldap_auth_;
    std::shared_ptr<WebdavHardening> hardening_;
};

} // namespace webdav

#endif // WEBSERVICE_SERVER_H