Name:           fileengine-webdav-bridge
Version:        1.1.0
Release:        1%{?dist}
Summary:        WebDAV bridge for the FileEngine gRPC core
License:        MIT
URL:            https://github.com/fileengine/fileengine-webdav-bridge
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  cmake, gcc-c++, make, pkgconfig
BuildRequires:  grpc-devel, grpc-plugins, protobuf-devel, protobuf-compiler
BuildRequires:  poco-devel
BuildRequires:  openssl-devel
BuildRequires:  openldap-devel
BuildRequires:  libpq-devel
BuildRequires:  libpqxx-devel
BuildRequires:  systemd-rpm-macros

Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
fileengine-webdav-bridge exposes the FileEngine gRPC core over WebDAV (default
:8080), so standard WebDAV clients can mount a tenant's filesystem. It handles
the full WebDAV verb set, multi-tenancy by sub-domain, LDAP Basic/Digest
authentication, and path-to-UUID resolution backed by PostgreSQL.

Concurrent connections are served from a dedicated, correctly-sized worker pool
(WEBDAV_THREAD_POOL), and a separate reporter listener (default :8089) exposes
/healthz, /readyz, and /poolz for load-balancer health checks.

Ships a systemd unit (runs as a transient DynamicUser) and a default
environment file at /etc/fileengine-webdav-bridge/bridge.env.

%prep
%setup -q -n %{name}-%{version}

%build
mkdir -p build
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}

# Binary (installed under a fileengine-prefixed name to avoid a generic
# /usr/bin/webdav_bridge that could collide with unrelated software).
install -D -m 0755 build/webdav_bridge %{buildroot}%{_bindir}/fileengine-webdav-bridge

# systemd unit.
install -D -m 0644 fileengine-webdav-bridge.service \
    %{buildroot}%{_unitdir}/fileengine-webdav-bridge.service

# Default environment file (config).
install -D -m 0640 webdav-bridge.env \
    %{buildroot}/etc/fileengine-webdav-bridge/bridge.env

%post
%systemd_post fileengine-webdav-bridge.service

%preun
%systemd_preun fileengine-webdav-bridge.service

%postun
%systemd_postun_with_restart fileengine-webdav-bridge.service

%files
%defattr(-,root,root,-)
%attr(0755,root,root) %{_bindir}/fileengine-webdav-bridge
%{_unitdir}/fileengine-webdav-bridge.service
%dir /etc/fileengine-webdav-bridge
%config(noreplace) %attr(0640,root,root) /etc/fileengine-webdav-bridge/bridge.env

%clean
rm -rf %{buildroot}

%changelog
* Fri Jun 26 2026 FileEngine Team <maintainer@fileengine.example.com> - 1.1.0-1
- Sync fileservice.proto to canonical (CULL_VERSIONS permission + ACL RPCs).

* Wed Jun 24 2026 FileEngine Team <maintainer@fileengine.example.com> - 1.0.0-1
- Initial RPM packaging: fileengine-webdav-bridge daemon, systemd unit
  (DynamicUser), and default environment file.
