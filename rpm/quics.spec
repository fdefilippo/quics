Name:           quics
Version:        0.2
Release:        1%{?dist}
Summary:        QUIC File Transfer and Remote Command Execution
License:        GPLv3
URL:            https://github.com/fdefilippo/quics
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.16
Requires:       openssl

%description
QUICS is a secure file transfer and remote command execution application 
built on the QUIC protocol using quic-go. It provides mutual TLS authentication,
configurable command whitelisting, and support for running commands as 
specific users/groups on Linux systems.

%prep
%setup -q

%build
make server client

%install
# Create directories
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_sysconfdir}/quics
mkdir -p %{buildroot}%{_sharedstatedir}/quics/files
mkdir -p %{buildroot}%{_datarootdir}/doc/quics

# Install binaries
install -m 0755 bin/quicsd %{buildroot}%{_bindir}/
install -m 0755 bin/quicsc %{buildroot}%{_bindir}/

# Install configuration
install -m 0644 config/server.yaml %{buildroot}%{_sysconfdir}/quics/server.yaml.example
install -m 0644 certs/README.md %{buildroot}%{_datarootdir}/doc/quics/CERTIFICATES.md
install -m 0644 README.md %{buildroot}%{_datarootdir}/doc/quics/

# Create empty certificate directory
mkdir -p %{buildroot}%{_sysconfdir}/quics/certs

%post
# Create runtime directories with correct permissions
if [ ! -d /var/lib/quics/files ]; then
    mkdir -p /var/lib/quics/files
    chmod 0755 /var/lib/quics/files
fi

if [ ! -d /etc/quics/certs ]; then
    mkdir -p /etc/quics/certs
    chmod 0755 /etc/quics/certs
fi

# Generate user configuration directory
if [ ! -d ~/.quicsc ]; then
    mkdir -p ~/.quicsc
    chmod 0700 ~/.quicsc
fi

%postun
# Clean up empty directories on uninstall
if [ $1 -eq 0 ]; then
    # Package removal, not upgrade
    rmdir /var/lib/quics/files 2>/dev/null || true
    rmdir /var/lib/quics 2>/dev/null || true
    rmdir /etc/quics/certs 2>/dev/null || true
    rmdir /etc/quics 2>/dev/null || true
fi

%files
%license LICENSE
%doc README.md certs/README.md
%{_bindir}/quicsd
%{_bindir}/quicsc
%config(noreplace) %{_sysconfdir}/quics/server.yaml.example
%dir %{_sysconfdir}/quics
%dir %{_sysconfdir}/quics/certs
%dir %{_sharedstatedir}/quics
%dir %{_sharedstatedir}/quics/files

%changelog
* Thu Apr 23 2026 Francesco Defilippo <francesco@defilippo.org> - 0.2-1
- Version bump to 0.2: resume upload/download, SHA-256 checksum verification, security fixes
* Mon Apr 21 2025 Francesco Defilippo <francesco@defilippo.org> - 0.1-1
- Initial RPM package
