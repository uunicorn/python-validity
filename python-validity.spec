%global pypi_name validity

Name:           python-%{pypi_name}
Version:        0.12
Release:        1%{?dist}
Summary:        Validity fingerprint sensor driver

License:        MIT
URL:            https://github.com/uunicorn/%{name}
Source0:        %{name}-%{version}.tar.gz
#Source0:        https://github.com/uunicorn/%{name}/archive/%{version}.tar.gz
BuildArch:      noarch


%description
Validity fingerprint sensor driver.


%package -n python3-%{pypi_name}
Summary:        %{summary}

BuildRequires:  python3-devel
BuildRequires:  policycoreutils
BuildRequires:  checkpolicy
BuildRequires:  bzip2
Requires:       policycoreutils
Requires:       innoextract
Requires:       open-fprintd
%{?python_provide:%python_provide python3-%{pypi_name}}


%description -n python3-%{pypi_name}
Validity fingerprint sensor driver.


%prep
%autosetup -n %{name}-%{version}


%build
%py3_build

cd selinux
checkmodule -M -m -o python3-validity.mod python3-validity.te
semodule_package -o python3-validity.pp -m python3-validity.mod
bzip2 python3-validity.pp
cd ..


%install
%py3_install

%__install -d -m 0700 $RPM_BUILD_ROOT%{_sysconfdir}/python-validity
%__install -m 0600 etc/python-validity/dbus-service.yaml $RPM_BUILD_ROOT%{_sysconfdir}/python-validity/

%__install -d -m 0755 $RPM_BUILD_ROOT%{_prefix}/lib/systemd/system
%__install -m 0644 debian/python3-validity.service       $RPM_BUILD_ROOT%{_prefix}/lib/systemd/system/

%__install -d -m 0755 $RPM_BUILD_ROOT%{_prefix}/lib/udev/rules.d
%__install -m 0644 debian/python3-validity.udev          $RPM_BUILD_ROOT%{_prefix}/lib/udev/rules.d/40-python3-validity.udev

%__install -d -m 0755 $RPM_BUILD_ROOT%{_datadir}/selinux/packages
%__install -m 0644 selinux/python3-validity.pp.bz2       $RPM_BUILD_ROOT%{_datadir}/selinux/packages/


%post -n python3-%{pypi_name}
%selinux_modules_install %{_datadir}/selinux/packages/python3-validity.pp.bz2
validity-sensors-firmware || true
systemctl daemon-reload || true
udevadm control --reload-rules || true
udevadm trigger || true
%systemd_post python3-validity.service


%preun -n python3-%{pypi_name}
%systemd_preun python3-validity.service


%postun -n python3-%{pypi_name}
%systemd_postun_with_restart python3-validity.service
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall %{_datadir}/selinux/packages/python3-validity.pp.bz2
fi


%files -n python3-%{pypi_name}
%doc README.md
%license LICENSE
%config(noreplace) %{_sysconfdir}/python-validity/dbus-service.yaml
%{_prefix}/lib/systemd/system/python3-validity.service
%{_prefix}/lib/udev/rules.d/40-python3-validity.udev
%{python3_sitelib}/validitysensor/
%{python3_sitelib}/python_%{pypi_name}-%{version}-py*.egg-info/
%{_bindir}/validity-led-dance
%{_bindir}/validity-sensors-firmware
%{_prefix}/lib/%{name}/dbus-service
%{_datadir}/dbus-1/system.d/io.github.uunicorn.Fprint.conf
%{_datadir}/%{name}/
%{_datadir}/selinux/packages/python3-validity.pp.bz2


%changelog
* Tue Nov 03 2020 Veit Wahlich <cru@zodia.de> - 0.12-1
- Initial build.
