Name: swap-modules
Version: 3.0
Release: 1
License: GPL
Summary: Linux profiler
Group: System Environment/Kernel
Vendor: Samsung
Source: swap-modules-3.0.tar.gz
BuildRequires: linux-glibc-devel
BuildRequires: linux-kernel-devel
BuildRequires: perl
BuildRequires: python
Provides: swap-modules
%description
Profiler. Add more words.

%prep
%setup -q

%build

%ifarch i686
./build.sh /usr/src/linux-kernel-build-3.10.33-tizen_defconfig.1 i386
%endif

%ifarch armv7l
./build.sh /usr/src/linux-kernel-build-3.10.33-tizen_defconfig.1 arm
%endif

%install
mkdir -p %{buildroot}/opt/swap/sdk
find . -name "*.ko" -exec install -m 777 -t %{buildroot}/opt/swap/sdk {} \;
strip -x -g %{buildroot}/opt/swap/sdk/swap.ko
install -m 755 start.sh %{buildroot}/opt/swap/sdk
install -m 755 stop.sh %{buildroot}/opt/swap/sdk

%files
%defattr(-,root,root)
/opt/swap/sdk/swap.ko
/opt/swap/sdk/start.sh
/opt/swap/sdk/stop.sh
