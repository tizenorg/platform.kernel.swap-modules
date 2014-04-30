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
install -m 666 buffer/swap_buffer.ko -t %{buildroot}/opt/swap/sdk
install -m 666 ksyms/swap_ksyms.ko -t %{buildroot}/opt/swap/sdk
install -m 666 driver/swap_driver.ko -t %{buildroot}/opt/swap/sdk
install -m 666 writer/swap_writer.ko -t %{buildroot}/opt/swap/sdk
install -m 666 kprobe/swap_kprobe.ko -t %{buildroot}/opt/swap/sdk
install -m 666 ks_manager/swap_ks_manager.ko -t %{buildroot}/opt/swap/sdk
install -m 666 uprobe/swap_uprobe.ko -t %{buildroot}/opt/swap/sdk
install -m 666 us_manager/swap_us_manager.ko -t %{buildroot}/opt/swap/sdk
install -m 666 ks_features/swap_ks_features.ko -t %{buildroot}/opt/swap/sdk
install -m 666 sampler/swap_sampler.ko -t %{buildroot}/opt/swap/sdk
install -m 666 energy/swap_energy.ko -t %{buildroot}/opt/swap/sdk
install -m 666 parser/swap_message_parser.ko -t %{buildroot}/opt/swap/sdk
install -m 755 start.sh %{buildroot}/opt/swap/sdk
install -m 755 stop.sh %{buildroot}/opt/swap/sdk

%files
%defattr(-,root,root)
/opt/swap/sdk/swap_buffer.ko
/opt/swap/sdk/swap_ksyms.ko
/opt/swap/sdk/swap_driver.ko
/opt/swap/sdk/swap_writer.ko
/opt/swap/sdk/swap_kprobe.ko
/opt/swap/sdk/swap_ks_manager.ko
/opt/swap/sdk/swap_uprobe.ko
/opt/swap/sdk/swap_us_manager.ko
/opt/swap/sdk/swap_ks_features.ko
/opt/swap/sdk/swap_sampler.ko
/opt/swap/sdk/swap_energy.ko
/opt/swap/sdk/swap_message_parser.ko
/opt/swap/sdk/start.sh
/opt/swap/sdk/stop.sh
