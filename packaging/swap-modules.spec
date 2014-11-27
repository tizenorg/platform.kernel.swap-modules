Name: swap-modules
Version: 3.0
Release: 1
License: GPL
Summary: Linux profiler
Group: System Environment/Kernel
Vendor: Samsung
Source: swap-modules-3.0.tar.gz

BuildRequires: perl
BuildRequires: python
%ifarch %{arm}
%define build_arch arm
%if "%_project" != "Tizen:2.3" && "%_project" != "Kirana_SWA_OPEN:Build"
BuildRequires: NotSupportedProject
%else
%if "%_project" == "Tizen:2.3"
BuildRequires: linux-kernel-devel
%define kernel_path /usr/src/linux-kernel-build-3.0.15-tizen_defconfig.1
%endif
%if "%_project" == "Kirana_SWA_OPEN:Build"
BuildRequires: kernel-devel-tizen-dev
%define kernel_path /var/tmp/kernel/devel/kernel-devel-tizen_kiran_2g
%endif
%endif
%else
%define build_arch i386
BuildRequires: emulator-kernel-devel
%define kernel_path /usr/src/linux-kernel-build-3.12.18
%endif
Provides: swap-modules
%description
Kernel modules for SWAP

%prep
%setup -q

%build
./build.sh %kernel_path %build_arch

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
install -m 666 retprobe/swap_retprobe.ko -t %{buildroot}/opt/swap/sdk
install -m 666 webprobe/swap_webprobe.ko -t %{buildroot}/opt/swap/sdk

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
/opt/swap/sdk/swap_retprobe.ko
/opt/swap/sdk/swap_webprobe.ko
