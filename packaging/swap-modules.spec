Name: swap-modules
Version: 3.0
Release: 1
License: GPL-2.0+
Summary: Linux profiler
Group: System Environment/Kernel
Vendor: Samsung
Source: swap-modules-3.0.tar.gz

BuildRequires: perl
BuildRequires: python
Provides: swap-modules

%if "%{_repository}" == "emulator32" || "%{_repository}" == "emulator32-wayland"
BuildRequires: emulator-kernel-devel
    %define build_arch i386
    %define kernel_path /usr/src/linux-kernel-build-3.14.25
%else
    %if "%{_repository}" == "arm" || "%{_repository}" == "target-TM1"
BuildRequires: kernel-devel-3.10-sc7730
        %define build_arch arm
        %define kernel_path /boot/kernel/devel/kernel-devel-tizen_tm1
    %else
        %if "%{_repository}" == "arm-wayland"
BuildRequires: arm-trats2-linux-kernel-devel
            %define build_arch arm
            %define kernel_path /usr/src/linux-kernel-build-3.10.60-arm-trats2
	%else
BuildRequires: REPOSITORY_%{_repository}_IS_NOT_SUPPORTED
        %endif
    %endif
%endif


%description
Kernel modules for SWAP

%prep
%setup -q

%build
./build.sh --kernel %kernel_path --arch %build_arch compile

%install
mkdir -p %{buildroot}/opt/swap/sdk
install -m 666 master/swap_master.ko -t %{buildroot}/opt/swap/sdk
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
install -m 666 preload/swap_preload.ko -t %{buildroot}/opt/swap/sdk
install -m 666 fbiprobe/swap_fbiprobe.ko -t %{buildroot}/opt/swap/sdk
install -m 666 wsp/swap_wsp.ko -t %{buildroot}/opt/swap/sdk
install -m 666 nsp/swap_nsp.ko -t %{buildroot}/opt/swap/sdk
install -m 666 task_ctx/swap_taskctx.ko -t %{buildroot}/opt/swap/sdk

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.GPL-2.0+ %{buildroot}/usr/share/license/%{name}

%files
/usr/share/license/%{name}
%defattr(-,root,root)
/opt/swap/sdk/swap_master.ko
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
/opt/swap/sdk/swap_preload.ko
/opt/swap/sdk/swap_fbiprobe.ko
/opt/swap/sdk/swap_wsp.ko
/opt/swap/sdk/swap_nsp.ko
/opt/swap/sdk/swap_taskctx.ko
