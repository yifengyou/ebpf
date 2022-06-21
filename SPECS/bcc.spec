# luajit is not available RHEL 8
%bcond_with lua

%bcond_with llvm_static

%if %{without llvm_static}
%global with_llvm_shared 1
%endif

Name:           bcc
Version:        0.19.0
Release:        5%{?dist}
Summary:        BPF Compiler Collection (BCC)
License:        ASL 2.0
URL:            https://github.com/iovisor/bcc
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Patch0:         %{name}-%{version}-Manpages-remove-unstable-statement.patch
Patch1:         %{name}-%{version}-Fix-BPF-src_file-foo.patch
Patch2:         %{name}-%{version}-Define-missing-BPF_-macros.patch
Patch3:         %{name}-%{version}-fix-llvm-compilation-errors.patch
Patch4:         %{name}-%{version}-Fix-a-llvm-compilation-error.patch
Patch5:         %{name}-%{version}-Remove-APInt-APSInt-toString-std-string-variants.patch
Patch6:         %{name}-%{version}-Handle-renaming-of-task_struct_-state-field-on-RHEL-.patch

# Arches will be included as upstream support is added and dependencies are
# satisfied in the respective arches
ExcludeArch: i686

BuildRequires:  bison
BuildRequires:  cmake >= 2.8.7
BuildRequires:  flex
BuildRequires:  libxml2-devel
BuildRequires:  python3-devel
BuildRequires:  elfutils-libelf-devel
BuildRequires:  llvm-devel
BuildRequires:  clang-devel
%if %{with llvm_static}
BuildRequires:  llvm-static
%endif
BuildRequires:  ncurses-devel
%if %{with lua}
BuildRequires:  pkgconfig(luajit)
%endif
BuildRequires:  libbpf-devel >= 0.0.9, libbpf-static >= 0.0.9

Requires:       libbpf >= 0.0.9
Requires:       tar
Recommends:     kernel-devel
Recommends:     %{name}-tools = %{version}-%{release}

%description
BCC is a toolkit for creating efficient kernel tracing and manipulation
programs, and includes several useful tools and examples. It makes use of
extended BPF (Berkeley Packet Filters), formally known as eBPF, a new feature
that was first added to Linux 3.15. BCC makes BPF programs easier to write,
with kernel instrumentation in C (and includes a C wrapper around LLVM), and
front-ends in Python and lua. It is suited for many tasks, including
performance analysis and network traffic control.


%package devel
Summary:        Shared library for BPF Compiler Collection (BCC)
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The %{name}-devel package contains libraries and header files for developing
application that use BPF Compiler Collection (BCC).


%package doc
Summary:        Examples for BPF Compiler Collection (BCC)
Recommends:     python3-%{name} = %{version}-%{release}
%if %{with lua}
Recommends:     %{name}-lua = %{version}-%{release}
%endif
BuildArch:      noarch

%description doc
Examples for BPF Compiler Collection (BCC)


%package -n python3-%{name}
Summary:        Python3 bindings for BPF Compiler Collection (BCC)
Requires:       %{name}%{?_isa} = %{version}-%{release}
%{?python_provide:%python_provide python3-%{name}}

%description -n python3-%{name}
Python3 bindings for BPF Compiler Collection (BCC)


%if %{with lua}
%package lua
Summary:        Standalone tool to run BCC tracers written in Lua
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description lua
Standalone tool to run BCC tracers written in Lua
%endif


%package tools
Summary:        Command line tools for BPF Compiler Collection (BCC)
Requires:       python3-%{name} = %{version}-%{release}
Requires:       python3-netaddr

%description tools
Command line tools for BPF Compiler Collection (BCC)

%prep
%autosetup -p1

%build
%cmake . \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DREVISION_LAST=%{version} -DREVISION=%{version} -DPYTHON_CMD=python3 \
        -DCMAKE_USE_LIBBPF_PACKAGE:BOOL=TRUE \
        %{?with_llvm_shared:-DENABLE_LLVM_SHARED=1}
%make_build


%install
%make_install

# Fix python shebangs
# This messes the timestamp and rpmdiff complains about it
# Let's set the all thing according to a reference file
touch -r %{buildroot}%{_datadir}/%{name}/examples/hello_world.py %{_tmppath}/timestamp

find %{buildroot}%{_datadir}/%{name}/{tools,examples} -type f -exec \
  sed -i -e '1s=^#!/usr/bin/python\([0-9.]\+\)\?$=#!%{__python3}=' \
         -e '1s=^#!/usr/bin/env python\([0-9.]\+\)\?$=#!%{__python3}=' \
         -e '1s=^#!/usr/bin/env bcc-lua$=#!/usr/bin/bcc-lua=' {} \;

for i in `find %{buildroot}%{_datadir}/%{name}/examples/` ; do
    touch -h -r %{_tmppath}/timestamp $i
done

# Move man pages to the right location
mkdir -p %{buildroot}%{_mandir}
mv %{buildroot}%{_datadir}/%{name}/man/* %{buildroot}%{_mandir}/
# Avoid conflict with other manpages
# https://bugzilla.redhat.com/show_bug.cgi?id=1517408
for i in `find %{buildroot}%{_mandir} -name "*.gz"`; do
  tname=$(basename $i)
  rename $tname %{name}-$tname $i
done
# Fix the symlink too
for i in `find %{buildroot}%{_mandir} -lname \*.gz` ; do
    target=`readlink $i`;
    ln -sf bcc-$target $i;
done

# We cannot run the test suit since it requires root and it makes changes to
# the machine (e.g, IP address)
#%check

%ldconfig_scriptlets

%files
%doc README.md
%license LICENSE.txt
%{_libdir}/lib%{name}.so.*
%{_libdir}/libbcc_bpf.so.*

%files devel
%exclude %{_libdir}/lib%{name}*.a
%exclude %{_libdir}/lib%{name}*.la
%{_libdir}/lib%{name}.so
%{_libdir}/libbcc_bpf.so
%{_libdir}/pkgconfig/lib%{name}.pc
%{_includedir}/%{name}/

%files -n python3-%{name}
%{python3_sitelib}/%{name}*

%files doc
# % dir % {_docdir}/% {name}
%doc %{_datadir}/%{name}/examples/
%if %{without lua}
%exclude %{_datadir}/%{name}/examples/lua
%endif

%files tools
%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/tools
%dir %{_datadir}/%{name}/introspection
%{_datadir}/%{name}/tools/*
%{_datadir}/%{name}/introspection/*
%exclude %{_datadir}/%{name}/tools/old/
# inject relies on BPF_KPROBE_OVERRIDE which is not set on RHEL 8
%exclude %{_datadir}/%{name}/tools/inject
%exclude %{_datadir}/%{name}/tools/doc/inject_example.txt
%exclude %{_mandir}/man8/bcc-inject.8.gz
# Neither btrfs nor zfs are available on RHEL8
%exclude %{_datadir}/%{name}/tools/btrfs*
%exclude %{_datadir}/%{name}/tools/doc/btrfs*
%exclude %{_mandir}/man8/bcc-btrfs*
%exclude %{_datadir}/%{name}/tools/zfs*
%exclude %{_datadir}/%{name}/tools/doc/zfs*
%exclude %{_mandir}/man8/bcc-zfs*
# criticalstat relies on CONFIG_PREEMPTIRQ_EVENTS which is disabled on RHEL 8
%exclude %{_datadir}/%{name}/tools/criticalstat
%exclude %{_datadir}/%{name}/tools/doc/criticalstat_example.txt
%exclude %{_mandir}/man8/bcc-criticalstat.8.gz
# compactsnoop is only supported on x86_64
%ifnarch x86_64
%exclude %{_datadir}/%{name}/tools/compactsnoop
%exclude %{_datadir}/%{name}/tools/doc/compactsnoop_example.txt
%exclude %{_mandir}/man8/bcc-compactsnoop.8.gz
%endif
%{_mandir}/man8/*

%if %{with lua}
%files lua
%{_bindir}/bcc-lua
%endif


%changelog
* Tue Nov 23 2021 Jerome Marchand <jmarchan@redhat.com> - 0.19.0-5
- Handle the renaming of task_struct_>state field
- Rebuild for LLVM 13

* Fri Jul 02 2021 Jerome Marchand <jmarchan@redhat.com> - 0.19.0-4
- Build bcc from standard sources
- Don't require bcc-tools by default

* Wed Jun 09 2021 Jerome Marchand <jmarchan@redhat.com> - 0.19.0-3
- Rebuild on LLVM 12

* Fri Apr 30 2021 Jerome Marchand <jmarchan@redhat.com> - 0.19.0-2
- Fix BPF src_file.

* Tue Apr 27 2021 Jerome Marchand <jmarchan@redhat.com> - 0.19.0-1
- Rebased to version 0.19.0
- Remove hard dependency on kernel-devel

* Fri Jan 22 2021 Jerome Marchand <jmarchan@redhat.com> - 0.16.0-2
- Build with libbpf package
- spec file cleanups

* Mon Oct 26 2020 Jerome Marchand <jmarchan@redhat.com> - 0.16.0-1
- Rebase on bcc-0.16.0
- Fix IPv6 ports

* Wed Sep 02 2020 Jerome Marchand <jmarchan@redhat.com> - 0.14.0-4
- Fix KFUNC_PROBE return value
- Forbid trampolines on unsupported arches

* Tue Jul 21 2020 Jerome Marchand <jmarchan@redhat.com> - 0.14.0-3
- Add KBUILD_MODNAME flag to default cflags

* Thu Jun 11 2020 Jerome Marchand <jmarchan@redhat.com> - 0.14.0-2
- Remove criticalstat manpage
- Remove compactsnoop on non x86_64
- Suggest to use --binary in deadlock
- Remove non-existent argument from tcpconnect man page
- Suggest to install the proper kernel-devel version
- Fix dbstat and dbslower

* Wed Apr 22 2020 Jerome Marchand <jmarchan@redhat.com> - 0.14.0-1
- Rebase on bcc-0.14.0

* Wed Dec 04 2019 Jerome Marchand <jmarchan@redhat.com> - 0.11.0-2
- Add -c option ton the synopsis of tcpretrans manpage

* Tue Nov 26 2019 Jerome Marchand <jmarchan@redhat.com> - 0.11.0-1
- Rebase to bcc-0.11.0
- Reinstate the unstable comment patch that has been removed by mistake

* Thu Oct 17 2019 Jerome Marchand <jmarchan@redhat.com> - 0.10.0-1
- Rebase to bcc-0.10.0
- Drop criticalstat
- Fix regression on vfscount and runqslower
- Rebuild on LLVM 9

* Tue Aug 06 2019 Jerome Marchand <jmarchan@redhat.com> - 0.8.0-4
- remove unstable statement from the man pages

* Wed Jul 03 2019 Jerome Marchand <jmarchan@redhat.com> - 0.8.0-3
- fix b.support_raw_tracepoint
- fix runqslower warning

* Wed May 15 2019 Jerome Marchand <jmarchan@redhat.com> - 0.8.0-2
- Rebuild for llvm 8

* Thu Apr 11 2019 Jerome Marchand <jmarchan@redhat.com> - 0.8.0-1
- Rebase on bcc-8.0.0
- Replace the temporary s390x workaround by a proper fix
- Remove the doc of excluded tool from the package
- Fix print_log2_hist
- Fix yet a few other python3 bytes vs strings issues

* Mon Mar 25 2019 Jerome Marchand <jmarchan@redhat.com> - 0.7.0-6
- Add CI gating

* Thu Dec 13 2018 Jerome Marchand <jmarchan@redhat.com> - 0.7.0-5
- Fix biolatency -D
- Fix biotop manpage
- Rebuild for LLVM 7.0.1 (from Tom Stellard)

* Mon Dec 10 2018 Jerome Marchand <jmarchan@redhat.com> - 0.7.0-4
- Fix bio* tools

* Mon Nov 05 2018 Jerome Marchand <jmarchan@redhat.com> - 0.7.0-3
- Fix multiple bytes/string encoding issues
- Fix misc covscan warning

* Mon Oct 15 2018 Tom Stellard <tstellar@redhat.com> - 0.7.0-2
- Drop explicit dependency on clang-libs

* Fri Oct 12 2018 Jerome Marchand <jmarchan@redhat.com> - 0.7.0-1
- Rebase on bcc-7.0.0
- Remove useless tools (zfs*, btrfs* and inject) 

* Thu Sep 20 2018 Jerome Marchand <jmarchan@redhat.com> - 0.6.1-1
- Rebase on bcc-0.6.1

* Thu Sep 20 2018 Jerome Marchand <jmarchan@redhat.com> - 0.6.0-6
- llcstat: print a nicer error message on virtual machine
- Add NSS support to sslsniff
- Fixes miscellaneous error uncovered by covscan

* Wed Aug 08 2018 Tom Stellard <tstellar@redhat.com> - 0.6.0-5
- Use llvm-toolset-6.0 prefix for clang-libs dependency

* Fri Aug 03 2018 Tom Stellard <tstellar@redhat.com> - 0.6.0-4
- Rebuld for llvm-toolset-6.0

* Wed Jul 18 2018 Jerome Marchand <jmarchan@redhat.com> - 0.6.0-3
 - Disable lua on all arches

* Tue Jun 26 2018 Jerome Marchand <jmarchan@redhat.com> - 0.6.0-2
- Add clang-libs requirement
- Fix manpages symlinks

* Tue Jun 19 2018 Jerome Marchand <jmarchan@redhat.com> - 0.6.0-1
- Rebase on bcc-0.6.0

* Thu May 24 2018 Jerome Marchand <jmarchan@redhat.com> - 0.5.0-5
- Enables build on ppc64(le) and s390x arches

* Thu Apr 05 2018 Rafael Santos <rdossant@redhat.com> - 0.5.0-4
- Resolves #1555627 - fix compilation error with latest llvm/clang

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.5.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Fri Feb 02 2018 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 0.5.0-2
- Switch to %%ldconfig_scriptlets

* Wed Jan 03 2018 Rafael Santos <rdossant@redhat.com> - 0.5.0-1
- Rebase to new released version

* Thu Nov 16 2017 Rafael Santos <rdossant@redhat.com> - 0.4.0-4
- Resolves #1517408 - avoid conflict with other manpages

* Thu Nov 02 2017 Rafael Santos <rdossant@redhat.com> - 0.4.0-3
- Use weak deps to not require lua subpkg on ppc64(le)

* Wed Nov 01 2017 Igor Gnatenko <ignatenkobrain@fedoraproject.org> - 0.4.0-2
- Rebuild for LLVM5

* Wed Nov 01 2017 Rafael Fonseca <rdossant@redhat.com> - 0.4.0-1
- Resolves #1460482 - rebase to new release
- Resolves #1505506 - add support for LLVM 5.0
- Resolves #1460482 - BPF module compilation issue
- Partially address #1479990 - location of man pages
- Enable ppc64(le) support without lua
- Soname versioning for libbpf by ignatenkobrain

* Wed Aug 02 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.3.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.3.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Thu Mar 30 2017 Igor Gnatenko <ignatenko@redhat.com> - 0.3.0-2
- Rebuild for LLVM4
- Trivial fixes in spec

* Fri Mar 10 2017 Rafael Fonseca <rdossant@redhat.com> - 0.3.0-1
- Rebase to new release.

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.2.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Tue Jan 10 2017 Rafael Fonseca <rdossant@redhat.com> - 0.2.0-2
- Fix typo

* Tue Nov 29 2016 Rafael Fonseca <rdossant@redhat.com> - 0.2.0-1
- Initial import
