Name:       amjdesk
Version:    1.2.6
Release:    0
Summary:    RPM package
License:    GPL-3.0
Requires:   gtk3 libxcb libxdo libXfixes alsa-lib libappindicator libvdpau1 libva2 pam gstreamer1-plugins-base

%description
The best open-source remote desktop client software, written in Rust.

%prep
# we have no source, so nothing here

%build
# we have no source, so nothing here

%global __python %{__python3}

%install
mkdir -p %{buildroot}/usr/bin/
mkdir -p %{buildroot}/usr/lib/amjdesk/
mkdir -p %{buildroot}/usr/share/amjdesk/files/
mkdir -p %{buildroot}/usr/share/icons/hicolor/256x256/apps/
mkdir -p %{buildroot}/usr/share/icons/hicolor/scalable/apps/
install -m 755 $HBB/target/release/amjdesk %{buildroot}/usr/bin/amjdesk
install $HBB/libsciter-gtk.so %{buildroot}/usr/lib/amjdesk/libsciter-gtk.so
install $HBB/res/amjdesk.service %{buildroot}/usr/share/amjdesk/files/
install $HBB/res/128x128@2x.png %{buildroot}/usr/share/icons/hicolor/256x256/apps/amjdesk.png
install $HBB/res/scalable.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/amjdesk.svg
install $HBB/res/amjdesk.desktop %{buildroot}/usr/share/amjdesk/files/
install $HBB/res/amjdesk-link.desktop %{buildroot}/usr/share/amjdesk/files/

%files
/usr/bin/amjdesk
/usr/lib/amjdesk/libsciter-gtk.so
/usr/share/amjdesk/files/amjdesk.service
/usr/share/icons/hicolor/256x256/apps/amjdesk.png
/usr/share/icons/hicolor/scalable/apps/amjdesk.svg
/usr/share/amjdesk/files/amjdesk.desktop
/usr/share/amjdesk/files/amjdesk-link.desktop
/usr/share/amjdesk/files/__pycache__/*

%changelog
# let's skip this for now

# https://www.cnblogs.com/xingmuxin/p/8990255.html
%pre
# can do something for centos7
case "$1" in
  1)
    # for install
  ;;
  2)
    # for upgrade
    systemctl stop amjdesk || true
  ;;
esac

%post
cp /usr/share/amjdesk/files/amjdesk.service /etc/systemd/system/amjdesk.service
cp /usr/share/amjdesk/files/amjdesk.desktop /usr/share/applications/
cp /usr/share/amjdesk/files/amjdesk-link.desktop /usr/share/applications/
systemctl daemon-reload
systemctl enable amjdesk
systemctl start amjdesk
update-desktop-database

%preun
case "$1" in
  0)
    # for uninstall
    systemctl stop amjdesk || true
    systemctl disable amjdesk || true
    rm /etc/systemd/system/amjdesk.service || true
  ;;
  1)
    # for upgrade
  ;;
esac

%postun
case "$1" in
  0)
    # for uninstall
    rm /usr/share/applications/amjdesk.desktop || true
    rm /usr/share/applications/amjdesk-link.desktop || true
    update-desktop-database
  ;;
  1)
    # for upgrade
  ;;
esac
