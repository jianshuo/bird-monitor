#!/bin/bash
# 生成自包含的 BirdMonitor.app（拷贝 server.py + static 进 Resources），默认装到 ~/Applications
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$HOME/Applications}"
APP="${DEST}/BirdMonitor.app"

mkdir -p "${DEST}"
rm -rf "${APP}"
mkdir -p "${APP}/Contents/MacOS" "${APP}/Contents/Resources/bin"
cp "${HERE}/server.py" "${APP}/Contents/Resources/"
cp -R "${HERE}/static" "${APP}/Contents/Resources/"
cp "${HERE}/bin/bird-monitor" "${APP}/Contents/Resources/bin/"

cat > "${APP}/Contents/MacOS/BirdMonitor" <<'EOF'
#!/bin/bash
# 双击：没在跑就在后台启动监控服务，然后用默认浏览器打开仪表盘
exec "$(dirname "$0")/../Resources/bin/bird-monitor" open
EOF
chmod +x "${APP}/Contents/MacOS/BirdMonitor" "${APP}/Contents/Resources/bin/bird-monitor"

cat > "${APP}/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>BirdMonitor</string>
  <key>CFBundleDisplayName</key><string>BiRD Monitor</string>
  <key>CFBundleIdentifier</key><string>com.wangjianshuo.birdmonitor</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleExecutable</key><string>BirdMonitor</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
</dict>
</plist>
EOF

# 图标：用系统自带的 iCloud 图标（只读复制）
for src in /System/Library/PrivateFrameworks/iCloudDriveCore.framework/Versions/A/Resources/iCloudDrive.icns \
           "/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/iCloudDrive.icns"; do
  if [ -f "$src" ]; then cp "$src" "${APP}/Contents/Resources/AppIcon.icns"; break; fi
done

touch "${APP}"
echo "已生成：${APP}"
