@echo off
REM ============================================================
REM  Pegasus Suite - build the Android APK
REM  Requirements: Node, Android SDK (see android\local.properties),
REM                JDK 17+ and a network connection (first npm install).
REM ============================================================
setlocal
cd /d "%~dp0"

echo [1/3] Capacitor dependencies (if needed)...
if not exist "node_modules" (
  call npm install
  if errorlevel 1 ( echo npm install FAILED & pause & exit /b 1 )
)

echo [2/3] Syncing www -> android ...
call npx cap sync android
if errorlevel 1 ( echo cap sync FAILED & pause & exit /b 1 )

echo [3/3] Building the debug APK ...
cd android
call gradlew.bat assembleDebug
if errorlevel 1 ( echo BUILD FAILED & pause & exit /b 1 )

echo.
echo APK produced: android\app\build\outputs\apk\debug\Pegasus-Suite-debug.apk
echo Install     : adb install -r android\app\build\outputs\apk\debug\Pegasus-Suite-debug.apk
pause
