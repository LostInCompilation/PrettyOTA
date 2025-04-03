# Changelog

## Version: 1.0.5

- Updated README with better documentation
- Added donation option

## Version: 1.0.4

- Fixed a bug where long strings for app version, build time and date would break the website formatting

## Version: 1.0.3

- Updated keywords.txt for ArduinoIDE
- Finished README
- Fixed README header logo
- Fixed README TOC for PlatformIO

## Version: 1.0.2

- Fixed PlatformIO release

## Version: 1.0.1

- Added `PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE` macro, `OverwriteAppBuildTimeAndDate(...)` and `OverwriteAppVersion(...)` to overwrite the build time, build date and app version which get displayed on the website. This is needed when using the ArduinoIDE. See README for details
- Added mDNS example
- Added setCustomVersionAndBuildTime example
- Fixed examples
- Fixed dependencies for ArduinoIDE
- Updated README

## Version: 1.0.0

- Backend rewrite and code cleanup for performance optimization
- Reduced code size
- UI improvements and cleanup
- Support for custom URLs (ability to change the default `/update` and `/login` URLs)
- Renamed internal URLs to avoid name conflicts
- Added a "Log out" button to website
- Save and restore logged in clients to NVS automatically. Clients will stay logged in even after a reboot or update of the ESP32
- Removed dependency on Arduino MD5Builder
- Added compile checks for incompatible libraries/boards
- Wrote own low level ESP update manager and removed Arduino dependency
- Switched to `std::string` instead of Arduino `String`
- Fixed a bug where every unauthenticated request would get redirected to the login page, even for POST requests
- Many more changes for usability and performance

## Version 0.3.8

- Initial release
