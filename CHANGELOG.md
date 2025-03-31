# Changelog

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