/*

Copyright (c) 2025 Marc Schöndorf

Permission is granted to anyone to use this software for private and
commercial applications, to alter it and redistribute it, subject to
the following conditions:

1. The origin of this software must not be misrepresented. You must not
   claim that you wrote the original software. If you use this Software
   in a product, acknowledgment in the product documentation or credits is required.

2. Altered source versions must be plainly marked as such, and must not
   be misrepresented as being the original software.

3. You are not permitted to modify, replace or remove the name "PrettyOTA"
   or the original logo displayed within the Software's default user interface (if applicable),
   unless you have obtained a separate commercial license granting you such rights.
   This restriction applies even when redistributing modified versions of the source code.

4. This license notice must not be removed or altered from any source code distribution.

Disclaimer:
The software is provided "as is", without warranty of any kind, express
or implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and non-infringement.
In no event shall the authors or copyright holders be liable for any claim,
damages or other liability, whether in an action of contract, tort or otherwise,
arising from, out of or in connection with the software or the use or other
dealings in the software.


******************************************************
*                    PRETTY OTA                      *
*                                                    *
* A better looking Web-OTA.                          *
******************************************************

Description:
    PrettyOTA is a modern, user-friendly Over-The-Air (OTA) update solution for ESP32 devices.

    The main header file. Include this file in your project.

*/

#pragma once

// ********************************************************
// Library configuration options
#ifndef PRETTY_OTA_ENABLE_ARDUINO_OTA
    #define PRETTY_OTA_ENABLE_ARDUINO_OTA 1
#endif

// Development features (not for public use)
#define DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING 0 // Work in progress feature


// ********************************************************
// Standard library includes
#include <string>
#include <vector>
#include <new> //std::nothrow

// Arduino core includes
#include <Arduino.h>
#include <ArduinoJson.h>

#if (PRETTY_OTA_ENABLE_ARDUINO_OTA == 1)
    #include <ArduinoOTA.h>
#endif

// ESP-IDF includes
#include <esp_err.h>
#include <esp_ota_ops.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <mdns.h>

// External dependencies
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>

// PrettyOTA internal includes
#include "CustomTypes.h"
#include "MD5Hasher.h"
#include "ESPUpdateManager.h"

#if (DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING == 1)
    #include "FirmwarePullManager.h"
#endif

// ********************************************************
// Compile checks
#ifndef ESP32
    #error PrettyOTA only supports ESP32 devices. Support for RaspberryPi Pico W will follow soon.
#endif

// Dependency version checks
#if !defined(ASYNCWEBSERVER_VERSION) || ASYNCWEBSERVER_VERSION_MAJOR < 3
    #error PrettyOTA needs the "ESPAsyncWebServer" library (from ESP32Async) version 3.0 or newer. If you have it installed, make sure you only have one library with the name "ESPAsyncWebServer" installed (there are two libraries with the same name).
#endif

#if !defined(ARDUINOJSON_VERSION_MAJOR) || ARDUINOJSON_VERSION_MAJOR < 7
    #error PrettyOTA needs the "ArduinoJson" library version 7.0 or newer.
#endif

/**
 * @class PrettyOTA
 * @brief Main class for handling OTA updates with a beautiful web interface
 *
 * PrettyOTA provides a modern and user-friendly way to perform Over-The-Air updates
 * on ESP32 devices.
 */
class PrettyOTA
{
private:
    // Version information
    static const uint8_t    PRETTY_OTA_VERSION_MAJOR = 2;
    static const uint8_t    PRETTY_OTA_VERSION_MINOR = 0;
    static const uint8_t    PRETTY_OTA_VERSION_REVISION = 0;

    // Task configuration
    static const uint32_t   BACKGROUND_TASK_STACK_SIZE = 3072;
    static const uint8_t    BACKGROUND_TASK_PRIORITY = 4;

    // Authentication limits
    static const uint8_t    MAX_NUM_LOGGED_IN_CLIENTS = 5;

    // Embedded web resources
    static const uint8_t    PRETTY_OTA_WEBSITE_DATA[12706];
    static const uint8_t    PRETTY_OTA_LOGIN_DATA[6208];

private:
    // UUID type definition and helper methods
    using UUID_t = uint8_t[16];

    /**
     * @brief Generates a new UUID
     * @param out_uuid Pointer to store the generated UUID
     */
    void        GenerateUUID(UUID_t* out_uuid) const;

    /**
     * @brief Converts a UUID to a string representation
     * @param uuid The UUID to convert
     * @return String representation of the UUID
     */
    std::string UUIDToString(const UUID_t uuid) const;

private:
    // Static configuration variables
    static std::string  m_AppBuildTime;    // Application build time
    static std::string  m_AppBuildDate;    // Application build date
    static std::string  m_AppVersion;      // Application version
    static std::string  m_HardwareID;      // Unique hardware identifier

    // URL configuration
    std::string         m_LoginURL = "";   // URL for login page
    std::string         m_MainURL = "";    // URL for main update page

    // Core components
    static Stream*      m_SerialMonitorStream;  // Stream for logging
    AsyncWebServer*     m_Server = nullptr;     // Web server instance
    NSPrettyOTA::ESPUpdateManager m_UpdateManager;  // Manages ESP32 updates

#if (DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING == 1)
    NSPrettyOTA::FirmwarePullManager m_FirmwarePullManager;  // Manages firmware pulling
#endif

    // State tracking
    bool                m_IsInitialized = false;     // Whether PrettyOTA is initialized
    bool                m_IsUpdateRunning = false;   // Whether an update is in progress
    bool                m_AutoRebootEnabled = true;  // Whether to auto-reboot after update
    bool                m_RequestReboot = false;     // Whether a reboot has been requested
    static bool         m_DefaultCallbackPrintWithColor;  // Whether to use colored output
    uint32_t            m_RebootRequestTime = 0;     // Time when reboot was requested

    // Authentication
    bool                m_AuthenticationEnabled = false;  // Whether authentication is enabled
    std::string         m_Username = "";    // Username for authentication
    std::string         m_Password = "";    // Password for authentication
    std::vector<std::string> m_AuthenticatedSessionIDs;  // List of active session IDs

    // User callback functions
    std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> m_OnStartUpdate = nullptr;
    std::function<void(uint32_t currentSize, uint32_t totalSize)> m_OnProgressUpdate = nullptr;
    std::function<void(bool successful)> m_OnEndUpdate = nullptr;

private:
    // Default callback implementations
    static void OnOTAStart(NSPrettyOTA::UPDATE_MODE updateMode);
    static void OnOTAProgress(uint32_t currentSize, uint32_t totalSize);
    static void OnOTAEnd(bool successful);

    // Internal logging methods
    static void P_LOG_I(const std::string& message);
    static void P_LOG_W(const std::string& message);
    static void P_LOG_E(const std::string& message);

    // Methods
    static void BackgroundTask(void* parameter);  // Background task for updates

    /**
     * @brief Enables Arduino OTA functionality
     * @param password Password for Arduino OTA
     * @param passwordIsMD5Hash Whether the password is already an MD5 hash
     * @param OTAport Port for Arduino OTA
     */
    void EnableArduinoOTA(const char* const password, bool passwordIsMD5Hash, uint16_t OTAport);

    /**
     * @brief Checks if a request is authenticated
     * @param request The web request to check
     * @return true if authenticated, false otherwise
     */
    bool IsAuthenticated(const AsyncWebServerRequest* const request) const;

    /**
     * @brief Saves session IDs to NVS storage
     * @return true if successful, false otherwise
     */
    bool SaveSessionIDsToNVS();

    /**
     * @brief Loads session IDs from NVS storage
     * @return true if successful, false otherwise
     */
    bool LoadSessionIDsFromNVS();

    /**
     * @brief Gets the version as a string
     * @return Version string in format "major.minor.revision"
     */
    std::string GetVersionAsString() const;

    //std::string SHA256ToString(const uint8_t hash[32]) const;

public:
    /**
     * @brief Default constructor
     */
    PrettyOTA() = default;

    /**
     * @brief Initializes the PrettyOTA update system
     *
     * Sets up the web server routes, authentication, and Arduino OTA if enabled.
     * This method must be called before using any other PrettyOTA functionality.
     *
     * @param server Pointer to an existing AsyncWebServer instance
     * @param username Optional username for web interface authentication
     * @param password Optional password for web interface authentication
     * @param passwordIsMD5Hash Whether the password is already an MD5 hash
     * @param mainURL URL path for the main update page (default: "/update")
     * @param loginURL URL path for the login page (default: "/login")
     * @param OTAport Port for Arduino OTA (default: 3232)
     * @return true if initialization successful, false otherwise
     */
    bool Begin(AsyncWebServer* const server,
               const char* const username = "",
               const char* const password = "",
               bool passwordIsMD5Hash = false,
               const char* const mainURL = "/update",
               const char* const loginURL = "/login",
               uint16_t OTAport = 3232);

    /**
     * @brief Sets or changes authentication details
     *
     * Updates the username and password required for accessing the web interface.
     * Can be called after Begin() to change authentication settings.
     *
     * @param username Username for authentication
     * @param password Password for authentication
     * @param passwordIsMD5Hash Whether the password is already an MD5 hash
     */
    void SetAuthenticationDetails(const char* const username,
                                  const char* const password,
                                  bool passwordIsMD5Hash = false);

#if (DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING == 1)
    /**
     * @brief Initiates a firmware pull operation (development feature)
     *
     * @param customFilter Custom filter for firmware selection
     * @return true if pull operation started successfully
     */
    bool DoFirmwarePull(const char* const customFilter);
#endif

    /**
     * @brief Checks if an update is currently in progress
     *
     * @return true if an update is running, false otherwise
     */
    bool IsUpdateRunning() const { return m_IsUpdateRunning; }

    /**
     * @brief Sets callback function for update start events
     *
     * This callback is triggered when an OTA update begins.
     *
     * @param func Function to call when update starts
     */
    void OnStart(std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> func) { m_OnStartUpdate = func; }

    /**
     * @brief Sets callback function for update progress events
     *
     * This callback is triggered periodically during an update to report progress.
     *
     * @param func Function to call during update progress
     */
    void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func) { m_OnProgressUpdate = func; }

    /**
     * @brief Sets callback function for update completion events
     *
     * This callback is triggered when an update finishes, either successfully or with failure.
     *
     * @param func Function to call when update completes
     */
    void OnEnd(std::function<void(bool successful)> func) { m_OnEndUpdate = func; }

    /**
     * @brief Configures PrettyOTA to use the built-in callback implementations
     *
     * The default callbacks display formatted progress information in the serial monitor.
     *
     * @param printWithColor Whether to use ANSI color codes in the output
     */
    void UseDefaultCallbacks(bool printWithColor = false);

    /**
     * @brief Sets the hardware ID
     *
     * This ID is displayed in the web interface and can help identify different devices.
     *
     * @param hardwareID Unique identifier for the hardware/board
     */
    void SetHardwareID(const char* const hardwareID) { m_HardwareID = hardwareID; }

    /**
     * @brief Sets the application version string
     *
     * This version is displayed in the web interface.
     *
     * @param appVersion Version string (e.g., "1.0.0")
     */
    static void SetAppVersion(const char* const appVersion);

    // Deprecated alias for backwards compatibility
    [[deprecated("Use SetAppVersion() instead.")]]
    static constexpr auto OverwriteAppVersion = SetAppVersion;

    /**
     * @brief Sets the application build time and date
     * @param appBuildTime Build time string
     * @param appBuildDate Build date string
     */
    static void SetAppBuildTimeAndDate(const char* const appBuildTime, const char* const appBuildDate);

    // Deprecated alias for backwards compatibility
    [[deprecated("Use SetAppBuildTimeAndDate() instead.")]]
    static constexpr auto OverwriteAppBuildTimeAndDate = SetAppBuildTimeAndDate;

    /**
     * @brief Sets the stream for log messages
     *
     * @param serialStream Pointer to Stream object (e.g., &Serial)
     */
    void SetSerialOutputStream(Stream* const serialStream) { m_SerialMonitorStream = serialStream; }
};

/**
 * @brief Helper macro to set the current build time and date
 *
 * Uses the __TIME__ and __DATE__ compiler macros to set the build information.
 */
#define PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE() PrettyOTA::SetAppBuildTimeAndDate(__TIME__, __DATE__)

const char version[6+1] =
{
   // YY year
   __DATE__[9], __DATE__[10],

   // First month letter, Oct Nov Dec = '1' otherwise '0'
   (__DATE__[0] == 'O' || __DATE__[0] == 'N' || __DATE__[0] == 'D') ? '1' : '0',

   // Second month letter
   (__DATE__[0] == 'J') ? ( (__DATE__[1] == 'a') ? '1' :       // Jan, Jun or Jul
                            ((__DATE__[2] == 'n') ? '6' : '7') ) :
   (__DATE__[0] == 'F') ? '2' :                                // Feb
   (__DATE__[0] == 'M') ? (__DATE__[2] == 'r') ? '3' : '5' :   // Mar or May
   (__DATE__[0] == 'A') ? (__DATE__[1] == 'p') ? '4' : '8' :   // Apr or Aug
   (__DATE__[0] == 'S') ? '9' :                                // Sep
   (__DATE__[0] == 'O') ? '0' :                                // Oct
   (__DATE__[0] == 'N') ? '1' :                                // Nov
   (__DATE__[0] == 'D') ? '2' :                                // Dec
   0,

   // First day letter, replace space with digit
   __DATE__[4]==' ' ? '0' : __DATE__[4],

   // Second day letter
   __DATE__[5],

  '\0'
};
