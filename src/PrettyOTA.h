/*

Copyright (c) 2025 Marc Schöndorf

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Branding or white-labeling (changing the logo and name of PrettyOTA) is permitted only
with a commercial license. See README for details.

Permission is granted to anyone to use this software for private and commercial
applications, to alter it and redistribute it, subject to the following restrictions:

1. The origin of this software must not be misrepresented. You must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment is required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. You are not allowed to change the logo or name of PrettyOTA without a commercial
   license, even when redistributing modified source code.
4. This notice may not be removed or altered from any source distribution.


******************************************************
*                    PRETTY OTA                      *
*                                                    *
* A better looking Web-OTA.                          *
******************************************************

Description:
    The main header file. Include this file in your project.

*/

#pragma once

// ********************************************************
// Settings
#ifndef PRETTY_OTA_ENABLE_ARDUINO_OTA
    #define PRETTY_OTA_ENABLE_ARDUINO_OTA 1
#endif

#define DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING 0 // Do not change. WIP

// std-lib
#include <string>
#include <vector>
#include <new> //std::nothrow

// Arduino include
#include <Arduino.h>
#include <ArduinoJson.h>

#if (PRETTY_OTA_ENABLE_ARDUINO_OTA == 1)
    #include <ArduinoOTA.h>
#endif

// ESP-IDF
#include <esp_err.h>
#include <esp_ota_ops.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <mdns.h>

// Arduino dependencies
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>

// PrettyOTA includes
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

// Is it the correct version and fork of ESP32AsyncWebServer?
#if !defined(ASYNCWEBSERVER_VERSION) || ASYNCWEBSERVER_VERSION_MAJOR < 3
    #error PrettyOTA needs the "ESPAsyncWebServer" library (from ESP32Async) version 3.0 or newer. If you have it installed, make sure you only have one library with the name "ESPAsyncWebServer" installed (there are two libraries with the same name).
#endif

// Is it the correct version of ArduinoJson?
#if !defined(ARDUINOJSON_VERSION_MAJOR) || ARDUINOJSON_VERSION_MAJOR < 7
    #error PrettyOTA needs the "ArduinoJson" library version 7.0 or newer.
#endif

class PrettyOTA
{
private:
    // Constants
    static const uint8_t    PRETTY_OTA_VERSION_MAJOR = 1;
    static const uint8_t    PRETTY_OTA_VERSION_MINOR = 1;
    static const uint8_t    PRETTY_OTA_VERSION_REVISION = 3;

    static const uint32_t   BACKGROUND_TASK_STACK_SIZE = 3072;
    static const uint8_t    BACKGROUND_TASK_PRIORITY = 4;

    static const uint8_t    MAX_NUM_LOGGED_IN_CLIENTS = 5;

    // Website code
    static const uint8_t    PRETTY_OTA_WEBSITE_DATA[12706];
    static const uint8_t    PRETTY_OTA_LOGIN_DATA[6208];

private:
    // UUID generation
    using UUID_t = uint8_t[16];

    void        GenerateUUID(UUID_t* out_uuid) const;
    std::string UUIDToString(const UUID_t uuid) const;

private:
    // Variables
    static std::string  m_AppBuildTime;
    static std::string  m_AppBuildDate;
    static std::string  m_AppVersion;
    static std::string  m_HardwareID;

    std::string         m_LoginURL = "";
    std::string         m_MainURL = "";

    static Stream*      m_SerialMonitorStream;
    AsyncWebServer*     m_Server = nullptr;
    NSPrettyOTA::ESPUpdateManager m_UpdateManager;

#if (DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING == 1)
    NSPrettyOTA::FirmwarePullManager m_FirmwarePullManager;
#endif

    bool                m_IsInitialized = false;
    bool                m_IsUpdateRunning = false;
    bool                m_AutoRebootEnabled = true;
    bool                m_RequestReboot = false;
    static bool         m_DefaultCallbackPrintWithColor;
    uint32_t            m_RebootRequestTime = 0;

    // Authentication
    bool                m_AuthenticationEnabled = false;
    std::string         m_Username = "";
    std::string         m_Password = "";
    std::vector<std::string> m_AuthenticatedSessionIDs;

    // User callbacks
    std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> m_OnStartUpdate = nullptr;
    std::function<void(uint32_t currentSize, uint32_t totalSize)> m_OnProgressUpdate = nullptr;
    std::function<void(bool successful)> m_OnEndUpdate = nullptr;

private:
    // Default callback functions
    static void OnOTAStart(NSPrettyOTA::UPDATE_MODE updateMode);
    static void OnOTAProgress(uint32_t currentSize, uint32_t totalSize);
    static void OnOTAEnd(bool successful);

    // Log functions
    static void P_LOG_I(const std::string& message);
    static void P_LOG_W(const std::string& message);
    static void P_LOG_E(const std::string& message);

    // Methods
    static void BackgroundTask(void* parameter);

    void EnableArduinoOTA(const char* const password, bool passwordIsMD5Hash, uint16_t OTAport);
    bool IsAuthenticated(const AsyncWebServerRequest* const request) const;

    // NVS storage
    bool SaveSessionIDsToNVS();
    bool LoadSessionIDsFromNVS();

    // Helper
    std::string GetVersionAsString() const;
    //std::string SHA256ToString(const uint8_t hash[32]) const;

public:
    PrettyOTA() = default;

    bool Begin(AsyncWebServer* const server, const char* const username = "", const char* const password = "", bool passwordIsMD5Hash = false, const char* const mainURL = "/update", const char* const loginURL = "/login", uint16_t OTAport = 3232);
    void SetAuthenticationDetails(const char* const username, const char* const password, bool passwordIsMD5Hash = false);

#if (DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING == 1)
    bool DoFirmwarePull(const char* const customFilter);
#endif

    // Is an update running? (web interface or pulling in background)
    bool IsUpdateRunning() const { return m_IsUpdateRunning; }

    // Set user callbacks
    void OnStart(std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> func) { m_OnStartUpdate = func; }
    void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func) { m_OnProgressUpdate = func; }
    void OnEnd(std::function<void(bool successful)> func) { m_OnEndUpdate = func; }

    // Use built in callbacks that print info to the serial monitor
    void UseDefaultCallbacks(bool printWithColor = false);

    // Set the HardwareID. It should be a unique identifier for your hardware/board
    void SetHardwareID(const char* const hardwareID) { m_HardwareID = hardwareID; }

    // Set app version
    static void SetAppVersion(const char* const appVersion);
    // Alias for backwards compatibility. DO NOT USE
    [[deprecated("Use SetAppVersion() instead.")]]
    static constexpr auto OverwriteAppVersion = SetAppVersion;

    // Set build time and date
    static void SetAppBuildTimeAndDate(const char* const appBuildTime, const char* const appBuildDate);
    // Alias for backwards compatibility. DO NOT USE
    [[deprecated("Use SetAppBuildTimeAndDate() instead.")]]
    static constexpr auto OverwriteAppBuildTimeAndDate = SetAppBuildTimeAndDate;

    // Set the Stream to write log messages too (Example: Use &Serial as argument)
    void SetSerialOutputStream(Stream* const serialStream) { m_SerialMonitorStream = serialStream; }
};

// ********************************************************
// Helper macro to be able to set build time and date when using ArduinoIDE.
// This is not required for PlatformIO, however you can use it to overwrite the
// build time and date read by PrettyOTA from the firmware image itself
// using esp_ota_get_app_description().
#define PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE() PrettyOTA::SetAppBuildTimeAndDate(__TIME__, __DATE__)
