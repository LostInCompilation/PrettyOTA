/*

zlib license

Copyright (c) 2025 Marc Schöndorf

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.


******************************************************
*                    PRETTY OTA                      *
*                                                    *
* A better looking Web-OTA.                          *
******************************************************

Description:
    The main header file. Include this file in your project.

*/

#pragma once

// std-lib
#include <string>
#include <vector>
#include <new> //std::nothrow

// Arduino include
#include <Arduino.h>
#include <ArduinoJson.h>
#include <ArduinoOTA.h>

// ESP-IDF
#include <esp_err.h>
#include <esp_ota_ops.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <mdns.h>

// Dependencies
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>

// PrettyOTA includes
#include "CustomTypes.h"
#include "MD5Hasher.h"
#include "ESPUpdateManager.h"
#include "BasicOTAManager.h"

// ********************************************************
// Compile checks
#ifndef ESP32
    #error PrettyOTA only supports ESP32 devices.
#endif

// Is it the correct version and fork of ESP32AsyncWebServer?
#if !defined(ASYNCWEBSERVER_VERSION) || ASYNCWEBSERVER_VERSION_MAJOR < 3
    #error PrettyOTA needs the "ESPAsyncWebServer" library (from ESP32Async) version 3.0 or newer.
#endif

// Is it the correct version for ArduinoJson?
#if !defined(ARDUINOJSON_VERSION_MAJOR) || ARDUINOJSON_VERSION_MAJOR < 7
    #error PrettyOTA needs the "ArduinoJson" library version 7.0 or newer.
#endif

class PrettyOTA
{
private:
    // Constants
    static const uint8_t    PRETTY_OTA_VERSION_MAJOR = 1;
    static const uint8_t    PRETTY_OTA_VERSION_MINOR = 0;
    static const uint8_t    PRETTY_OTA_VERSION_REVISION = 4;

    static const uint32_t   BACKGROUND_TASK_STACK_SIZE = 4096;
    static const uint8_t    BACKGROUND_TASK_PRIORITY = 4;

    static const uint8_t    MAX_NUM_LOGGED_IN_CLIENTS = 5;

    // Website code
    static const uint8_t    PRETTY_OTA_WEBSITE_DATA[12662];
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

    std::string         m_LoginURL = "";
    std::string         m_MainURL = "";

    static Stream*      m_SerialMonitorStream;
    AsyncWebServer*     m_Server = nullptr;
    NSPrettyOTA::ESPUpdateManager m_UpdateManager;

    bool                m_IsInitialized = false;
    bool                m_AutoRebootEnabled = true;
    bool                m_RequestReboot = false;
    uint32_t            m_RebootRequestTime = 0;
    uint32_t            m_WrittenBytes = 0;

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
    std::string SHA256ToString(const uint8_t hash[32]) const;

public:
    PrettyOTA() = default;

    bool Begin(AsyncWebServer* const server, const char* const username = "", const char* const password = "", bool passwordIsMD5Hash = false, const char* const mainURL = "/update", const char* const loginURL = "/login", uint16_t OTAport = 3232);
    void SetAuthenticationDetails(const char* const username, const char* const password, bool passwordIsMD5Hash = false);

    // Set user callbacks
    void OnStart(std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> func) { m_OnStartUpdate = func; }
    void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func) { m_OnProgressUpdate = func; }
    void OnEnd(std::function<void(bool successful)> func) { m_OnEndUpdate = func; }

    // Use built in callbacks that print info to the serial monitor
    void UseDefaultCallbacks();

    // Set the Stream to write log messages too (Example: Use &Serial as argument)
    void SetSerialOutputStream(Stream* const serialStream);

    // Overwrite the build time and date read automatically by PrettyOTA using esp_ota_get_app_description().
    // This is needed for ArduinoIDE, since ArduinoIDE uses a prebuilt ESP-IDF SDK so the build time and date
    // would be wrong. It is not needed for PlatformIO.
    // However you can always call this function to overwrite the build time and date
    // which will be send to the client browser
    static void OverwriteAppBuildTimeAndDate(const char* const appBuildTime, const char* const appBuildDate);

    // Same as above but for the app version
    static void OverwriteAppVersion(const char* const appVersion);
};

// ********************************************************
// Helper macro to be able to set build time and date when using ArduinoIDE.
// This is not required for PlatformIO, however you can use it to overwrite the
// build time and date read by PrettyOTA from the firmware image itself
// using esp_ota_get_app_description().
#define PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE() PrettyOTA::OverwriteAppBuildTimeAndDate(__TIME__, __DATE__)
