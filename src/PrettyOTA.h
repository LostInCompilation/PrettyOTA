/*

******************************************************
*                    PRETTY OTA                      *
*                                                    *
* A better looking Web-OTA.                          *
******************************************************

Description:
    The main header file. Include this file in your project.

Author:     Marc Schöndorf
License:    See LICENSE.md

*/

#pragma once

#include <Arduino.h>
#include <ArduinoOTA.h>
#include <ArduinoJson.h>
#include <ESPmDNS.h>
#include <ESPAsyncWebServer.h>
#include <Update.h>
#include <MD5Builder.h>
#include <vector>
#include <esp_ota_ops.h>

class PrettyOTA
{
public:
    enum class UPDATE_MODE : uint8_t
    {
        FIRMWARE = 0,
        FILESYSTEM
    };

private:
    // UUID generation
    using UUID_t = uint8_t[16];
    void GenerateUUID(UUID_t out_uuid) const;
    String UUIDToString(const UUID_t uuid) const;

private:
    // Constants
    static const uint8_t  MAX_NUM_LOGGED_IN_CLIENTS = 5;
    static const uint32_t BACKGROUND_TASK_STACK_SIZE = 4096;
    static const uint8_t  BACKGROUND_TASK_PRIORITY = 4;

    // Website code
    static const uint8_t PRETTY_OTA_WEBSITE_DATA[11823];
    static const uint8_t PRETTY_OTA_LOGIN_DATA[6101];

    static Stream*     m_SerialMonitorStream;

    // Variables
    bool        m_AutoRebootEnabled = true;
    bool        m_RequestReboot = false;
    uint32_t    m_RebootRequestTime = 0;
    uint32_t    m_WrittenBytes = 0;

    // Authentication
    bool                m_AuthenticationEnabled = false;
    String              m_Username = "";
    String              m_Password = "";
    uint8_t             m_NumLoggedInClients = 0;

    using SessionIDString_t = char[47];
    SessionIDString_t m_AuthenticatedSessionIDs[MAX_NUM_LOGGED_IN_CLIENTS];

    // User callbacks
    std::function<void(UPDATE_MODE updateMode)> m_OnStartUpdate = nullptr;
    std::function<void(uint32_t currentSize, uint32_t totalSize)> m_OnProgressUpdate = nullptr;
    std::function<void(bool successful)> m_OnEndUpdate = nullptr;

    void EnableArduinoOTA(const char* const password, bool passwordIsMD5Hash, uint16_t OTAport);

    static void BackgroundTask(void* parameter);
    bool IsAuthenticated(const AsyncWebServerRequest* const request) const;

    // Default callback functions
    static void OnOTAStart(UPDATE_MODE updateMode);
    static void OnOTAProgress(uint32_t currentSize, uint32_t totalSize);
    static void OnOTAEnd(bool successful);

    // Log functions
    void LOG_I(String message);
    void LOG_W(String message);
    void LOG_E(String message);

public:
    PrettyOTA() = default;

    bool Begin(AsyncWebServer* const server, const char* const username = "", const char* const password = "", bool passwordIsMD5Hash = false, uint16_t OTAport = 3232);

    void SetAuthenticationDetails(const char* const username, const char* const password, bool passwordIsMD5Hash = false);
    void EnableAuthetication(bool enable) { m_AuthenticationEnabled = enable; }

    // Set user callbacks
    void OnStart(std::function<void(UPDATE_MODE updateMode)> func) { m_OnStartUpdate = func; }
    void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func) { m_OnProgressUpdate = func; }
    void OnEnd(std::function<void(bool successful)> func) { m_OnEndUpdate = func; }

    // Set the Stream to write log messages too (Example: Use &Serial as parameter)
    void SetSerialOutputStream(Stream* const serialStream) { m_SerialMonitorStream = serialStream; }

    // Use built in callbacks that print info to the serial monitor
    void UseDefaultCallbacks();
};
