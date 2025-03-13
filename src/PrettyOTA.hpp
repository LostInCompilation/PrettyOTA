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
#include <ArduinoJson.h>
#include <ESPAsyncWebServer.h>
#include <Update.h>
#include <MD5Builder.h>
#include <vector>
#include <esp_ota_ops.h>

class PrettyOTA
{
private:
    // UUID generation
    using UUID_t = uint8_t[16];
    void GenerateUUID(UUID_t out_uuid) const;
    String UUIDToString(const UUID_t uuid) const;

private:
    // Constants
    static const uint8_t  MAX_NUM_LOGGED_IN_CLIENTS = 4;
    static const uint32_t TASK_STACK_SIZE_HANDLE_REBOOT_REQUEST = 2048;
    static const uint8_t  TASK_PRIORITY_HANDLE_REBOOT_REQUEST = 3;

    // Website code
    static const uint8_t PRETTY_OTA_WEBSITE_DATA[11840];
    static const uint8_t PRETTY_OTA_LOGIN_DATA[6105];

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
    std::function<void()> m_OnStartUpdate = nullptr;
    std::function<void(uint32_t currentSize, uint32_t totalSize)> m_OnProgressUpdate = nullptr;
    std::function<void(bool successful)> m_OnEndUpdate = nullptr;

    static void HandleRebootRequest(void* parameter);
    bool IsAuthenticated(const AsyncWebServerRequest* const request) const;

public:
    PrettyOTA() = default;

    bool Begin(AsyncWebServer* const server, const char* const username = "", const char* const password = "", bool passwordIsMD5Hash = false);

    void SetAuthenticationDetails(const char* const username, const char* const password, bool passwordIsMD5Hash = false);
    void EnableAuthetication(bool enable) { m_AuthenticationEnabled = enable; }

    // Set user callbacks
    void OnStart(std::function<void()> func) { m_OnStartUpdate = func; }
    void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func) { m_OnProgressUpdate = func; }
    void OnEnd(std::function<void(bool successful)> func) { m_OnEndUpdate = func; }

    // Use built in callbacks that print info to the serial monitor
    void UseDefaultCallbacks();
};
