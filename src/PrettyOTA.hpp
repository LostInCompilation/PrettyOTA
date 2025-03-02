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
    using UUID = uint8_t[16];
    void GenerateUUID(UUID out_uuid);
    String UUIDToString(const UUID uuid);

private:
    // Constants
    static const uint32_t m_TaskStackSizeHandleRebootRequest = 2048;
    static const uint8_t m_MaxNumLoggedInClients = 8;

    // Website code
    static const uint8_t PRETTY_OTA_WEBSITE_DATA[14145];
    static const uint8_t PRETTY_OTA_LOGIN_DATA[8680];

    bool        m_AutoReboot = true;
    bool        m_RequestReboot = false;
    uint32_t    m_RebootRequestTime = 0;
    uint32_t    m_WrittenBytes = 0;

    // Authentication
    bool                m_AuthenticationEnabled = false;
    String              m_Username = "";
    String              m_Password = "";
    uint8_t             m_NumLoggedInClients = 0;

    using SessionIDString_t = char[47];
    std::array<SessionIDString_t, m_MaxNumLoggedInClients> m_AuthenticatedSessionIDs;

    bool IsAuthenticated(const AsyncWebServerRequest* const request);

    // User callbacks
    std::function<void()> m_OnStartUpdate = nullptr;
    std::function<void(uint32_t currentSize, uint32_t totalSize)> m_OnProgressUpdate = nullptr;
    std::function<void(bool successful)> m_OnEndUpdate = nullptr;

    static void HandleRebootRequest(void* parameter);

public:
    PrettyOTA() = default;

    void Begin(AsyncWebServer* const server, const char* const username = "", const char* const password = "", bool passwordIsMD5Hash = false);

    void EnableAuthetication(bool enable) { m_AuthenticationEnabled = enable; }
    void SetAuthenticationDetails(const char* const username, const char* const password, bool passwordIsMD5Hash);

    void OnStart(std::function<void()> func) { m_OnStartUpdate = func; }
    void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func) { m_OnProgressUpdate = func; }
    void OnEnd(std::function<void(bool successful)> func) { m_OnEndUpdate = func; }
};
