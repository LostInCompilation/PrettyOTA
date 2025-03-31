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
    The main source file.

*/

#include "PrettyOTA.h"

//using namespace NSPrettyOTA;

// Static variables
Stream* PrettyOTA::m_SerialMonitorStream = nullptr;
std::string PrettyOTA::m_AppBuildTime = "";
std::string PrettyOTA::m_AppBuildDate = "";
std::string PrettyOTA::m_AppVersion = "";

// ********************************************************
// NVS storage
bool PrettyOTA::SaveSessionIDsToNVS()
{
    // Open NVS
    nvs_handle_t nvsHandle = 0;
    esp_err_t err = nvs_open("PrettyOTA", NVS_READWRITE, &nvsHandle);
    if(err != ESP_OK)
    {
        P_LOG_E("Could not open NVS storage for saving session IDs");
        return false;
    }

    // Save number of logged in clients
    err = nvs_set_u8(nvsHandle, "numClients", m_AuthenticatedSessionIDs.size());
    if(err != ESP_OK)
    {
        P_LOG_E("Could not save number of logged in clients to NVS");
        return false;
    }

    // Save all session IDs
    for(uint8_t i = 0; i < MAX_NUM_LOGGED_IN_CLIENTS; i++)
    {
        const std::string key = "sessionID" + std::to_string(i);

        if(i < m_AuthenticatedSessionIDs.size())
            err = nvs_set_str(nvsHandle, key.c_str(), m_AuthenticatedSessionIDs[i].c_str());
        else // Write empty values for unused fields
            err = nvs_set_str(nvsHandle, key.c_str(), "sessionID=00000000-0000-0000-0000-000000000000");

        if(err != ESP_OK)
        {
            P_LOG_E("Could not save session ID to NVS. [Key: " + key + "]");
            return false;
        }
    }

    // Commit
    err = nvs_commit(nvsHandle);
    if(err != ESP_OK)
    {
        P_LOG_E("Could not commit changes to NVS");
        return false;
    }

    // Close
    nvs_close(nvsHandle);

    return true;
}

bool PrettyOTA::LoadSessionIDsFromNVS()
{
    // Open NVS (readonly)
    nvs_handle_t nvsHandle = 0;
    esp_err_t err = nvs_open("PrettyOTA", NVS_READONLY, &nvsHandle);
    if(err == ESP_ERR_NVS_NOT_FOUND)
    {
        // Namespace "PrettyOTA" doesn't exist yet. Create the namespace by saving default values to NVS
        P_LOG_W("Namespace \"PrettyOTA\" doesn't exist in NVS yet. Writing default values");

        if(!SaveSessionIDsToNVS())
            return false;

        // Open namespace again after writing default values
        err = nvs_open("PrettyOTA", NVS_READONLY, &nvsHandle);
        if(err != ESP_OK)
        {
            P_LOG_E("Could not open NVS storage for loading session IDs");
            return false;
        }
    }
    else if(err != ESP_OK)
    {
        P_LOG_E("Could not open NVS storage for loading session IDs");
        return false;
    }

    // Read number of logged in clients
    uint8_t numClients = 0;
    err = nvs_get_u8(nvsHandle, "numClients", &numClients);
    if(err != ESP_OK)
    {
        P_LOG_E("Could not load number of logged in clients from NVS");
        return false;
    }

    // Clear all current sessionIDs
    m_AuthenticatedSessionIDs.clear();

    // Read session IDs
    for(uint8_t i = 0; i < numClients; i++)
    {
        size_t valueSize = 0;
        const std::string key = "sessionID" + std::to_string(i);

        // Get size of value
        err = nvs_get_str(nvsHandle, key.c_str(), nullptr, &valueSize);
        if(err)
        {
            P_LOG_E("Could not load session ID from NVS. [Key: " + key + "]");
            return false;
        }

        // Is size valid?
        if(valueSize != 47)
        {
            P_LOG_E("Could not load session ID from NVS. Size mismatch. [Key: " + key + "]");
            return false;
        }

        // Read data
        char buffer[valueSize];
        err = nvs_get_str(nvsHandle, key.c_str(), buffer, &valueSize);
        if(err != ESP_OK)
        {
            P_LOG_E("Could not load session ID from NVS. [Key: " + key + "]");
            return false;
        }

        // Add sessionID to m_AuthenticatedSessionIDs
        m_AuthenticatedSessionIDs.push_back(buffer);
    }

    // Close
    nvs_close(nvsHandle);

    return true;
}

// ********************************************************
// Check if client is authenticated
bool PrettyOTA::IsAuthenticated(const AsyncWebServerRequest* const request) const
{
    if(request->hasHeader("Cookie"))
    {
        const char* const cookieValue = request->getHeader("Cookie")->value().c_str();

        for(auto& i : m_AuthenticatedSessionIDs)
        {
            if(i == cookieValue)
                return true;
        }
    }

    return false;
};

void PrettyOTA::SetAuthenticationDetails(const char* const username, const char* const password, bool passwordIsMD5Hash)
{
    m_Username = username;
    m_Password = password;

    // Enable authentication?
    if(m_Username.length() != 0 || m_Password.length() != 0)
        m_AuthenticationEnabled = true;
    else
        m_AuthenticationEnabled = false;

    if(m_AuthenticationEnabled && !passwordIsMD5Hash)
    {
        // Convert password to MD5 hash
        NSPrettyOTA::MD5Hasher hasher;
        hasher.Begin();
        hasher.AddData(password, strlen(password));
        hasher.Calculate();

        m_Password = hasher.GetHashAsString();
    }
}

// ********************************************************
// Begin
bool PrettyOTA::Begin(AsyncWebServer* const server, const char* const username, const char* const password, bool passwordIsMD5Hash, const char* const mainURL, const char* const loginURL, uint16_t OTAport)
{
    if(!server || m_IsInitialized)
        return false;

    m_Server = server;
    m_LoginURL = loginURL;
    m_MainURL = mainURL;

    if(m_LoginURL.length() == 0 || m_MainURL.length() == 0)
        return false;

    // Use Serial as default output
    if(!m_SerialMonitorStream)
        m_SerialMonitorStream = &Serial;

    SetAuthenticationDetails(username, password, passwordIsMD5Hash);

    // Load session IDs from NVS
    LoadSessionIDsFromNVS();

    // Enable ArduinoOTA support
    EnableArduinoOTA(password, passwordIsMD5Hash, OTAport);

    // ********************************************************
    // Login page (default: "/login")
    server->on(m_LoginURL.c_str(), HTTP_GET | HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(request->method() != HTTP_GET)
            return;

        // Redirect to main URL (default: "/update") if already logged in
        if(!m_AuthenticationEnabled || IsAuthenticated(request))
            return request->redirect(m_MainURL.c_str(), 302);

        // Send login page
        AsyncWebServerResponse* response = request->beginResponse(200, "text/html", PRETTY_OTA_LOGIN_DATA, sizeof(PRETTY_OTA_LOGIN_DATA));
        response->addHeader("Content-Encoding", "gzip");
        request->send(response);
    },
    nullptr,
    [&](AsyncWebServerRequest* request, uint8_t* data, uint64_t size, uint64_t index, uint64_t total)
    {
        if(request->method() != HTTP_POST)
            return;

        // Parse JSON
        JsonDocument loginData;
        deserializeJson(loginData, data);

        // Check login credentials
        if(loginData["userId"].as<std::string>() == m_Username && loginData["password"].as<std::string>() == m_Password)
        {
            // Generate session ID
            UUID_t id = {0};
            GenerateUUID(&id);
            const std::string sessionIDstr = "sessionID=" + UUIDToString(id);

            // If max number of clients is logged in, log out oldest client (first in vector) by removing it's sessionID
            if(m_AuthenticatedSessionIDs.size() >= MAX_NUM_LOGGED_IN_CLIENTS)
                m_AuthenticatedSessionIDs.erase(m_AuthenticatedSessionIDs.begin());

            // Add session ID to known (authenticated) session IDs
            m_AuthenticatedSessionIDs.push_back(sessionIDstr);

            // Save session IDs to NVS
            SaveSessionIDsToNVS();

            // Send response and set session ID cookie
            AsyncWebServerResponse* response = request->beginResponse(200);
            response->addHeader("Set-Cookie", sessionIDstr.c_str());
            return request->send(response);
        }
        else
        {
            return request->send(401, "text/plain", "Wrong username or password");
        }
    });

    // ********************************************************
    // Handle log out "/prettyota/logout"
    server->on("/prettyota/logout", HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(request->hasHeader("Cookie"))
        {
            const char* const cookieValue = request->getHeader("Cookie")->value().c_str();

            const std::vector<std::string>::iterator it = std::find(m_AuthenticatedSessionIDs.begin(), m_AuthenticatedSessionIDs.end(), cookieValue);
            if(it != m_AuthenticatedSessionIDs.end())
            {
                m_AuthenticatedSessionIDs.erase(it);

                // Save sessionIDs to NVS
                SaveSessionIDsToNVS();

                return request->send(200);
            }
            else
            {
                return request->send(400, "text/plain", "No client with given sessionID is logged in");
            }
        }
        else
        {
            return request->send(400, "text/plain", "No cookie with sessionID found");
        }
    });

    // ********************************************************
    // Main page (default: "/update")
    server->on(m_MainURL.c_str(), HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", m_LoginURL.c_str());
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        AsyncWebServerResponse* response = request->beginResponse(200, "text/html", PRETTY_OTA_WEBSITE_DATA, sizeof(PRETTY_OTA_WEBSITE_DATA));
        response->addHeader("Content-Encoding", "gzip");
        request->send(response);
    });

    // ********************************************************
    // Page "/prettyota/start"
    server->on("/prettyota/start", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(401, "text/plain", "Not authenticated");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Get OTA update mode (filesystem / firmware)
        NSPrettyOTA::UPDATE_MODE updateMode = NSPrettyOTA::UPDATE_MODE::FIRMWARE;
        if(request->hasParam("mode"))
        {
            const std::string value = request->getParam("mode")->value().c_str();
            updateMode = (value == "fs" ? NSPrettyOTA::UPDATE_MODE::FILESYSTEM : NSPrettyOTA::UPDATE_MODE::FIRMWARE);
        }
        else
        {
            P_LOG_E("Missing parameter: mode");
            return request->send(400, "text/plain", "Missing parameter in URL: mode");
        }

        // Get reboot switch
        if(request->hasParam("reboot"))
        {
            const std::string value = request->getParam("reboot")->value().c_str();
            m_AutoRebootEnabled = (value == "true" ? true : false);
        }
        else
        {
            P_LOG_E("Missing parameter: reboot");
            return request->send(400, "text/plain", "Missing parameter in URL: reboot");
        }

        // Get MD5 hash of update file
        std::string md5Hash = "";
        if(request->hasParam("hash"))
        {
            md5Hash = request->getParam("hash")->value().c_str();
        }
        else
        {
            P_LOG_E("Missing parameter: hash");
            return request->send(400, "text/plain", "Missing parameter in URL: hash");
        }

        // Call OnStart callback
        if(m_OnStartUpdate)
            m_OnStartUpdate(updateMode);

        // Start update
        if(!m_UpdateManager.Begin(updateMode, md5Hash.c_str()))
        {
            P_LOG_E("UpdateManager: Could not start update");
            P_LOG_E(m_UpdateManager.GetLastErrorAsString() + "\n");
            return request->send(400, "text/plain", m_UpdateManager.GetLastErrorAsString().c_str());
        }

        // Send result
        return request->send(200);
    });

    // ********************************************************
    // Page "/prettyota/upload"
    server->on("/prettyota/upload", HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(401, "text/plain", "Not authenticated");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Call OnEnd callback
        if(m_OnEndUpdate)
            m_OnEndUpdate(!m_UpdateManager.HasError());

        // Response
        AsyncWebServerResponse* response;
        if(m_UpdateManager.HasError())
            response = request->beginResponse(400, "text/plain", m_UpdateManager.GetLastErrorAsString().c_str());
        else
            response = request->beginResponse(200);

        response->addHeader("Connection", "close");
        response->addHeader("Access-Control-Allow-Origin", "*");
        request->send(response);

        // Set reboot flag if requested
        if(!m_UpdateManager.HasError() && m_AutoRebootEnabled)
        {
            m_RebootRequestTime = millis();
            m_RequestReboot = true;
        }
    },
    [&](AsyncWebServerRequest* request, String filename, uint64_t index, uint8_t* data, uint64_t size, bool isLastFrame)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(401, "text/plain", "Not authenticated");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        if(index == 0)
            m_WrittenBytes = 0;

        if(size != 0)
        {
            if(m_UpdateManager.Write(data, size) != size)
            {
                P_LOG_E("UpdateManager: Error while writing");
                P_LOG_E(m_UpdateManager.GetLastErrorAsString() + "\n");
                return request->send(400, "text/plain", m_UpdateManager.GetLastErrorAsString().c_str());
            }

            m_WrittenBytes += size;

            // Call OnProgress callback
            if(m_OnProgressUpdate)
                m_OnProgressUpdate(m_WrittenBytes, request->contentLength());
        }

        // Is this the last frame of data?
        if(isLastFrame)
        {
            if(!m_UpdateManager.End())
            {
                P_LOG_E("UpdateManager: Could not finish update");
                P_LOG_E(m_UpdateManager.GetLastErrorAsString() + "\n");
                return request->send(400, "text/plain", m_UpdateManager.GetLastErrorAsString().c_str());
            }
        }
    });

    // ********************************************************
    // Page "/prettyota/doRollback": Firmware rollback
    server->on("/prettyota/doRollback", HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(401, "text/plain", "Not authenticated");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Is a rollback possible?
        if(!m_UpdateManager.IsRollbackPossible())
        {
            P_LOG_E("No previous firmware for rollback has been found");
            return request->send(400, "text/plain", "No previous firmware for rollback has been found");
        }

        P_LOG_I("Rolling back to previous firmware...");

        // Do rollback
        if(m_UpdateManager.DoRollback())
        {
            P_LOG_I("Rollback successful");
            request->send(200);

            // Request reboot
            m_RebootRequestTime = millis();
            m_RequestReboot = true;
        }
        else
        {
            P_LOG_E("Could not roll back to previous firmware");
            return request->send(400, "text/plain", "Could not roll back to previous firmware");
        }
    });

    // ********************************************************
    // Page "/prettyota/queryInfo": Get infos about board
    server->on("/prettyota/queryInfo", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(401, "text/plain", "Not authenticated");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        const esp_app_desc_t* const appDesc = esp_ota_get_app_description();

        JsonDocument jsonInfo;
        jsonInfo["rollbackPossible"] = m_UpdateManager.IsRollbackPossible();
        jsonInfo["sdkVersion"] = appDesc->idf_ver;
        jsonInfo["projectName"] = appDesc->project_name;
        jsonInfo["firmwareSHA256"] = SHA256ToString(appDesc->app_elf_sha256);

        // Check if app version has been overwritten
        if(m_AppVersion != "")
            jsonInfo["firmwareVersion"] = m_AppVersion;
        else
            jsonInfo["firmwareVersion"] = appDesc->version;

        // Check if build date has been overwritten
        if(m_AppBuildDate != "")
            jsonInfo["buildDate"] = m_AppBuildDate;
        else
            jsonInfo["buildDate"] = appDesc->date;

        // Check if build time has been overwritten
        if(m_AppBuildTime != "")
            jsonInfo["buildTime"] = m_AppBuildTime;
        else
            jsonInfo["buildTime"] = appDesc->time;

        // Send Json
        std::string jsonString = "";
        serializeJson(jsonInfo, jsonString);
        request->send(200, "application/json", jsonString.c_str());
    });

    // ********************************************************
    // Page "/prettyota/queryPrettyOTAInfo": Get info about PrettyOTA (version, URLs)
    server->on("/prettyota/queryPrettyOTAInfo", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        JsonDocument jsonInfo;
        jsonInfo["prettyotaVersion"] = GetVersionAsString();
        jsonInfo["mainURL"] = m_MainURL;
        jsonInfo["loginURL"] = m_LoginURL;
        jsonInfo["authenticationEnabled"] = m_AuthenticationEnabled;

        // Send Json
        std::string jsonString = "";
        serializeJson(jsonInfo, jsonString);
        request->send(200, "application/json", jsonString.c_str());
    });

    // ********************************************************
    // Page "/prettyota/rebootCheck": For checking if server rebooted
    server->on("/prettyota/rebootCheck", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        return request->send(200, "text/plain", "Server is running");
    });

    // ********************************************************
    // Page "/prettyota/doManualReboot": For requesting a reboot
    server->on("/prettyota/doManualReboot", HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(401, "text/plain", "Not authenticated");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Request reboot
        m_RebootRequestTime = millis();
        m_RequestReboot = true;

        return request->send(200);
    });

    // Create background task with lower priority for handling reboot request and ArduinoOTA
    const BaseType_t xReturn = xTaskCreate(BackgroundTask, "PrettyOTABackgroundTask",
        BACKGROUND_TASK_STACK_SIZE, this, BACKGROUND_TASK_PRIORITY, nullptr);

    if(xReturn != pdPASS)
    {
        P_LOG_E("PrettyOTA: Could not create background task for handling reboots");

        return false;
    }

    m_IsInitialized = true;

    return true;
}

void PrettyOTA::EnableArduinoOTA(const char* const password, bool passwordIsMD5Hash, uint16_t OTAport)
{
    ArduinoOTA.setPort(OTAport);
    ArduinoOTA.setRebootOnSuccess(true); // ToDo

    // Do a dummy query to check if DNS is running
    esp_ip4_addr_t ipv4;
    const esp_err_t dnsResult = mdns_query_a("localhost", 100, &ipv4);

    if(dnsResult != ESP_ERR_INVALID_STATE)
    {
        // DNS is running, enable arduino ota discovery
        ArduinoOTA.setMdnsEnabled(false);

        // Enable ArduinoOTA on mDNS
        mdns_txt_item_t arduTxtData[4] = {
            {"board", "esp32"},
            {"tcp_check", "no"},
            {"ssh_upload", "no"},
            {"auth_upload", "no"}
        };

        // Add mDNS service
        if(mdns_service_add(nullptr, "_arduino", "_tcp", OTAport, arduTxtData, 4) != ESP_OK)
            P_LOG_E("Could not add ArduinoOTA as a mDNS service");

        // Set authentication
        if(strlen(password) > 0)
        {
            if(mdns_service_txt_item_set("_arduino", "_tcp", "auth_upload", "yes") != ESP_OK)
                P_LOG_E("Could not set ArduinoOTA mDNS txt item");
        }
    }
    else
    {
        // DNS is not running. Enable it
        ArduinoOTA.setMdnsEnabled(true);
    }

    // Password
    if(strcmp(password, "") != 0)
    {
        if(passwordIsMD5Hash)
            ArduinoOTA.setPasswordHash(password);
        else
            ArduinoOTA.setPassword(password);
    }

    // Configure ArduinoOTA
    ArduinoOTA.onStart([&]() {
        const NSPrettyOTA::UPDATE_MODE mode = (ArduinoOTA.getCommand() == U_FLASH) ? NSPrettyOTA::UPDATE_MODE::FIRMWARE : NSPrettyOTA::UPDATE_MODE::FILESYSTEM;
        if(m_OnStartUpdate)
           m_OnStartUpdate(mode);
    })
    .onEnd([&]() {
        if(m_OnEndUpdate)
           m_OnEndUpdate(true);
    })
    .onProgress([&](unsigned int progress, unsigned int total) {
        if(m_OnProgressUpdate)
           m_OnProgressUpdate(progress, total);
    })
    .onError([&](ota_error_t error) {
        if(m_OnEndUpdate)
            m_OnEndUpdate(false);

        if(m_SerialMonitorStream)
            m_SerialMonitorStream->printf("ArduinoOTA error: [Code %u]", error);
    });

    ArduinoOTA.begin();
}

// Handle reboot request background task
void PrettyOTA::BackgroundTask(void* parameter)
{
    PrettyOTA* const me = reinterpret_cast<PrettyOTA*>(parameter);

    while (true)
    {
        ArduinoOTA.handle();

        // Check if specified time has passed since reboot request was made
        if(me->m_RequestReboot && (millis() - me->m_RebootRequestTime >= 2000))
        {
            me->P_LOG_I("Rebooting...");

            yield();
            delay(2000);

            me->m_RequestReboot = false;
            ESP.restart();
        }

        yield();
        delay(1000);
    }
}

void PrettyOTA::UseDefaultCallbacks()
{
    m_OnStartUpdate = OnOTAStart;
    m_OnProgressUpdate = OnOTAProgress;
    m_OnEndUpdate = OnOTAEnd;
}

void PrettyOTA::SetSerialOutputStream(Stream* const serialStream)
{
    m_SerialMonitorStream = serialStream;
}

void PrettyOTA::OverwriteAppBuildTimeAndDate(const char *const appBuildTime, const char *const appBuildDate)
{
    m_AppBuildTime = appBuildTime;
    m_AppBuildDate = appBuildDate;
}

void PrettyOTA::OverwriteAppVersion(const char* const appVersion)
{
    m_AppVersion = appVersion;
}

const uint8_t PrettyOTA::PRETTY_OTA_WEBSITE_DATA[12627] = {
    31, 139, 8, 8, 247, 214, 233, 103, 0, 3, 80, 114, 101, 116, 116, 121, 79, 84, 65, 95, 109, 105, 110, 105, 102, 121, 46, 104, 116, 109, 108, 0, 229, 125, 139, 118, 219, 86, 150, 229, 175,
    32, 172, 142, 67, 182, 9, 24, 247, 133, 135, 36, 42, 147, 56, 169, 114, 205, 178, 187, 106, 197, 137, 167, 167, 179, 210, 105, 136, 132, 36, 118, 40, 66, 69, 66, 114, 28, 69, 253, 63,
    243, 27, 243, 101, 179, 247, 185, 32, 9, 240, 33, 203, 105, 167, 102, 122, 77, 28, 17, 192, 125, 157, 115, 207, 251, 62, 112, 113, 242, 201, 164, 26, 215, 239, 174, 203, 224, 178, 190, 154,
    157, 158, 240, 55, 152, 21, 243, 139, 81, 57, 199, 83, 89, 76, 78, 79, 174, 202, 186, 8, 198, 151, 197, 98, 89, 214, 163, 239, 190, 253, 99, 152, 53, 105, 243, 226, 170, 28, 221, 78,
    203, 183, 215, 213, 162, 14, 198, 213, 188, 46, 231, 245, 168, 247, 118, 58, 169, 47, 71, 147, 242, 118, 58, 46, 67, 121, 24, 78, 231, 211, 122, 90, 204, 194, 229, 184, 152, 149, 35, 213,
    107, 55, 48, 41, 151, 227, 197, 244, 186, 158, 86, 243, 77, 27, 95, 4, 103, 101, 93, 151, 139, 96, 86, 85, 63, 77, 231, 23, 193, 95, 190, 253, 34, 120, 91, 158, 5, 55, 215, 147,
    2, 233, 17, 154, 168, 167, 245, 172, 60, 253, 235, 2, 5, 223, 33, 251, 228, 153, 79, 56, 153, 77, 231, 63, 5, 139, 114, 54, 154, 162, 185, 128, 157, 27, 77, 175, 138, 139, 242, 217,
    242, 246, 226, 233, 207, 232, 223, 229, 162, 60, 31, 245, 208, 78, 113, 212, 201, 24, 126, 106, 158, 227, 54, 192, 237, 124, 57, 250, 236, 178, 174, 175, 143, 158, 61, 123, 251, 246, 109, 244,
    214, 68, 213, 226, 226, 153, 142, 227, 152, 133, 63, 11, 124, 31, 63, 115, 74, 127, 22, 92, 150, 211, 139, 203, 186, 121, 144, 186, 71, 183, 190, 246, 18, 213, 111, 203, 113, 93, 68, 211,
    234, 217, 188, 152, 87, 159, 125, 106, 190, 6, 144, 235, 162, 190, 12, 38, 163, 207, 94, 197, 65, 124, 137, 106, 183, 248, 123, 17, 191, 137, 127, 249, 44, 56, 159, 206, 102, 163, 207, 62,
    213, 198, 58, 254, 251, 236, 217, 86, 13, 229, 92, 100, 92, 22, 100, 121, 148, 57, 51, 51, 145, 73, 85, 24, 197, 90, 7, 38, 74, 99, 141, 219, 56, 195, 109, 150, 231, 76, 13, 148,
    142, 50, 157, 224, 214, 170, 192, 70, 214, 24, 220, 42, 29, 232, 56, 202, 82, 166, 226, 214, 68, 121, 194, 18, 105, 26, 168, 44, 114, 25, 43, 218, 44, 80, 42, 138, 37, 221, 36, 207,
    117, 174, 163, 84, 39, 4, 106, 0, 8, 181, 117, 154, 4, 185, 139, 172, 78, 3, 99, 19, 128, 137, 199, 168, 224, 148, 98, 189, 204, 161, 41, 20, 69, 43, 58, 137, 84, 102, 3, 109,
    3, 171, 103, 0, 228, 128, 155, 138, 221, 216, 69, 46, 1, 108, 192, 176, 38, 208, 81, 130, 50, 214, 70, 58, 116, 82, 38, 97, 7, 220, 44, 84, 145, 137, 89, 35, 214, 207, 141, 51,
    145, 67, 13, 92, 114, 92, 141, 49, 168, 132, 170, 169, 142, 0, 205, 0, 176, 206, 212, 56, 68, 15, 18, 116, 36, 137, 210, 220, 133, 38, 137, 18, 157, 7, 105, 164, 243, 208, 37, 145,
    65, 199, 211, 72, 177, 225, 36, 202, 53, 251, 31, 231, 172, 17, 11, 41, 228, 214, 197, 164, 144, 125, 169, 82, 135, 6, 179, 153, 144, 147, 61, 210, 145, 178, 41, 113, 76, 0, 49, 78,
    21, 113, 79, 98, 160, 230, 18, 146, 45, 3, 172, 216, 184, 32, 7, 254, 41, 240, 53, 164, 131, 178, 76, 52, 232, 128, 81, 102, 76, 126, 16, 153, 56, 177, 97, 228, 64, 121, 101, 34,
    173, 208, 99, 16, 135, 45, 56, 131, 251, 44, 1, 33, 162, 52, 1, 50, 113, 20, 103, 30, 121, 19, 170, 20, 29, 74, 165, 178, 1, 242, 10, 120, 51, 65, 10, 1, 113, 144, 198, 233,
    16, 237, 165, 169, 9, 179, 200, 36, 41, 146, 98, 163, 67, 11, 2, 218, 144, 164, 202, 195, 52, 114, 44, 9, 113, 17, 161, 0, 21, 40, 54, 76, 17, 1, 137, 51, 148, 142, 65, 53,
    164, 74, 61, 33, 10, 10, 219, 72, 57, 47, 54, 72, 206, 82, 17, 38, 29, 106, 29, 229, 74, 139, 216, 132, 96, 178, 21, 114, 218, 44, 132, 108, 88, 147, 139, 216, 16, 142, 142, 41,
    157, 10, 152, 170, 200, 138, 200, 177, 21, 29, 219, 177, 175, 10, 100, 45, 75, 176, 47, 16, 108, 112, 20, 18, 128, 50, 160, 46, 59, 12, 114, 107, 86, 80, 6, 194, 23, 229, 134, 2,
    146, 130, 92, 14, 116, 119, 114, 175, 161, 2, 58, 23, 32, 9, 8, 237, 50, 37, 2, 142, 94, 229, 196, 20, 114, 145, 69, 42, 113, 94, 47, 128, 80, 238, 18, 207, 8, 48, 44, 179,
    190, 3, 84, 7, 35, 233, 206, 5, 32, 105, 106, 165, 106, 58, 214, 108, 38, 147, 100, 107, 136, 93, 200, 78, 7, 9, 36, 221, 81, 90, 20, 180, 0, 229, 19, 16, 144, 236, 206, 1,
    33, 129, 148, 130, 10, 232, 5, 96, 224, 73, 131, 142, 22, 125, 7, 127, 0, 15, 108, 101, 82, 2, 30, 166, 41, 184, 1, 246, 161, 52, 184, 155, 59, 41, 150, 171, 92, 216, 72, 186,
    163, 65, 19, 106, 240, 63, 213, 66, 27, 21, 66, 250, 50, 37, 15, 58, 85, 51, 112, 46, 19, 133, 87, 9, 200, 168, 12, 137, 171, 50, 97, 174, 215, 97, 21, 26, 136, 42, 5, 90,
    129, 11, 218, 130, 176, 164, 19, 122, 129, 50, 169, 216, 135, 44, 164, 25, 209, 158, 165, 160, 30, 122, 25, 43, 240, 38, 5, 67, 73, 3, 24, 0, 240, 63, 33, 163, 45, 232, 9, 58,
    37, 34, 177, 25, 153, 146, 100, 20, 216, 76, 133, 84, 42, 75, 89, 84, 20, 78, 40, 112, 35, 175, 34, 162, 34, 173, 65, 35, 161, 34, 174, 129, 151, 80, 47, 174, 96, 177, 82, 46,
    212, 180, 88, 20, 246, 44, 17, 113, 21, 94, 233, 60, 17, 129, 109, 155, 69, 61, 62, 51, 69, 178, 50, 139, 52, 198, 184, 131, 51, 240, 62, 196, 91, 251, 171, 106, 114, 51, 43, 131,
    241, 162, 90, 46, 171, 197, 244, 98, 58, 63, 133, 39, 88, 214, 193, 114, 86, 150, 215, 163, 114, 116, 58, 47, 223, 6, 127, 93, 84, 87, 211, 101, 217, 175, 71, 167, 112, 108, 223, 78,
    175, 202, 234, 166, 238, 215, 195, 114, 48, 24, 94, 77, 220, 232, 252, 102, 62, 166, 83, 234, 15, 238, 86, 183, 65, 217, 47, 135, 245, 112, 62, 172, 134, 139, 225, 108, 112, 119, 91, 44,
    130, 98, 56, 61, 134, 11, 186, 89, 204, 131, 101, 191, 95, 140, 150, 253, 165, 52, 50, 92, 246, 43, 148, 25, 12, 167, 163, 197, 176, 56, 57, 153, 254, 90, 156, 158, 158, 66, 130, 167,
    131, 225, 124, 112, 191, 110, 146, 32, 125, 131, 203, 225, 108, 88, 12, 238, 154, 198, 202, 254, 252, 73, 245, 235, 127, 204, 159, 44, 4, 162, 207, 220, 84, 155, 63, 80, 109, 241, 107, 245,
    228, 63, 246, 87, 171, 14, 87, 251, 215, 234, 95, 247, 215, 89, 28, 172, 83, 253, 107, 127, 254, 235, 127, 44, 6, 123, 171, 45, 73, 43, 79, 163, 249, 168, 159, 56, 103, 220, 147, 114,
    240, 180, 185, 171, 7, 13, 213, 250, 229, 233, 169, 74, 144, 94, 55, 215, 185, 92, 79, 78, 84, 242, 171, 47, 58, 191, 111, 0, 182, 216, 0, 226, 207, 130, 41, 120, 90, 204, 199, 101,
    117, 30, 124, 55, 157, 215, 217, 23, 139, 69, 241, 238, 215, 95, 251, 179, 17, 249, 251, 109, 249, 115, 253, 245, 124, 92, 77, 202, 69, 127, 16, 149, 114, 215, 239, 45, 235, 5, 194, 137,
    222, 104, 68, 73, 65, 197, 217, 231, 179, 163, 255, 254, 250, 47, 255, 20, 249, 140, 233, 249, 59, 180, 61, 24, 28, 159, 87, 139, 126, 195, 222, 209, 247, 63, 12, 39, 210, 228, 6, 10,
    10, 13, 111, 70, 241, 112, 60, 154, 68, 103, 239, 234, 242, 101, 57, 191, 168, 47, 143, 111, 78, 198, 199, 55, 79, 159, 14, 166, 209, 245, 205, 242, 178, 255, 90, 218, 140, 206, 33, 105,
    207, 17, 63, 61, 39, 6, 147, 239, 111, 126, 24, 172, 58, 223, 238, 18, 104, 181, 2, 10, 106, 143, 122, 48, 99, 8, 2, 146, 52, 203, 139, 179, 241, 164, 60, 239, 13, 23, 163, 94,
    111, 184, 28, 197, 199, 203, 147, 58, 154, 121, 136, 75, 64, 91, 60, 29, 85, 17, 3, 180, 47, 234, 126, 127, 62, 170, 229, 158, 192, 240, 188, 28, 12, 32, 118, 246, 137, 114, 131, 167,
    235, 66, 10, 68, 93, 163, 176, 184, 239, 31, 192, 130, 224, 42, 128, 171, 78, 140, 254, 199, 53, 196, 234, 233, 40, 27, 204, 159, 142, 246, 117, 174, 254, 190, 58, 61, 117, 63, 0, 98,
    245, 169, 209, 79, 180, 115, 107, 48, 243, 14, 24, 145, 163, 217, 247, 5, 75, 255, 58, 82, 58, 59, 57, 41, 80, 99, 56, 251, 94, 217, 167, 253, 226, 105, 98, 209, 70, 126, 114, 98,
    7, 63, 140, 138, 53, 51, 166, 35, 149, 26, 237, 50, 171, 114, 3, 150, 192, 58, 226, 217, 100, 105, 14, 94, 132, 235, 44, 11, 174, 172, 114, 178, 225, 143, 232, 192, 143, 39, 179, 21,
    246, 63, 62, 29, 65, 186, 68, 42, 175, 70, 211, 225, 197, 104, 50, 252, 135, 209, 205, 240, 114, 52, 62, 158, 140, 22, 253, 238, 95, 181, 245, 55, 223, 250, 171, 187, 127, 192, 162, 238,
    223, 0, 122, 221, 31, 67, 108, 234, 254, 116, 136, 180, 225, 24, 189, 250, 241, 105, 252, 195, 48, 29, 134, 73, 22, 195, 133, 230, 38, 25, 72, 22, 51, 212, 15, 67, 165, 135, 161, 65,
    196, 147, 88, 151, 33, 135, 213, 152, 163, 145, 147, 14, 147, 56, 65, 196, 148, 169, 124, 128, 150, 166, 146, 97, 126, 24, 106, 84, 81, 177, 133, 95, 113, 198, 196, 131, 7, 65, 91, 1,
    13, 103, 101, 21, 92, 67, 186, 1, 237, 4, 180, 98, 88, 155, 193, 3, 180, 64, 39, 2, 26, 198, 31, 68, 69, 240, 98, 213, 6, 120, 234, 129, 91, 151, 198, 46, 207, 204, 195, 160,
    51, 130, 86, 105, 10, 55, 228, 172, 106, 245, 58, 247, 189, 70, 52, 6, 150, 89, 171, 210, 13, 108, 21, 123, 224, 22, 142, 210, 108, 224, 42, 213, 244, 58, 207, 99, 11, 239, 150, 232,
    135, 65, 43, 45, 176, 209, 49, 196, 105, 73, 166, 91, 20, 55, 30, 184, 141, 209, 49, 248, 198, 22, 104, 219, 244, 219, 197, 32, 138, 214, 121, 220, 130, 239, 4, 62, 180, 50, 129, 85,
    50, 58, 39, 248, 185, 128, 159, 11, 248, 121, 23, 252, 15, 67, 135, 134, 18, 135, 64, 196, 169, 120, 3, 29, 164, 205, 201, 187, 36, 119, 112, 221, 70, 183, 160, 83, 20, 236, 48, 177,
    136, 233, 211, 84, 181, 250, 14, 138, 232, 24, 50, 146, 66, 74, 82, 19, 235, 135, 65, 59, 1, 157, 198, 24, 43, 100, 73, 174, 90, 29, 143, 9, 219, 100, 128, 27, 147, 115, 107, 192,
    78, 0, 135, 73, 18, 219, 52, 51, 198, 109, 32, 91, 15, 217, 34, 6, 50, 105, 102, 179, 135, 33, 231, 132, 236, 16, 205, 91, 116, 34, 107, 1, 182, 77, 167, 17, 35, 129, 25, 36,
    235, 10, 182, 241, 160, 85, 150, 154, 196, 228, 73, 75, 208, 50, 1, 173, 64, 35, 103, 192, 16, 245, 30, 122, 27, 79, 112, 11, 216, 25, 34, 239, 150, 152, 107, 1, 238, 20, 248, 141,
    46, 108, 64, 167, 2, 26, 134, 2, 220, 204, 32, 233, 45, 94, 107, 223, 109, 149, 107, 208, 4, 97, 138, 37, 240, 74, 128, 87, 2, 188, 218, 166, 184, 37, 123, 50, 80, 124, 3, 23,
    29, 80, 106, 136, 168, 73, 107, 151, 2, 45, 179, 197, 234, 4, 210, 105, 242, 24, 99, 28, 202, 242, 26, 54, 73, 110, 208, 154, 51, 8, 199, 93, 242, 48, 100, 37, 144, 21, 203, 230,
    208, 151, 150, 156, 89, 129, 174, 16, 62, 102, 57, 88, 106, 186, 253, 78, 88, 201, 217, 60, 21, 9, 92, 195, 142, 61, 108, 132, 108, 160, 7, 70, 42, 241, 123, 160, 27, 130, 7, 189,
    117, 154, 171, 212, 110, 128, 199, 190, 235, 24, 169, 66, 108, 180, 214, 93, 126, 3, 56, 18, 157, 86, 121, 218, 178, 106, 137, 192, 78, 19, 68, 231, 42, 203, 31, 6, 156, 75, 183, 129,
    159, 73, 44, 198, 21, 45, 73, 211, 30, 178, 213, 42, 83, 46, 163, 40, 119, 164, 60, 25, 130, 84, 24, 54, 56, 221, 82, 109, 237, 123, 157, 231, 176, 165, 25, 180, 149, 176, 23, 2,
    123, 33, 176, 23, 219, 150, 156, 212, 203, 179, 196, 196, 144, 244, 13, 108, 210, 149, 2, 171, 49, 220, 82, 86, 185, 45, 187, 34, 210, 73, 105, 182, 121, 220, 210, 48, 154, 21, 32, 12,
    9, 49, 212, 178, 135, 97, 179, 123, 16, 27, 216, 83, 11, 89, 75, 91, 186, 109, 4, 56, 244, 40, 183, 192, 12, 78, 99, 203, 160, 18, 122, 236, 148, 211, 109, 49, 247, 160, 117, 12,
    148, 52, 88, 152, 63, 12, 60, 19, 216, 80, 84, 120, 4, 227, 242, 22, 209, 157, 7, 14, 137, 81, 16, 3, 219, 245, 35, 132, 236, 18, 170, 62, 44, 79, 11, 184, 17, 232, 10, 146,
    171, 156, 74, 236, 123, 128, 91, 79, 117, 139, 113, 4, 24, 216, 146, 115, 81, 37, 246, 28, 126, 76, 43, 168, 120, 222, 245, 160, 110, 152, 2, 231, 44, 213, 174, 37, 107, 185, 239, 185,
    1, 205, 65, 71, 114, 124, 138, 200, 125, 58, 188, 66, 187, 184, 153, 12, 47, 136, 205, 18, 216, 252, 3, 42, 225, 102, 60, 188, 28, 52, 113, 232, 247, 13, 90, 63, 28, 14, 156, 124,
    140, 184, 10, 153, 78, 79, 33, 255, 62, 144, 154, 111, 162, 168, 167, 131, 249, 247, 213, 15, 72, 101, 53, 159, 155, 109, 71, 89, 62, 156, 250, 117, 212, 71, 36, 245, 164, 19, 215, 85,
    207, 178, 1, 130, 100, 134, 89, 173, 8, 171, 24, 77, 163, 127, 175, 166, 243, 126, 175, 135, 145, 71, 246, 143, 69, 211, 28, 34, 218, 251, 251, 254, 96, 120, 89, 44, 47, 255, 136, 128,
    237, 143, 211, 89, 57, 42, 150, 239, 230, 227, 96, 107, 52, 196, 88, 127, 48, 58, 189, 155, 149, 117, 80, 73, 208, 203, 178, 223, 148, 5, 194, 232, 227, 42, 170, 230, 179, 170, 152, 108,
    198, 70, 229, 64, 74, 206, 183, 195, 227, 50, 170, 139, 197, 69, 89, 71, 139, 114, 121, 51, 67, 176, 95, 247, 49, 166, 234, 207, 129, 199, 176, 66, 98, 49, 249, 98, 41, 37, 191, 188,
    57, 63, 71, 128, 94, 14, 238, 7, 199, 30, 161, 205, 184, 227, 102, 254, 157, 204, 246, 17, 202, 229, 116, 82, 126, 61, 43, 175, 202, 121, 221, 239, 221, 92, 19, 139, 231, 213, 236, 230,
    106, 222, 67, 175, 218, 121, 24, 203, 213, 136, 75, 151, 251, 115, 207, 170, 98, 113, 160, 226, 217, 77, 93, 87, 243, 117, 94, 241, 182, 152, 54, 35, 198, 190, 166, 188, 45, 47, 171, 183,
    235, 194, 215, 139, 234, 2, 93, 219, 64, 1, 216, 191, 54, 105, 223, 114, 26, 178, 223, 123, 13, 10, 212, 171, 169, 75, 63, 109, 217, 3, 29, 22, 239, 132, 98, 245, 200, 3, 104, 115,
    4, 253, 28, 206, 71, 147, 106, 124, 67, 32, 17, 200, 215, 192, 251, 242, 221, 159, 39, 253, 94, 85, 23, 175, 192, 252, 222, 32, 186, 45, 102, 55, 37, 36, 234, 96, 209, 69, 121, 86,
    85, 245, 243, 203, 114, 252, 211, 89, 245, 243, 159, 231, 215, 55, 53, 170, 141, 249, 92, 78, 48, 142, 240, 176, 207, 203, 122, 124, 217, 255, 183, 103, 215, 50, 133, 138, 230, 159, 45, 137,
    243, 231, 24, 63, 151, 163, 127, 184, 155, 223, 63, 33, 118, 184, 171, 239, 159, 248, 22, 113, 95, 221, 255, 219, 224, 120, 122, 222, 255, 100, 17, 85, 63, 13, 234, 203, 69, 245, 54, 248,
    122, 177, 128, 12, 247, 158, 87, 55, 179, 73, 48, 175, 64, 54, 182, 211, 237, 56, 59, 189, 20, 49, 249, 231, 87, 47, 95, 212, 245, 245, 55, 229, 223, 110, 202, 101, 125, 188, 140, 60,
    59, 33, 91, 43, 170, 118, 228, 11, 176, 202, 70, 140, 159, 87, 87, 232, 73, 113, 54, 107, 196, 174, 30, 189, 42, 234, 203, 104, 81, 221, 204, 39, 44, 132, 86, 202, 201, 51, 200, 30,
    250, 50, 251, 71, 21, 199, 131, 227, 131, 36, 90, 193, 250, 178, 88, 128, 52, 203, 250, 221, 172, 140, 252, 172, 110, 253, 180, 247, 105, 111, 248, 222, 138, 111, 200, 4, 84, 157, 206, 231,
    229, 226, 197, 183, 175, 94, 250, 138, 247, 247, 195, 37, 186, 66, 17, 127, 7, 50, 212, 37, 148, 118, 126, 177, 210, 182, 214, 164, 130, 29, 141, 150, 162, 9, 239, 94, 179, 216, 147, 39,
    253, 223, 128, 107, 15, 157, 124, 12, 178, 190, 230, 6, 213, 166, 94, 71, 1, 118, 100, 122, 71, 5, 16, 19, 19, 105, 118, 235, 102, 249, 121, 191, 163, 17, 203, 155, 241, 120, 75, 33,
    94, 251, 164, 87, 248, 43, 46, 160, 17, 94, 155, 131, 38, 249, 252, 102, 182, 134, 193, 159, 63, 86, 139, 215, 229, 226, 182, 92, 124, 35, 162, 246, 26, 141, 127, 35, 198, 163, 63, 24,
    28, 217, 7, 32, 151, 148, 190, 54, 92, 17, 199, 70, 11, 191, 19, 217, 10, 206, 11, 232, 215, 164, 149, 13, 139, 182, 4, 27, 200, 129, 229, 117, 53, 95, 150, 156, 46, 0, 160, 143,
    215, 116, 207, 247, 38, 240, 214, 185, 156, 4, 30, 249, 128, 243, 16, 65, 239, 233, 170, 51, 52, 205, 162, 28, 126, 214, 2, 84, 184, 250, 170, 168, 139, 227, 89, 84, 92, 95, 151, 144,
    235, 222, 57, 218, 239, 13, 203, 97, 25, 113, 189, 100, 64, 241, 66, 70, 191, 247, 215, 191, 188, 254, 182, 55, 236, 181, 212, 215, 43, 18, 81, 137, 150, 172, 58, 219, 103, 151, 60, 218,
    52, 76, 189, 167, 77, 147, 247, 227, 130, 150, 160, 216, 50, 179, 239, 23, 136, 143, 70, 172, 34, 186, 242, 82, 2, 63, 181, 153, 172, 154, 211, 42, 138, 245, 162, 33, 104, 230, 139, 136,
    226, 243, 155, 101, 93, 93, 125, 49, 43, 23, 144, 142, 225, 202, 60, 156, 170, 129, 23, 141, 118, 118, 239, 47, 243, 217, 187, 160, 8, 150, 232, 241, 172, 228, 68, 98, 25, 140, 139, 121,
    112, 86, 6, 158, 92, 224, 76, 1, 95, 55, 31, 151, 17, 240, 250, 68, 13, 142, 122, 103, 211, 121, 239, 147, 81, 249, 125, 252, 131, 208, 39, 90, 94, 207, 166, 104, 9, 249, 209, 117,
    117, 221, 223, 3, 229, 51, 129, 210, 139, 88, 83, 96, 44, 183, 129, 68, 159, 249, 198, 251, 45, 183, 6, 0, 72, 140, 7, 247, 135, 13, 121, 53, 155, 157, 21, 227, 159, 190, 20, 231,
    4, 248, 197, 100, 242, 245, 45, 178, 95, 78, 151, 117, 9, 109, 238, 247, 198, 179, 233, 248, 167, 222, 112, 203, 190, 52, 46, 179, 75, 168, 191, 183, 19, 61, 246, 70, 122, 143, 209, 175,
    31, 107, 34, 235, 174, 137, 20, 11, 84, 255, 102, 11, 244, 77, 67, 206, 15, 183, 65, 224, 82, 99, 133, 14, 64, 127, 80, 250, 215, 112, 15, 201, 127, 253, 159, 176, 67, 239, 109, 252,
    61, 150, 168, 110, 89, 162, 97, 125, 208, 184, 76, 170, 21, 32, 64, 168, 189, 129, 65, 212, 118, 216, 247, 248, 144, 225, 191, 166, 228, 238, 154, 186, 46, 148, 182, 168, 189, 126, 243, 167,
    3, 210, 38, 4, 224, 116, 243, 150, 165, 220, 146, 212, 223, 91, 77, 30, 41, 223, 71, 253, 195, 125, 124, 73, 27, 214, 212, 234, 61, 192, 243, 78, 37, 95, 188, 33, 71, 55, 252, 120,
    13, 233, 161, 11, 242, 50, 130, 139, 244, 183, 145, 224, 40, 120, 64, 96, 143, 90, 18, 123, 24, 143, 139, 234, 203, 182, 213, 156, 76, 151, 140, 26, 39, 163, 79, 212, 227, 234, 232, 110,
    165, 247, 105, 198, 171, 98, 126, 83, 204, 214, 228, 121, 140, 118, 204, 170, 139, 234, 230, 55, 105, 199, 239, 44, 45, 48, 68, 101, 253, 102, 90, 190, 237, 55, 18, 209, 213, 196, 29, 255,
    250, 178, 186, 8, 208, 147, 181, 245, 121, 152, 86, 190, 219, 31, 100, 65, 182, 135, 49, 7, 73, 213, 33, 82, 53, 46, 102, 175, 235, 106, 1, 209, 3, 164, 250, 207, 117, 121, 181, 106,
    240, 199, 113, 211, 226, 3, 129, 243, 131, 35, 40, 14, 86, 201, 133, 201, 162, 186, 254, 2, 164, 60, 60, 16, 99, 137, 95, 170, 57, 7, 64, 235, 176, 134, 105, 47, 166, 23, 151, 51,
    110, 27, 33, 174, 171, 102, 162, 241, 172, 88, 46, 217, 45, 246, 113, 83, 57, 188, 92, 149, 238, 181, 214, 215, 152, 251, 221, 252, 242, 61, 13, 45, 202, 171, 234, 182, 124, 95, 91, 109,
    235, 196, 118, 14, 116, 167, 28, 236, 105, 25, 34, 50, 41, 231, 237, 214, 218, 102, 228, 177, 173, 73, 135, 119, 155, 218, 9, 95, 31, 104, 111, 29, 175, 74, 201, 142, 189, 41, 59, 45,
    110, 217, 233, 135, 154, 92, 118, 138, 62, 208, 102, 203, 33, 63, 212, 94, 185, 46, 246, 190, 182, 26, 223, 253, 222, 198, 124, 185, 173, 214, 214, 130, 176, 171, 43, 19, 104, 4, 248, 182,
    232, 170, 75, 25, 65, 69, 89, 240, 171, 242, 188, 144, 49, 23, 245, 242, 161, 86, 170, 235, 247, 181, 208, 184, 181, 50, 226, 78, 171, 111, 23, 197, 124, 121, 94, 46, 34, 9, 142, 143,
    219, 161, 125, 253, 94, 88, 32, 253, 188, 38, 202, 29, 213, 121, 111, 37, 223, 205, 15, 171, 51, 43, 139, 219, 210, 87, 106, 41, 215, 35, 104, 241, 33, 53, 246, 216, 171, 131, 76, 62,
    95, 209, 137, 230, 135, 245, 250, 43, 235, 67, 165, 109, 182, 45, 28, 119, 52, 185, 109, 158, 203, 97, 77, 255, 117, 184, 253, 57, 34, 148, 243, 41, 6, 128, 168, 189, 37, 230, 12, 69,
    71, 104, 224, 243, 71, 85, 246, 83, 12, 91, 26, 189, 85, 160, 209, 188, 222, 224, 232, 55, 53, 185, 50, 57, 135, 90, 61, 108, 206, 223, 139, 40, 233, 134, 6, 198, 224, 255, 98, 181,
    23, 164, 69, 96, 239, 247, 154, 135, 81, 107, 191, 72, 203, 177, 254, 167, 186, 228, 225, 223, 15, 211, 210, 108, 89, 210, 142, 251, 189, 59, 140, 224, 199, 0, 191, 53, 3, 139, 176, 98,
    241, 110, 189, 193, 242, 207, 243, 243, 170, 239, 195, 143, 114, 95, 248, 81, 238, 11, 63, 90, 244, 153, 158, 247, 17, 123, 148, 157, 216, 67, 66, 143, 114, 53, 0, 105, 66, 27, 217, 143,
    113, 205, 253, 166, 253, 250, 114, 186, 53, 69, 115, 120, 70, 15, 218, 190, 4, 36, 191, 47, 161, 35, 195, 117, 180, 14, 64, 222, 248, 66, 195, 253, 241, 65, 211, 196, 143, 205, 46, 145,
    225, 110, 197, 193, 129, 154, 87, 197, 116, 254, 227, 205, 98, 198, 58, 188, 255, 238, 155, 151, 135, 138, 34, 4, 218, 148, 149, 7, 41, 12, 65, 188, 169, 47, 209, 155, 134, 85, 95, 207,
    37, 250, 252, 188, 51, 114, 232, 70, 141, 71, 157, 128, 189, 155, 119, 127, 63, 44, 155, 40, 236, 79, 95, 111, 5, 97, 187, 124, 237, 113, 22, 165, 9, 200, 246, 9, 193, 199, 231, 189,
    164, 125, 76, 246, 159, 79, 23, 87, 111, 139, 69, 249, 227, 138, 137, 53, 202, 111, 137, 193, 170, 204, 74, 10, 14, 54, 118, 118, 51, 157, 77, 126, 228, 44, 205, 190, 102, 36, 247, 43,
    100, 190, 175, 129, 26, 202, 121, 176, 1, 106, 46, 184, 190, 154, 226, 249, 107, 181, 92, 78, 193, 241, 207, 15, 207, 3, 239, 204, 6, 61, 106, 92, 179, 170, 181, 66, 68, 230, 143, 71,
    189, 113, 53, 171, 22, 71, 127, 136, 227, 243, 243, 56, 62, 126, 40, 20, 222, 170, 191, 233, 72, 239, 127, 150, 180, 229, 191, 9, 225, 248, 183, 34, 124, 126, 238, 240, 239, 55, 34, 252,
    79, 144, 244, 251, 114, 182, 44, 3, 219, 22, 189, 207, 185, 63, 176, 154, 113, 9, 225, 162, 223, 91, 75, 252, 209, 206, 64, 148, 83, 166, 29, 121, 60, 122, 108, 205, 238, 156, 203, 90,
    230, 223, 171, 166, 239, 209, 206, 61, 163, 250, 181, 158, 42, 241, 253, 178, 190, 216, 158, 206, 48, 178, 48, 82, 158, 168, 248, 120, 112, 215, 206, 80, 142, 25, 171, 21, 170, 249, 62, 61,
    159, 55, 43, 128, 192, 165, 173, 222, 128, 21, 19, 88, 124, 63, 100, 9, 9, 76, 59, 249, 79, 159, 74, 206, 254, 126, 182, 198, 90, 232, 233, 124, 213, 83, 153, 148, 150, 170, 171, 13,
    128, 245, 35, 122, 223, 154, 211, 40, 37, 242, 241, 70, 229, 183, 13, 244, 100, 161, 171, 126, 242, 228, 147, 71, 140, 17, 222, 59, 231, 241, 197, 77, 93, 173, 38, 60, 166, 203, 96, 165,
    10, 81, 240, 87, 248, 116, 72, 100, 147, 117, 37, 115, 9, 179, 119, 1, 74, 223, 32, 25, 62, 33, 32, 39, 86, 182, 43, 234, 61, 48, 23, 213, 157, 167, 105, 86, 134, 15, 79, 47,
    31, 156, 38, 121, 64, 59, 15, 79, 147, 196, 199, 94, 110, 14, 206, 55, 245, 31, 48, 223, 31, 121, 198, 102, 56, 127, 192, 142, 62, 150, 99, 62, 139, 107, 180, 160, 254, 124, 186, 188,
    44, 39, 67, 12, 208, 68, 177, 193, 193, 197, 205, 124, 206, 45, 144, 143, 103, 200, 67, 182, 242, 177, 72, 109, 86, 89, 23, 37, 140, 207, 188, 28, 215, 81, 208, 96, 58, 150, 188, 75,
    12, 97, 154, 233, 152, 160, 90, 236, 8, 80, 48, 169, 202, 165, 52, 112, 86, 74, 209, 113, 181, 64, 83, 245, 236, 221, 135, 244, 164, 181, 63, 120, 51, 97, 116, 247, 118, 58, 159, 84,
    111, 35, 6, 62, 204, 131, 173, 164, 181, 232, 183, 119, 32, 75, 67, 40, 186, 51, 25, 51, 157, 7, 237, 128, 233, 215, 95, 31, 57, 135, 243, 73, 60, 24, 110, 71, 110, 143, 108, 107,
    59, 222, 235, 169, 40, 142, 98, 24, 161, 77, 60, 247, 200, 150, 54, 241, 95, 239, 217, 106, 205, 123, 216, 10, 245, 30, 217, 76, 43, 54, 236, 61, 147, 135, 135, 70, 53, 15, 218, 174,
    81, 175, 94, 220, 148, 189, 209, 168, 3, 233, 226, 16, 25, 31, 0, 115, 56, 176, 222, 223, 244, 22, 85, 7, 195, 125, 227, 136, 97, 43, 174, 188, 111, 196, 166, 53, 43, 48, 106, 221,
    15, 155, 236, 181, 160, 141, 214, 119, 195, 117, 77, 217, 151, 226, 133, 235, 248, 228, 153, 127, 29, 224, 244, 68, 66, 135, 83, 190, 213, 118, 119, 94, 205, 235, 240, 188, 184, 154, 206, 222,
    29, 45, 139, 249, 50, 132, 34, 79, 207, 239, 207, 170, 201, 187, 59, 70, 11, 23, 178, 141, 32, 108, 162, 12, 149, 243, 223, 113, 243, 84, 38, 252, 119, 31, 157, 131, 100, 229, 226, 238,
    186, 90, 78, 41, 204, 71, 231, 211, 159, 225, 36, 102, 229, 121, 125, 20, 31, 159, 85, 176, 67, 87, 184, 145, 165, 249, 35, 174, 176, 31, 251, 119, 195, 142, 116, 118, 253, 243, 241, 108,
    202, 233, 55, 159, 96, 240, 188, 11, 212, 40, 254, 91, 1, 205, 114, 254, 59, 22, 188, 151, 211, 95, 202, 35, 37, 181, 170, 159, 195, 229, 101, 129, 78, 31, 197, 65, 28, 160, 225, 0,
    49, 92, 124, 47, 163, 142, 175, 166, 183, 119, 48, 130, 215, 179, 226, 221, 209, 249, 172, 252, 249, 248, 170, 88, 64, 134, 194, 186, 186, 62, 50, 24, 235, 173, 158, 27, 84, 45, 147, 88,
    46, 156, 76, 105, 1, 216, 165, 177, 40, 251, 113, 49, 155, 94, 204, 195, 41, 248, 185, 60, 26, 203, 236, 203, 125, 116, 41, 187, 128, 190, 169, 222, 222, 157, 85, 11, 220, 173, 154, 81,
    192, 1, 49, 208, 116, 18, 52, 132, 82, 227, 21, 32, 33, 141, 114, 215, 107, 76, 22, 210, 125, 166, 220, 251, 253, 26, 139, 47, 171, 159, 49, 32, 24, 255, 116, 39, 47, 7, 30, 233,
    72, 187, 21, 217, 92, 140, 138, 158, 154, 54, 222, 180, 209, 128, 117, 173, 102, 217, 65, 155, 178, 81, 208, 103, 195, 31, 152, 31, 216, 161, 219, 242, 184, 186, 46, 198, 211, 250, 221, 81,
    236, 153, 165, 98, 22, 93, 194, 214, 9, 134, 155, 10, 197, 25, 58, 114, 83, 151, 187, 204, 185, 92, 206, 250, 42, 53, 65, 18, 127, 26, 104, 253, 233, 96, 197, 229, 28, 72, 172, 208,
    197, 109, 45, 243, 92, 213, 226, 234, 104, 249, 19, 44, 98, 60, 41, 47, 134, 161, 118, 184, 32, 178, 2, 146, 202, 82, 18, 182, 112, 16, 162, 124, 40, 18, 214, 124, 16, 18, 123, 113,
    8, 243, 53, 14, 200, 248, 80, 12, 140, 91, 99, 160, 227, 13, 6, 114, 191, 168, 56, 200, 59, 178, 132, 186, 141, 79, 168, 27, 178, 240, 50, 16, 150, 133, 234, 174, 152, 79, 175, 10,
    175, 85, 139, 234, 74, 248, 18, 216, 101, 48, 157, 211, 245, 214, 165, 47, 166, 183, 139, 9, 233, 218, 229, 142, 215, 5, 194, 73, 73, 61, 80, 75, 95, 213, 188, 15, 194, 78, 77, 221,
    212, 180, 31, 14, 212, 44, 239, 255, 219, 79, 229, 187, 243, 69, 113, 5, 95, 187, 6, 119, 23, 127, 122, 247, 75, 8, 147, 85, 254, 12, 50, 181, 164, 82, 40, 52, 35, 197, 66, 146,
    47, 8, 19, 48, 70, 183, 74, 171, 77, 105, 213, 42, 13, 19, 112, 111, 91, 197, 242, 78, 30, 248, 124, 159, 180, 114, 179, 78, 46, 76, 199, 125, 214, 202, 77, 15, 64, 80, 26, 5,
    105, 205, 214, 37, 93, 39, 223, 144, 223, 235, 174, 220, 239, 116, 220, 75, 247, 251, 123, 254, 95, 190, 227, 141, 65, 107, 198, 33, 111, 254, 116, 215, 232, 134, 105, 171, 100, 232, 223, 72,
    107, 140, 234, 70, 112, 142, 188, 198, 216, 64, 47, 3, 122, 10, 190, 238, 178, 146, 174, 150, 145, 11, 213, 198, 114, 122, 64, 207, 167, 139, 241, 172, 188, 227, 27, 114, 71, 115, 140, 189,
    142, 225, 118, 171, 159, 202, 163, 63, 104, 119, 22, 231, 103, 205, 163, 127, 17, 27, 93, 109, 30, 39, 5, 156, 8, 55, 96, 30, 41, 110, 235, 106, 39, 87, 231, 231, 240, 174, 71, 235,
    52, 98, 51, 46, 174, 143, 196, 12, 180, 16, 102, 89, 27, 168, 200, 45, 3, 142, 95, 64, 162, 144, 235, 128, 107, 133, 109, 201, 65, 211, 183, 59, 33, 230, 198, 26, 248, 228, 190, 73,
    188, 33, 104, 215, 144, 198, 41, 52, 143, 199, 247, 222, 237, 43, 158, 199, 7, 202, 135, 198, 173, 216, 187, 39, 83, 105, 230, 222, 71, 237, 189, 6, 119, 109, 103, 179, 235, 143, 88, 99,
    91, 146, 188, 57, 109, 18, 131, 24, 190, 109, 77, 172, 97, 227, 168, 187, 169, 1, 134, 126, 213, 91, 248, 99, 68, 48, 37, 173, 222, 106, 225, 174, 17, 38, 99, 91, 150, 86, 201, 131,
    119, 198, 226, 133, 217, 131, 114, 237, 134, 141, 105, 242, 194, 69, 49, 153, 222, 44, 197, 229, 180, 226, 137, 40, 75, 29, 35, 128, 118, 96, 162, 128, 12, 211, 56, 117, 18, 74, 16, 176,
    146, 212, 86, 127, 154, 86, 197, 35, 4, 58, 141, 175, 26, 244, 185, 18, 49, 190, 89, 44, 225, 39, 174, 171, 169, 15, 26, 86, 248, 31, 93, 114, 57, 230, 174, 93, 117, 21, 87, 157,
    101, 155, 98, 155, 245, 201, 173, 162, 38, 62, 179, 69, 178, 41, 200, 248, 179, 97, 136, 48, 163, 155, 243, 213, 244, 234, 174, 169, 152, 150, 252, 119, 31, 249, 192, 230, 133, 196, 48, 221,
    32, 105, 43, 2, 90, 84, 111, 143, 255, 253, 102, 89, 79, 207, 223, 133, 205, 129, 4, 107, 109, 221, 137, 138, 218, 225, 153, 222, 10, 242, 84, 66, 197, 39, 33, 55, 34, 127, 115, 125,
    93, 46, 198, 32, 214, 49, 198, 246, 11, 196, 160, 51, 64, 245, 122, 219, 146, 46, 81, 242, 54, 194, 173, 222, 250, 2, 110, 71, 252, 16, 253, 172, 34, 199, 179, 152, 255, 186, 45, 208,
    30, 237, 198, 69, 77, 133, 198, 84, 180, 0, 36, 219, 24, 160, 254, 171, 231, 223, 221, 117, 195, 56, 189, 167, 212, 159, 96, 186, 186, 197, 178, 77, 169, 142, 20, 183, 4, 183, 19, 62,
    238, 151, 219, 22, 114, 191, 143, 166, 121, 12, 159, 123, 142, 63, 40, 33, 77, 140, 220, 230, 117, 148, 28, 31, 96, 207, 78, 8, 220, 240, 43, 91, 199, 182, 38, 118, 27, 10, 53, 240,
    191, 158, 115, 30, 238, 67, 197, 116, 137, 238, 151, 225, 89, 89, 191, 45, 203, 253, 49, 124, 7, 136, 108, 97, 190, 235, 10, 141, 151, 200, 187, 142, 130, 182, 194, 64, 200, 138, 229, 191,
    227, 235, 98, 194, 29, 60, 71, 112, 181, 226, 40, 247, 112, 211, 100, 252, 183, 197, 203, 164, 99, 130, 124, 40, 218, 162, 163, 4, 143, 220, 249, 90, 44, 248, 106, 175, 104, 70, 131, 211,
    94, 11, 18, 199, 201, 217, 249, 249, 125, 180, 103, 40, 188, 166, 158, 180, 17, 213, 213, 197, 197, 172, 124, 253, 118, 202, 89, 197, 14, 97, 247, 104, 245, 1, 253, 223, 85, 160, 134, 131,
    173, 0, 92, 171, 253, 99, 187, 220, 42, 183, 77, 12, 17, 228, 174, 197, 108, 73, 115, 56, 185, 89, 120, 87, 27, 71, 202, 45, 187, 93, 56, 58, 42, 206, 57, 22, 93, 97, 216, 235,
    29, 239, 134, 239, 13, 74, 201, 90, 212, 146, 85, 228, 191, 127, 0, 186, 98, 119, 7, 73, 184, 213, 3, 72, 233, 101, 123, 56, 138, 190, 4, 16, 132, 32, 149, 33, 105, 198, 127, 86,
    175, 196, 194, 109, 43, 249, 94, 150, 29, 53, 115, 23, 79, 247, 118, 117, 99, 69, 215, 81, 216, 63, 99, 48, 114, 253, 243, 224, 48, 209, 14, 118, 242, 3, 224, 239, 153, 30, 240, 98,
    247, 16, 175, 252, 252, 126, 19, 56, 28, 28, 147, 139, 67, 126, 244, 0, 188, 189, 71, 113, 221, 230, 116, 46, 250, 243, 152, 166, 105, 50, 246, 8, 251, 69, 113, 221, 140, 200, 61, 210,
    178, 63, 229, 17, 30, 71, 170, 76, 202, 186, 152, 206, 164, 244, 150, 90, 119, 236, 74, 27, 181, 3, 45, 53, 19, 198, 62, 170, 253, 234, 35, 53, 187, 178, 83, 97, 123, 204, 221, 158,
    214, 252, 31, 109, 168, 7, 25, 165, 118, 49, 60, 92, 86, 252, 93, 123, 110, 186, 91, 180, 99, 76, 39, 238, 188, 28, 175, 167, 153, 44, 36, 243, 108, 219, 32, 52, 99, 252, 118, 224,
    103, 119, 123, 230, 86, 118, 245, 173, 47, 146, 198, 241, 182, 157, 109, 84, 49, 222, 246, 174, 180, 5, 123, 196, 162, 51, 211, 68, 253, 37, 12, 153, 108, 194, 127, 185, 110, 187, 93, 184,
    210, 150, 115, 221, 22, 195, 46, 49, 86, 102, 124, 71, 167, 236, 36, 211, 52, 229, 237, 194, 167, 203, 219, 139, 85, 204, 176, 158, 217, 240, 48, 215, 214, 160, 129, 60, 199, 109, 49, 59,
    246, 179, 72, 42, 50, 251, 160, 6, 108, 110, 175, 25, 9, 65, 132, 193, 86, 149, 98, 76, 19, 223, 42, 47, 109, 247, 163, 60, 25, 236, 49, 43, 113, 108, 29, 205, 74, 167, 137, 213,
    138, 196, 158, 238, 54, 222, 177, 121, 202, 11, 254, 107, 211, 92, 98, 194, 70, 6, 66, 217, 89, 181, 108, 60, 89, 119, 85, 245, 163, 8, 151, 219, 22, 174, 255, 87, 68, 105, 29, 229,
    109, 119, 251, 189, 98, 212, 45, 46, 130, 180, 235, 32, 155, 201, 69, 125, 88, 180, 118, 37, 75, 239, 71, 37, 248, 3, 64, 252, 232, 135, 180, 187, 99, 220, 80, 101, 205, 108, 215, 86,
    221, 223, 38, 100, 91, 141, 252, 29, 196, 172, 237, 15, 124, 4, 33, 154, 221, 222, 228, 255, 255, 143, 36, 182, 58, 253, 126, 57, 108, 21, 126, 88, 10, 137, 242, 74, 200, 148, 221, 2,
    243, 27, 229, 164, 221, 196, 239, 35, 37, 45, 8, 59, 50, 226, 140, 159, 173, 218, 108, 76, 218, 51, 6, 61, 159, 85, 69, 125, 36, 67, 197, 181, 79, 243, 3, 71, 9, 143, 87, 179,
    43, 73, 43, 196, 222, 31, 189, 158, 159, 159, 199, 107, 25, 27, 243, 223, 74, 58, 4, 253, 237, 153, 137, 54, 90, 13, 23, 87, 83, 6, 238, 252, 188, 44, 182, 74, 52, 12, 104, 138,
    184, 241, 56, 57, 75, 238, 255, 224, 139, 236, 31, 92, 203, 124, 157, 94, 207, 181, 115, 82, 178, 41, 47, 132, 58, 80, 65, 166, 228, 91, 239, 109, 114, 172, 86, 32, 194, 91, 236, 141,
    248, 246, 68, 120, 171, 112, 110, 111, 8, 185, 106, 248, 110, 107, 72, 231, 244, 118, 216, 47, 131, 238, 213, 40, 47, 94, 79, 57, 109, 150, 100, 116, 26, 183, 81, 13, 229, 173, 228, 187,
    150, 2, 73, 49, 168, 80, 182, 177, 161, 123, 64, 116, 16, 113, 137, 129, 101, 216, 133, 21, 111, 224, 200, 160, 245, 35, 4, 134, 77, 39, 36, 176, 219, 218, 34, 121, 119, 59, 93, 78,
    207, 166, 51, 170, 187, 223, 147, 126, 188, 181, 228, 199, 102, 215, 52, 49, 59, 171, 123, 155, 177, 125, 134, 193, 83, 187, 135, 227, 177, 177, 214, 237, 153, 94, 219, 200, 240, 182, 133, 107,
    27, 64, 153, 25, 227, 155, 248, 221, 249, 243, 238, 228, 135, 118, 235, 25, 185, 233, 124, 184, 233, 75, 208, 74, 246, 133, 182, 248, 145, 238, 161, 69, 196, 253, 135, 109, 130, 200, 237, 172,
    99, 15, 247, 239, 199, 237, 138, 152, 26, 27, 13, 207, 233, 201, 217, 25, 154, 183, 166, 208, 79, 158, 249, 5, 219, 147, 103, 254, 232, 81, 46, 206, 158, 158, 76, 166, 183, 129, 108, 89,
    29, 53, 107, 156, 167, 39, 155, 99, 58, 15, 159, 210, 25, 52, 235, 208, 35, 88, 211, 230, 192, 78, 153, 119, 90, 29, 216, 153, 64, 211, 2, 30, 95, 250, 101, 245, 243, 168, 199, 197,
    84, 157, 170, 28, 94, 33, 49, 113, 239, 244, 164, 57, 114, 179, 247, 42, 65, 173, 32, 77, 77, 161, 114, 27, 240, 15, 69, 227, 16, 105, 70, 199, 227, 68, 7, 46, 13, 146, 152, 191,
    169, 115, 114, 137, 217, 86, 26, 39, 92, 158, 53, 49, 50, 11, 199, 102, 115, 38, 199, 42, 64, 35, 177, 51, 227, 80, 25, 23, 200, 1, 123, 40, 146, 134, 60, 52, 19, 151, 60, 70,
    251, 97, 22, 243, 0, 64, 131, 171, 14, 178, 44, 185, 77, 77, 60, 211, 38, 176, 174, 131, 3, 17, 8, 108, 60, 118, 105, 152, 152, 128, 191, 132, 31, 166, 113, 254, 70, 163, 198, 165,
    139, 205, 56, 141, 13, 209, 224, 177, 129, 25, 224, 26, 158, 54, 24, 23, 57, 112, 201, 61, 62, 113, 168, 120, 24, 95, 106, 136, 81, 106, 67, 252, 175, 172, 9, 83, 21, 230, 58, 14,
    83, 55, 67, 123, 113, 104, 66, 203, 83, 60, 175, 82, 13, 108, 85, 60, 14, 209, 47, 149, 132, 78, 5, 6, 96, 137, 249, 44, 228, 33, 159, 150, 189, 3, 3, 198, 38, 80, 32, 91,
    136, 139, 70, 122, 170, 3, 101, 181, 2, 230, 192, 83, 153, 32, 215, 105, 144, 217, 44, 200, 209, 140, 213, 236, 177, 82, 89, 200, 35, 35, 19, 195, 51, 147, 66, 29, 219, 34, 65, 1,
    254, 145, 104, 161, 5, 53, 172, 202, 199, 200, 9, 93, 30, 106, 21, 102, 54, 212, 14, 120, 230, 51, 96, 151, 184, 244, 82, 27, 144, 39, 203, 128, 24, 127, 132, 64, 154, 205, 197, 99,
    165, 211, 208, 230, 68, 33, 212, 134, 169, 161, 81, 49, 193, 161, 1, 32, 137, 95, 157, 225, 146, 177, 15, 38, 52, 183, 161, 177, 122, 28, 243, 184, 37, 52, 109, 242, 56, 76, 120, 248,
    162, 13, 121, 230, 100, 44, 84, 74, 88, 11, 127, 241, 149, 178, 200, 55, 196, 11, 116, 9, 129, 174, 97, 110, 224, 180, 16, 196, 24, 146, 64, 165, 110, 28, 130, 48, 6, 236, 78, 112,
    49, 72, 227, 113, 148, 14, 5, 73, 80, 155, 242, 64, 87, 200, 12, 201, 130, 43, 5, 142, 36, 209, 196, 78, 37, 150, 231, 167, 120, 146, 24, 21, 240, 207, 147, 196, 0, 158, 75, 200,
    54, 226, 195, 163, 35, 249, 151, 147, 97, 183, 144, 8, 55, 211, 22, 8, 143, 77, 236, 0, 213, 160, 8, 106, 242, 2, 134, 179, 121, 167, 67, 146, 39, 211, 232, 40, 36, 32, 51, 47,
    148, 51, 105, 76, 114, 154, 196, 142, 201, 115, 69, 60, 76, 158, 144, 216, 22, 164, 65, 21, 195, 250, 184, 40, 240, 0, 116, 188, 10, 13, 123, 145, 10, 30, 150, 253, 1, 173, 33, 210,
    148, 22, 99, 3, 72, 164, 78, 98, 136, 101, 6, 94, 162, 199, 60, 102, 211, 82, 118, 84, 12, 81, 3, 226, 114, 112, 36, 143, 13, 117, 33, 79, 108, 53, 9, 4, 186, 200, 82, 21,
    240, 79, 186, 9, 2, 131, 75, 26, 244, 132, 132, 232, 23, 16, 20, 75, 142, 42, 23, 176, 25, 138, 35, 40, 171, 12, 101, 2, 26, 23, 166, 160, 113, 170, 28, 180, 43, 77, 228, 252,
    50, 46, 229, 100, 87, 64, 26, 170, 103, 32, 185, 150, 18, 2, 244, 169, 154, 78, 155, 48, 55, 154, 138, 193, 250, 184, 162, 75, 148, 89, 60, 178, 89, 67, 249, 68, 113, 240, 68, 243,
    79, 59, 200, 187, 10, 28, 146, 82, 80, 45, 32, 177, 229, 55, 161, 206, 3, 174, 14, 0, 61, 97, 131, 113, 152, 39, 170, 224, 121, 174, 252, 19, 197, 79, 104, 54, 50, 7, 228, 141,
    64, 201, 88, 70, 46, 90, 170, 139, 240, 35, 79, 107, 246, 212, 82, 41, 175, 18, 39, 130, 85, 104, 30, 213, 139, 63, 175, 177, 58, 33, 5, 209, 23, 208, 9, 98, 73, 27, 3, 221,
    35, 61, 210, 124, 102, 137, 94, 236, 249, 20, 152, 12, 197, 72, 25, 23, 167, 184, 162, 164, 133, 44, 0, 23, 235, 168, 154, 164, 161, 21, 108, 168, 173, 54, 79, 11, 244, 89, 147, 81,
    252, 21, 172, 121, 92, 41, 200, 56, 166, 93, 192, 67, 134, 82, 25, 44, 17, 21, 139, 135, 228, 186, 12, 218, 65, 232, 60, 141, 54, 97, 78, 204, 227, 163, 120, 198, 48, 143, 156, 147,
    206, 232, 12, 32, 32, 139, 138, 121, 153, 228, 56, 96, 1, 5, 52, 40, 152, 145, 241, 236, 9, 48, 52, 16, 152, 140, 146, 10, 178, 102, 134, 53, 104, 22, 178, 48, 53, 154, 98, 75,
    131, 196, 102, 197, 254, 134, 60, 37, 151, 10, 66, 249, 1, 15, 178, 228, 10, 228, 165, 250, 36, 52, 80, 144, 62, 24, 177, 36, 119, 192, 77, 203, 53, 85, 100, 4, 88, 8, 242, 229,
    0, 227, 130, 252, 18, 191, 176, 112, 33, 173, 95, 6, 35, 1, 211, 226, 128, 116, 154, 177, 55, 192, 60, 201, 227, 158, 63, 124, 244, 15, 122, 124, 102, 11, 43, 15, 225, 226, 102, 86,
    142, 24, 6, 87, 147, 73, 240, 172, 229, 43, 52, 37, 198, 229, 121, 161, 28, 160, 130, 184, 254, 34, 130, 44, 167, 157, 146, 250, 58, 227, 9, 198, 242, 235, 21, 57, 79, 3, 157, 193,
    130, 130, 89, 144, 177, 152, 26, 13, 251, 76, 83, 205, 243, 101, 179, 144, 7, 203, 58, 55, 115, 206, 138, 201, 7, 179, 193, 48, 170, 12, 164, 101, 140, 178, 196, 149, 189, 10, 233, 25,
    160, 180, 176, 60, 186, 80, 9, 84, 5, 194, 233, 47, 98, 14, 209, 64, 72, 167, 165, 224, 6, 208, 116, 154, 130, 153, 144, 131, 148, 218, 13, 83, 174, 40, 126, 224, 38, 216, 146, 161,
    235, 32, 187, 141, 227, 34, 213, 52, 76, 43, 95, 129, 98, 169, 187, 130, 152, 241, 24, 94, 149, 62, 231, 121, 83, 105, 144, 199, 180, 186, 130, 126, 66, 237, 206, 17, 228, 128, 13, 38,
    29, 103, 48, 253, 57, 79, 103, 54, 168, 224, 224, 32, 117, 10, 121, 79, 40, 175, 49, 88, 170, 241, 227, 178, 132, 118, 151, 162, 1, 201, 208, 58, 81, 87, 42, 207, 233, 202, 10, 250,
    11, 254, 9, 108, 138, 76, 108, 199, 144, 49, 224, 157, 7, 41, 13, 43, 164, 41, 53, 151, 208, 182, 100, 6, 251, 172, 77, 65, 77, 18, 109, 98, 13, 152, 41, 151, 66, 20, 82, 122,
    141, 132, 38, 148, 103, 96, 193, 9, 196, 151, 60, 139, 206, 206, 196, 171, 153, 43, 195, 147, 102, 243, 2, 22, 157, 97, 81, 211, 83, 26, 232, 152, 39, 88, 91, 77, 179, 230, 47, 141,
    250, 105, 218, 131, 140, 146, 236, 228, 79, 168, 171, 168, 31, 62, 36, 160, 73, 113, 142, 59, 4, 72, 127, 200, 18, 213, 53, 4, 251, 40, 175, 80, 168, 128, 34, 14, 11, 8, 211, 14,
    211, 107, 41, 214, 16, 181, 148, 23, 234, 59, 138, 66, 99, 64, 25, 218, 101, 232, 41, 184, 150, 195, 87, 66, 204, 105, 133, 114, 182, 161, 161, 56, 48, 193, 192, 30, 30, 213, 229, 240,
    170, 60, 133, 27, 204, 76, 160, 73, 60, 248, 15, 228, 83, 4, 135, 20, 158, 106, 12, 235, 77, 255, 71, 131, 76, 223, 199, 158, 230, 36, 4, 64, 139, 243, 208, 116, 136, 24, 53, 226,
    206, 130, 255, 177, 83, 33, 67, 9, 208, 212, 242, 112, 99, 100, 226, 154, 64, 195, 224, 206, 89, 57, 203, 32, 165, 154, 49, 15, 181, 58, 160, 188, 0, 113, 227, 50, 198, 58, 74, 148,
    64, 46, 13, 45, 37, 193, 61, 7, 229, 64, 52, 152, 98, 224, 74, 162, 198, 249, 234, 206, 169, 244, 214, 36, 122, 6, 196, 73, 60, 148, 79, 147, 177, 66, 231, 83, 26, 51, 72, 152,
    21, 77, 48, 42, 157, 145, 171, 142, 234, 225, 232, 210, 97, 200, 117, 193, 115, 224, 40, 81, 166, 97, 17, 244, 12, 62, 29, 165, 82, 157, 164, 226, 88, 229, 226, 217, 4, 229, 160, 235,
    25, 195, 245, 128, 35, 104, 199, 102, 97, 166, 40, 218, 244, 96, 8, 196, 124, 232, 197, 6, 96, 2, 33, 235, 116, 209, 52, 41, 74, 206, 135, 134, 185, 84, 52, 129, 40, 139, 48, 201,
    65, 17, 53, 164, 40, 69, 74, 6, 239, 165, 81, 28, 134, 58, 149, 155, 144, 241, 13, 40, 12, 74, 39, 18, 87, 41, 186, 36, 57, 227, 89, 217, 87, 70, 12, 181, 177, 80, 124, 120,
    5, 144, 52, 46, 16, 8, 196, 224, 80, 115, 241, 180, 131, 150, 129, 169, 240, 199, 240, 206, 1, 145, 227, 5, 168, 66, 181, 93, 54, 211, 25, 143, 153, 78, 198, 100, 180, 54, 12, 56,
    32, 132, 208, 10, 167, 40, 144, 208, 113, 168, 54, 56, 15, 115, 205, 130, 228, 86, 28, 127, 129, 254, 161, 47, 65, 115, 17, 43, 111, 50, 88, 38, 29, 195, 169, 56, 232, 39, 172, 63,
    248, 149, 240, 124, 52, 134, 195, 208, 32, 7, 239, 203, 232, 148, 82, 1, 15, 44, 34, 97, 37, 118, 130, 152, 82, 213, 96, 49, 29, 45, 143, 28, 19, 45, 81, 26, 172, 106, 168, 19,
    130, 201, 174, 120, 248, 27, 219, 207, 36, 80, 98, 81, 70, 97, 136, 67, 104, 198, 185, 155, 76, 34, 170, 144, 7, 199, 67, 190, 102, 84, 109, 195, 14, 161, 63, 99, 74, 58, 197, 134,
    158, 150, 50, 198, 83, 180, 33, 5, 12, 73, 223, 232, 76, 39, 99, 138, 47, 106, 146, 111, 84, 40, 113, 162, 136, 85, 50, 9, 214, 104, 196, 173, 8, 186, 201, 94, 89, 90, 173, 212,
    194, 216, 3, 38, 34, 50, 71, 91, 39, 116, 16, 144, 52, 216, 140, 14, 16, 105, 33, 128, 230, 193, 224, 242, 235, 99, 109, 138, 78, 170, 199, 176, 75, 1, 205, 45, 133, 150, 186, 169,
    17, 116, 66, 199, 157, 144, 91, 185, 38, 198, 135, 200, 66, 102, 32, 100, 162, 28, 64, 28, 214, 138, 50, 3, 91, 134, 39, 205, 195, 218, 209, 56, 148, 137, 81, 61, 46, 192, 20, 162,
    65, 77, 129, 243, 161, 122, 179, 68, 82, 232, 36, 225, 249, 248, 242, 235, 93, 5, 140, 50, 198, 221, 99, 4, 231, 176, 135, 116, 89, 228, 76, 10, 246, 145, 143, 144, 57, 252, 50, 94,
    3, 225, 168, 32, 129, 243, 204, 73, 87, 204, 97, 36, 15, 8, 60, 189, 16, 191, 86, 167, 183, 136, 33, 32, 128, 89, 67, 44, 104, 70, 60, 246, 118, 146, 78, 133, 68, 84, 60, 48,
    60, 102, 172, 76, 225, 69, 152, 148, 104, 209, 21, 57, 151, 156, 198, 19, 241, 24, 132, 133, 97, 123, 144, 39, 80, 69, 141, 64, 202, 255, 122, 179, 205, 111, 19, 136, 121, 212, 28, 140,
    52, 23, 201, 226, 57, 223, 112, 49, 48, 74, 140, 142, 248, 227, 135, 86, 134, 7, 253, 187, 177, 196, 10, 60, 9, 31, 4, 227, 217, 250, 212, 52, 8, 5, 205, 3, 156, 75, 32, 84,
    5, 187, 11, 199, 227, 42, 3, 255, 235, 3, 45, 19, 75, 36, 1, 178, 42, 90, 120, 127, 105, 24, 195, 112, 94, 103, 99, 205, 16, 17, 81, 17, 71, 50, 12, 50, 80, 218, 74, 16,
    175, 197, 5, 133, 60, 124, 93, 51, 244, 198, 45, 236, 96, 64, 255, 68, 59, 144, 175, 226, 129, 114, 194, 127, 251, 227, 1, 14, 63, 253, 184, 117, 58, 25, 181, 183, 16, 53, 227, 216,
    118, 210, 233, 9, 167, 243, 214, 165, 87, 187, 88, 154, 146, 171, 71, 196, 24, 91, 41, 156, 2, 57, 253, 106, 81, 92, 4, 197, 124, 34, 167, 1, 96, 96, 187, 40, 79, 206, 22, 24,
    30, 95, 23, 243, 61, 197, 191, 154, 94, 157, 86, 11, 150, 144, 55, 137, 249, 134, 137, 95, 90, 15, 250, 60, 185, 104, 32, 39, 23, 1, 121, 212, 70, 31, 174, 79, 79, 166, 92, 20,
    245, 135, 170, 203, 193, 73, 192, 111, 253, 62, 114, 211, 190, 31, 208, 7, 5, 134, 252, 215, 245, 72, 78, 64, 26, 6, 252, 141, 46, 126, 233, 241, 88, 37, 255, 46, 96, 251, 133, 111,
    121, 5, 124, 0, 8, 19, 14, 229, 159, 249, 238, 251, 135, 134, 8, 221, 147, 167, 26, 72, 189, 246, 146, 106, 208, 156, 21, 208, 158, 29, 232, 238, 39, 110, 231, 244, 206, 170, 159, 3,
    217, 102, 218, 169, 176, 222, 0, 220, 6, 223, 202, 146, 89, 200, 3, 121, 117, 117, 189, 238, 193, 86, 254, 26, 154, 254, 187, 66, 51, 127, 87, 104, 246, 247, 131, 230, 127, 175, 219, 130,
    32, 75, 210, 43, 137, 94, 47, 13, 123, 33, 221, 52, 183, 111, 214, 116, 95, 254, 142, 156, 161, 194, 86, 17, 63, 155, 25, 248, 87, 15, 155, 57, 200, 79, 31, 64, 80, 102, 37, 183,
    218, 88, 207, 84, 158, 198, 159, 10, 166, 219, 36, 69, 253, 206, 90, 244, 195, 130, 206, 41, 173, 237, 26, 175, 223, 252, 233, 17, 243, 96, 237, 57, 46, 103, 16, 28, 152, 180, 215, 204,
    136, 37, 237, 9, 49, 222, 183, 38, 205, 154, 113, 141, 55, 119, 241, 249, 56, 55, 103, 129, 223, 42, 57, 226, 188, 221, 30, 211, 199, 33, 16, 67, 210, 40, 102, 64, 195, 143, 128, 4,
    207, 3, 126, 66, 34, 69, 212, 110, 92, 148, 43, 55, 12, 16, 90, 69, 244, 123, 24, 31, 160, 132, 26, 50, 2, 140, 48, 206, 13, 108, 158, 68, 10, 99, 161, 231, 176, 250, 40, 107,
    24, 23, 232, 200, 229, 102, 136, 129, 186, 139, 210, 60, 15, 108, 150, 68, 58, 179, 72, 48, 73, 148, 50, 60, 207, 178, 8, 195, 125, 212, 65, 167, 228, 19, 44, 8, 9, 162, 212, 23,
    73, 163, 132, 120, 164, 184, 230, 142, 9, 89, 164, 248, 17, 25, 36, 216, 56, 145, 58, 121, 100, 24, 176, 165, 130, 193, 80, 18, 96, 246, 57, 172, 149, 242, 188, 105, 218, 230, 116, 70,
    147, 156, 68, 121, 46, 46, 138, 95, 130, 105, 18, 50, 38, 112, 247, 100, 44, 229, 145, 66, 95, 69, 20, 12, 241, 231, 167, 56, 56, 132, 143, 115, 20, 101, 35, 154, 31, 164, 225, 140,
    152, 2, 177, 44, 234, 88, 244, 36, 78, 48, 52, 176, 81, 174, 147, 33, 200, 163, 81, 52, 14, 248, 189, 143, 84, 229, 195, 45, 186, 130, 206, 232, 138, 51, 81, 146, 40, 212, 78, 227,
    8, 180, 193, 16, 55, 130, 227, 3, 141, 249, 249, 16, 71, 242, 184, 8, 14, 126, 200, 24, 39, 178, 140, 183, 84, 34, 31, 153, 1, 141, 65, 13, 199, 72, 209, 130, 130, 73, 60, 12,
    44, 1, 90, 208, 56, 213, 145, 74, 81, 199, 130, 146, 140, 96, 17, 54, 128, 162, 57, 113, 204, 83, 126, 202, 132, 145, 103, 148, 39, 160, 151, 65, 17, 23, 51, 140, 35, 191, 134, 109,
    156, 94, 209, 235, 35, 19, 245, 13, 174, 57, 235, 195, 177, 70, 50, 124, 72, 248, 221, 17, 192, 196, 56, 38, 138, 17, 208, 154, 88, 69, 121, 170, 153, 192, 143, 240, 36, 62, 1, 52,
    125, 206, 9, 165, 40, 71, 168, 47, 41, 57, 139, 176, 43, 140, 86, 51, 100, 88, 52, 162, 32, 55, 90, 134, 150, 192, 19, 215, 151, 136, 136, 65, 68, 142, 170, 193, 78, 23, 115, 152,
    192, 18, 138, 252, 195, 53, 97, 9, 180, 234, 98, 47, 28, 49, 63, 148, 148, 130, 250, 49, 199, 215, 76, 87, 40, 225, 49, 1, 106, 146, 131, 8, 89, 229, 252, 8, 138, 128, 101, 201,
    151, 28, 105, 131, 232, 153, 192, 151, 207, 46, 229, 90, 114, 64, 60, 212, 36, 141, 77, 166, 34, 12, 139, 129, 79, 26, 161, 101, 208, 43, 53, 194, 100, 229, 164, 223, 76, 0, 1, 25,
    171, 35, 129, 163, 217, 231, 156, 96, 66, 127, 157, 79, 201, 72, 99, 118, 130, 241, 37, 68, 5, 193, 239, 112, 135, 174, 175, 130, 56, 146, 112, 39, 201, 36, 253, 185, 60, 51, 98, 134,
    22, 160, 8, 35, 111, 8, 56, 162, 59, 62, 166, 148, 234, 148, 223, 30, 74, 164, 100, 142, 1, 35, 41, 7, 105, 100, 118, 142, 161, 38, 162, 246, 40, 243, 143, 41, 165, 62, 217, 148,
    118, 140, 196, 19, 126, 243, 70, 26, 131, 14, 51, 123, 216, 197, 160, 183, 14, 129, 174, 91, 22, 171, 121, 155, 113, 101, 250, 187, 91, 141, 78, 119, 14, 7, 221, 178, 237, 135, 55, 237,
    236, 183, 140, 237, 215, 21, 59, 241, 193, 122, 123, 254, 198, 46, 106, 134, 138, 156, 213, 115, 156, 248, 31, 203, 134, 250, 61, 117, 252, 78, 251, 96, 49, 66, 152, 56, 126, 55, 66, 249,
    241, 207, 248, 69, 95, 125, 149, 125, 157, 222, 243, 58, 103, 211, 242, 129, 237, 78, 167, 235, 83, 227, 2, 255, 9, 181, 40, 138, 90, 206, 195, 111, 1, 91, 191, 60, 76, 72, 237, 13,
    39, 12, 184, 24, 218, 141, 90, 47, 101, 250, 248, 173, 169, 232, 97, 119, 182, 216, 60, 110, 49, 197, 187, 11, 46, 72, 173, 220, 133, 220, 119, 215, 79, 56, 235, 219, 196, 199, 226, 33,
    26, 111, 241, 246, 114, 90, 175, 30, 252, 139, 8, 35, 29, 116, 223, 46, 24, 201, 58, 81, 59, 145, 231, 88, 251, 212, 205, 252, 218, 149, 210, 50, 231, 26, 166, 24, 67, 166, 189, 246,
    204, 155, 130, 150, 235, 23, 110, 45, 122, 193, 159, 170, 128, 157, 60, 121, 118, 214, 116, 179, 227, 119, 91, 39, 42, 190, 223, 235, 254, 125, 60, 236, 249, 57, 134, 125, 250, 81, 30, 22,
    174, 5, 42, 8, 221, 123, 206, 15, 173, 201, 4, 10, 156, 94, 146, 208, 185, 194, 38, 241, 195, 107, 57, 191, 7, 135, 4, 250, 58, 120, 17, 235, 248, 113, 49, 177, 193, 198, 194, 74,
    165, 24, 157, 38, 141, 111, 229, 151, 152, 56, 126, 214, 192, 136, 109, 56, 195, 239, 58, 177, 141, 188, 177, 39, 244, 103, 214, 192, 158, 230, 141, 95, 181, 28, 191, 102, 54, 210, 180, 191,
    244, 171, 252, 14, 26, 109, 41, 204, 134, 148, 135, 127, 208, 222, 206, 43, 239, 34, 51, 218, 106, 49, 37, 48, 110, 141, 47, 166, 111, 113, 155, 58, 169, 183, 46, 240, 31, 77, 179, 64,
    80, 198, 101, 22, 198, 211, 121, 188, 114, 202, 152, 17, 159, 140, 46, 195, 125, 4, 98, 252, 51, 186, 34, 184, 131, 152, 254, 210, 160, 56, 253, 229, 154, 74, 164, 24, 140, 55, 251, 8,
    240, 226, 109, 211, 60, 74, 17, 131, 208, 214, 90, 244, 41, 180, 158, 106, 9, 63, 64, 7, 216, 57, 63, 95, 167, 101, 112, 250, 156, 19, 86, 252, 194, 85, 0, 35, 12, 8, 116, 140,
    64, 218, 113, 54, 23, 20, 112, 116, 131, 244, 148, 214, 89, 210, 7, 161, 6, 169, 12, 186, 193, 225, 195, 23, 192, 86, 90, 26, 72, 147, 161, 91, 41, 199, 229, 81, 166, 237, 112, 27,
    163, 87, 226, 53, 18, 46, 29, 192, 84, 211, 103, 188, 20, 47, 155, 193, 28, 43, 68, 67, 9, 231, 37, 112, 229, 204, 176, 54, 244, 42, 49, 125, 20, 238, 196, 19, 192, 191, 228, 77,
    9, 205, 185, 224, 216, 242, 187, 113, 77, 27, 92, 83, 52, 240, 208, 9, 252, 170, 74, 29, 168, 3, 52, 208, 5, 58, 94, 8, 16, 58, 97, 56, 179, 156, 192, 139, 229, 57, 221, 41,
    227, 0, 52, 146, 90, 86, 97, 2, 168, 3, 137, 49, 168, 155, 59, 193, 12, 113, 64, 156, 122, 223, 136, 240, 66, 102, 33, 65, 47, 193, 229, 165, 120, 1, 174, 240, 153, 24, 12, 148,
    143, 244, 1, 203, 132, 78, 62, 151, 32, 232, 185, 248, 31, 249, 76, 27, 60, 168, 161, 76, 233, 44, 247, 212, 225, 183, 228, 36, 176, 136, 25, 180, 241, 235, 130, 8, 30, 37, 166, 98,
    22, 87, 44, 124, 216, 72, 134, 243, 187, 106, 96, 11, 144, 240, 15, 25, 39, 15, 83, 241, 161, 150, 178, 161, 155, 44, 176, 45, 131, 240, 26, 8, 99, 66, 151, 104, 16, 133, 208, 231,
    27, 71, 143, 158, 2, 99, 3, 113, 224, 28, 28, 169, 196, 169, 103, 99, 41, 131, 86, 232, 152, 90, 250, 122, 226, 19, 199, 70, 250, 102, 115, 211, 148, 128, 204, 27, 45, 145, 197, 170,
    141, 86, 52, 144, 208, 75, 107, 225, 43, 161, 189, 20, 28, 29, 231, 140, 64, 123, 129, 18, 131, 91, 242, 173, 68, 42, 146, 22, 202, 229, 226, 213, 45, 23, 155, 208, 114, 202, 185, 187,
    117, 46, 91, 38, 150, 171, 250, 219, 18, 35, 113, 128, 104, 93, 230, 99, 0, 29, 123, 218, 167, 78, 226, 128, 88, 123, 194, 147, 120, 177, 136, 63, 115, 125, 196, 26, 251, 120, 21, 36,
    18, 242, 175, 30, 169, 129, 155, 210, 201, 138, 23, 77, 99, 12, 24, 125, 105, 15, 22, 98, 162, 221, 230, 49, 219, 138, 3, 54, 135, 223, 61, 28, 3, 248, 163, 11, 196, 233, 109, 234,
    249, 115, 238, 118, 135, 128, 205, 225, 25, 245, 226, 93, 80, 92, 96, 196, 39, 213, 26, 103, 183, 229, 28, 245, 239, 239, 29, 55, 190, 241, 191, 172, 103, 108, 157, 145, 219, 208, 99, 220,
    204, 83, 109, 130, 177, 246, 43, 63, 158, 66, 141, 15, 221, 122, 23, 40, 216, 125, 131, 168, 247, 126, 98, 10, 149, 198, 55, 139, 69, 57, 175, 253, 59, 102, 187, 59, 57, 248, 150, 197,
    138, 216, 114, 223, 33, 119, 206, 69, 55, 254, 180, 247, 113, 184, 52, 87, 65, 6, 47, 84, 136, 67, 92, 237, 17, 200, 185, 102, 112, 27, 166, 169, 187, 12, 49, 206, 120, 195, 18, 151,
    161, 250, 229, 42, 14, 51, 155, 196, 183, 200, 120, 145, 64, 236, 223, 216, 172, 91, 147, 165, 131, 248, 151, 87, 150, 123, 10, 144, 200, 146, 151, 104, 109, 79, 65, 130, 64, 131, 1, 27,
    124, 0, 58, 234, 18, 250, 47, 175, 96, 207, 91, 77, 2, 169, 3, 176, 63, 160, 201, 56, 72, 16, 229, 119, 75, 54, 15, 151, 40, 122, 203, 22, 95, 224, 225, 139, 78, 9, 95, 235,
    151, 43, 182, 17, 218, 52, 191, 100, 179, 111, 72, 142, 23, 187, 148, 20, 172, 8, 201, 166, 234, 65, 72, 73, 252, 98, 167, 67, 205, 195, 10, 20, 202, 18, 212, 45, 203, 238, 133, 148,
    72, 159, 248, 97, 168, 143, 5, 9, 253, 63, 216, 39, 4, 49, 9, 87, 65, 109, 65, 23, 231, 154, 5, 198, 160, 121, 184, 180, 24, 211, 239, 228, 112, 234, 253, 141, 70, 240, 208, 201,
    9, 155, 156, 23, 123, 115, 248, 112, 203, 214, 218, 166, 115, 87, 231, 196, 242, 125, 73, 69, 229, 235, 182, 85, 107, 124, 176, 209, 209, 245, 105, 13, 187, 89, 157, 151, 192, 14, 102, 200,
    43, 104, 128, 127, 250, 199, 213, 193, 49, 141, 26, 10, 56, 153, 98, 150, 249, 224, 61, 199, 174, 237, 107, 78, 102, 195, 78, 215, 179, 203, 15, 161, 180, 134, 252, 37, 207, 73, 11, 232,
    20, 58, 48, 183, 78, 103, 251, 184, 208, 120, 102, 219, 30, 104, 235, 163, 220, 62, 22, 180, 245, 177, 237, 215, 205, 193, 111, 29, 160, 157, 51, 204, 30, 11, 114, 223, 252, 98, 231, 60,
    244, 143, 110, 208, 249, 178, 231, 111, 178, 232, 143, 177, 226, 154, 225, 55, 127, 218, 86, 92, 243, 171, 200, 121, 154, 93, 134, 137, 172, 188, 201, 42, 167, 223, 40, 196, 197, 108, 251, 6,
    99, 0, 164, 203, 170, 94, 179, 129, 133, 235, 84, 201, 204, 38, 161, 77, 218, 57, 178, 229, 198, 101, 47, 21, 99, 105, 171, 108, 39, 143, 251, 133, 130, 120, 22, 34, 10, 234, 214, 226,
    231, 147, 253, 34, 84, 27, 54, 87, 119, 161, 237, 136, 103, 191, 80, 242, 17, 108, 213, 44, 54, 203, 151, 169, 97, 33, 184, 164, 87, 180, 179, 66, 255, 16, 223, 110, 119, 131, 75, 148,
    48, 15, 219, 221, 32, 88, 32, 5, 140, 118, 250, 193, 94, 4, 241, 75, 116, 129, 139, 254, 91, 93, 148, 85, 98, 4, 170, 54, 249, 162, 67, 21, 12, 89, 2, 15, 163, 75, 194, 32,
    181, 176, 135, 241, 54, 174, 92, 191, 115, 183, 219, 157, 8, 124, 134, 186, 76, 108, 167, 161, 192, 55, 20, 116, 58, 64, 154, 105, 233, 64, 176, 195, 8, 193, 82, 49, 22, 230, 174, 143,
    118, 150, 244, 109, 151, 121, 220, 173, 18, 203, 122, 93, 27, 108, 202, 181, 89, 144, 52, 217, 226, 2, 101, 70, 147, 13, 123, 58, 192, 157, 150, 234, 118, 91, 154, 2, 207, 209, 160, 11,
    146, 51, 195, 122, 182, 167, 3, 30, 75, 197, 197, 241, 237, 14, 8, 123, 246, 176, 77, 201, 50, 171, 217, 234, 129, 8, 177, 190, 220, 238, 1, 145, 23, 97, 186, 221, 39, 72, 34, 76,
    255, 242, 74, 73, 161, 4, 76, 165, 226, 88, 79, 87, 174, 197, 114, 183, 148, 79, 240, 137, 92, 72, 246, 15, 255, 242, 8, 63, 243, 186, 49, 33, 191, 179, 151, 225, 215, 162, 248, 125,
    43, 111, 6, 253, 178, 36, 12, 88, 243, 213, 171, 211, 147, 234, 90, 206, 15, 147, 117, 153, 209, 249, 162, 89, 185, 44, 39, 107, 247, 116, 242, 204, 23, 217, 46, 186, 60, 229, 210, 99,
    176, 124, 183, 172, 203, 171, 77, 161, 103, 190, 129, 71, 155, 107, 63, 147, 40, 111, 162, 54, 95, 181, 218, 94, 34, 93, 157, 165, 37, 246, 123, 247, 229, 210, 166, 249, 189, 57, 254, 181,
    211, 211, 224, 100, 86, 156, 149, 179, 224, 188, 90, 60, 208, 66, 251, 221, 84, 160, 47, 85, 30, 112, 1, 237, 183, 70, 155, 22, 218, 73, 123, 231, 20, 187, 239, 254, 4, 252, 10, 206,
    118, 218, 238, 184, 105, 235, 141, 171, 147, 205, 192, 72, 183, 230, 192, 228, 190, 99, 231, 85, 172, 173, 252, 244, 58, 129, 254, 227, 188, 74, 123, 4, 229, 31, 218, 33, 63, 167, 169, 98,
    19, 169, 113, 168, 242, 200, 112, 51, 43, 135, 207, 81, 202, 171, 129, 61, 227, 216, 122, 204, 69, 255, 200, 5, 73, 148, 114, 156, 166, 210, 136, 67, 243, 200, 188, 76, 28, 119, 37, 96,
    20, 62, 118, 76, 138, 104, 243, 35, 232, 126, 148, 250, 66, 114, 163, 35, 170, 161, 54, 81, 22, 38, 145, 145, 138, 161, 228, 230, 128, 162, 216, 166, 13, 57, 215, 37, 31, 102, 71, 8,
    29, 193, 22, 40, 73, 64, 120, 31, 234, 212, 142, 99, 102, 230, 172, 230, 162, 4, 136, 133, 198, 70, 57, 174, 191, 108, 70, 108, 235, 25, 238, 245, 27, 102, 255, 151, 9, 155, 39, 9,
    200, 97, 117, 22, 113, 219, 184, 2, 242, 9, 127, 128, 185, 225, 86, 110, 244, 35, 201, 132, 16, 113, 164, 249, 25, 250, 60, 180, 57, 126, 56, 163, 20, 230, 58, 226, 54, 51, 131, 103,
    174, 252, 89, 102, 129, 70, 180, 183, 54, 228, 116, 32, 55, 174, 162, 50, 87, 115, 66, 78, 159, 113, 70, 143, 53, 52, 9, 101, 121, 155, 49, 1, 108, 69, 128, 31, 113, 91, 83, 36,
    219, 84, 162, 12, 236, 66, 162, 118, 113, 196, 109, 214, 46, 50, 111, 114, 217, 30, 212, 80, 55, 21, 234, 242, 255, 229, 150, 32, 112, 90, 204, 81, 16, 40, 37, 76, 15, 36, 29, 255,
    95, 114, 150, 69, 141, 189, 248, 4, 178, 37, 85, 114, 165, 145, 78, 155, 151, 97, 150, 68, 201, 216, 57, 116, 204, 37, 81, 38, 107, 76, 89, 200, 73, 59, 8, 97, 74, 113, 224, 234,
    31, 25, 194, 174, 231, 146, 168, 32, 87, 70, 102, 107, 13, 134, 90, 64, 155, 11, 156, 1, 39, 166, 184, 103, 47, 226, 22, 190, 140, 98, 150, 24, 182, 226, 20, 239, 87, 77, 72, 77,
    182, 17, 74, 77, 105, 36, 116, 68, 20, 141, 112, 151, 154, 212, 68, 43, 58, 100, 205, 68, 90, 209, 178, 79, 159, 84, 7, 181, 34, 238, 149, 6, 74, 114, 3, 174, 137, 179, 2, 217,
    66, 112, 135, 187, 147, 20, 202, 37, 57, 234, 72, 131, 196, 42, 244, 237, 177, 109, 242, 201, 52, 109, 131, 81, 164, 4, 219, 33, 223, 83, 86, 39, 175, 21, 151, 200, 2, 37, 253, 101,
    53, 178, 144, 115, 201, 161, 17, 113, 17, 25, 145, 12, 118, 39, 97, 81, 41, 145, 81, 147, 88, 2, 242, 20, 88, 1, 2, 141, 202, 210, 192, 177, 8, 116, 140, 238, 143, 20, 227, 15,
    133, 46, 16, 161, 11, 40, 116, 129, 8, 93, 64, 161, 11, 40, 116, 1, 133, 46, 160, 208, 5, 34, 116, 178, 220, 108, 153, 197, 89, 81, 110, 246, 10, 40, 116, 129, 8, 29, 215, 81,
    83, 214, 77, 131, 52, 226, 110, 73, 225, 23, 126, 242, 156, 48, 121, 7, 153, 167, 198, 131, 195, 196, 10, 12, 163, 204, 179, 1, 209, 0, 65, 203, 107, 128, 199, 75, 52, 64, 240, 18,
    13, 16, 180, 68, 3, 4, 45, 175, 0, 30, 47, 227, 53, 33, 240, 42, 0, 180, 68, 1, 60, 90, 208, 0, 39, 186, 0, 126, 70, 206, 235, 2, 45, 146, 87, 133, 142, 165, 216, 108,
    253, 217, 125, 129, 115, 51, 232, 216, 56, 205, 102, 0, 209, 204, 5, 5, 173, 185, 179, 246, 171, 125, 141, 11, 104, 167, 236, 113, 0, 237, 87, 29, 63, 100, 226, 76, 183, 150, 149, 244,
    206, 178, 82, 203, 140, 173, 86, 74, 204, 153, 57, 11, 248, 202, 222, 249, 172, 122, 187, 218, 131, 36, 192, 142, 110, 5, 220, 18, 240, 110, 225, 222, 139, 104, 90, 61, 155, 23, 243, 170,
    101, 188, 12, 168, 153, 240, 149, 20, 7, 170, 154, 188, 224, 164, 111, 146, 7, 205, 69, 32, 114, 154, 62, 53, 138, 235, 3, 8, 197, 100, 81, 152, 51, 200, 205, 53, 246, 133, 200, 121,
    232, 170, 18, 15, 146, 197, 178, 94, 205, 149, 230, 36, 207, 164, 104, 178, 117, 121, 157, 161, 85, 60, 37, 156, 96, 71, 217, 230, 81, 26, 224, 222, 69, 32, 229, 104, 71, 185, 147, 25,
    12, 78, 184, 169, 14, 58, 151, 114, 43, 106, 198, 133, 243, 212, 163, 234, 49, 21, 52, 17, 221, 113, 99, 129, 163, 177, 52, 113, 246, 133, 133, 133, 225, 100, 254, 234, 234, 59, 147, 107,
    106, 191, 71, 84, 67, 226, 100, 123, 33, 4, 135, 147, 229, 44, 137, 208, 148, 191, 254, 254, 53, 141, 11, 132, 15, 74, 200, 41, 116, 255, 132, 186, 5, 115, 173, 241, 165, 120, 245, 109,
    107, 72, 60, 183, 2, 26, 151, 69, 54, 81, 191, 192, 231, 54, 149, 46, 227, 191, 173, 16, 109, 161, 125, 43, 64, 254, 214, 164, 133, 173, 28, 148, 111, 30, 227, 176, 149, 121, 27, 54,
    53, 218, 101, 253, 253, 33, 185, 223, 122, 37, 181, 137, 221, 182, 69, 189, 27, 37, 109, 189, 195, 214, 52, 181, 149, 186, 25, 159, 239, 249, 108, 198, 222, 193, 248, 38, 172, 244, 103, 135,
    50, 206, 246, 155, 138, 118, 94, 1, 60, 93, 159, 144, 26, 132, 65, 115, 66, 125, 176, 6, 216, 57, 132, 245, 84, 206, 169, 109, 224, 161, 244, 255, 254, 95, 112, 4, 218, 109, 205, 125,
    183, 95, 95, 245, 250, 219, 73, 217, 213, 223, 206, 39, 4, 118, 54, 30, 173, 95, 117, 221, 51, 156, 95, 233, 46, 207, 127, 105, 84, 90, 119, 151, 58, 63, 112, 17, 213, 230, 177, 152,
    76, 252, 2, 131, 139, 181, 246, 190, 138, 135, 10, 210, 28, 35, 118, 131, 11, 130, 64, 15, 97, 102, 245, 144, 123, 68, 134, 176, 148, 106, 243, 115, 137, 134, 225, 142, 37, 59, 150, 148,
    112, 93, 138, 14, 83, 81, 176, 216, 2, 92, 87, 22, 58, 177, 170, 52, 224, 171, 159, 165, 252, 14, 87, 25, 67, 254, 220, 250, 26, 67, 237, 45, 51, 90, 227, 6, 159, 144, 63, 114,
    247, 130, 237, 114, 255, 108, 148, 14, 99, 73, 150, 82, 225, 186, 20, 34, 62, 143, 182, 47, 179, 206, 220, 180, 211, 160, 237, 155, 144, 228, 225, 26, 144, 252, 172, 112, 0, 214, 68, 110,
    184, 70, 78, 126, 150, 130, 255, 42, 93, 48, 95, 247, 211, 72, 36, 0, 26, 132, 107, 26, 200, 143, 96, 253, 92, 136, 195, 213, 66, 7, 184, 240, 247, 41, 175, 158, 214, 191, 180, 222,
    113, 121, 101, 184, 165, 104, 104, 136, 138, 27, 67, 205, 135, 252, 35, 64, 24, 213, 33, 34, 14, 94, 151, 18, 127, 128, 240, 25, 163, 130, 40, 153, 101, 140, 246, 248, 51, 182, 140, 130,
    129, 58, 175, 12, 187, 135, 124, 159, 39, 50, 179, 112, 83, 36, 108, 202, 72, 190, 191, 65, 137, 97, 188, 148, 138, 190, 210, 80, 42, 37, 102, 152, 152, 23, 154, 238, 118, 76, 54, 178,
    177, 29, 166, 29, 164, 213, 37, 119, 31, 33, 28, 151, 86, 158, 27, 88, 112, 80, 88, 35, 92, 67, 95, 252, 3, 189, 53, 31, 54, 61, 22, 82, 60, 187, 232, 154, 157, 181, 114, 136,
    181, 105, 62, 136, 118, 192, 220, 60, 243, 239, 180, 62, 227, 153, 196, 167, 255, 7, 152, 104, 58, 43, 127, 143, 0, 0
};

const uint8_t PrettyOTA::PRETTY_OTA_LOGIN_DATA[6208] = {
    31, 139, 8, 8, 178, 215, 233, 103, 0, 3, 108, 111, 103, 105, 110, 95, 109, 105, 110, 105, 102, 121, 46, 104, 116, 109, 108, 0, 189, 91, 141, 114, 219, 72, 114, 126, 21, 132, 235, 181, 201,
    19, 1, 205, 255, 12, 40, 65, 87, 94, 103, 147, 221, 148, 55, 183, 181, 127, 149, 42, 151, 79, 5, 129, 144, 132, 91, 16, 96, 0, 80, 178, 86, 214, 189, 79, 94, 35, 79, 150, 175,
    7, 160, 8, 210, 146, 207, 149, 74, 101, 181, 36, 128, 193, 204, 116, 247, 215, 95, 247, 52, 136, 241, 233, 63, 45, 235, 172, 187, 91, 231, 193, 117, 183, 42, 207, 78, 233, 59, 40, 211,
    234, 42, 201, 43, 92, 229, 233, 242, 236, 116, 149, 119, 105, 144, 93, 167, 77, 155, 119, 201, 175, 191, 252, 75, 232, 134, 182, 42, 93, 229, 201, 77, 145, 223, 174, 235, 166, 11, 178, 186,
    234, 242, 170, 75, 38, 183, 197, 178, 187, 78, 150, 249, 77, 145, 229, 161, 191, 152, 23, 85, 209, 21, 105, 25, 182, 89, 90, 230, 9, 159, 140, 39, 88, 230, 109, 214, 20, 235, 174, 168,
    171, 221, 28, 175, 131, 139, 188, 235, 242, 38, 40, 235, 250, 247, 162, 186, 10, 254, 242, 203, 235, 224, 54, 191, 8, 54, 235, 101, 138, 246, 8, 83, 116, 69, 87, 230, 103, 111, 235, 171,
    162, 10, 194, 224, 199, 6, 3, 238, 208, 237, 244, 184, 191, 113, 90, 22, 213, 239, 65, 147, 151, 73, 129, 105, 3, 50, 50, 41, 86, 233, 85, 126, 220, 222, 92, 29, 125, 128, 157, 215,
    77, 126, 153, 76, 48, 95, 186, 216, 187, 49, 255, 90, 190, 193, 105, 128, 211, 170, 77, 94, 93, 119, 221, 122, 113, 124, 124, 123, 123, 27, 221, 202, 168, 110, 174, 142, 5, 99, 140, 58,
    191, 10, 122, 91, 95, 105, 46, 214, 31, 94, 5, 215, 121, 113, 117, 221, 61, 94, 250, 241, 139, 155, 126, 134, 22, 83, 220, 228, 89, 151, 70, 69, 125, 92, 165, 85, 253, 234, 107, 249,
    45, 4, 173, 211, 238, 58, 88, 38, 175, 126, 96, 1, 187, 198, 192, 27, 124, 190, 99, 191, 177, 63, 94, 5, 151, 69, 89, 38, 175, 190, 22, 82, 105, 250, 123, 117, 124, 48, 130, 107,
    29, 73, 237, 2, 23, 71, 78, 203, 82, 70, 210, 242, 48, 98, 66, 4, 50, 178, 76, 224, 148, 57, 156, 186, 56, 166, 214, 128, 139, 200, 9, 131, 83, 197, 3, 21, 41, 41, 113, 202,
    69, 32, 88, 228, 44, 181, 226, 84, 70, 177, 161, 30, 214, 6, 220, 69, 218, 209, 64, 229, 2, 206, 35, 230, 219, 165, 121, 35, 98, 17, 89, 97, 72, 168, 132, 32, 140, 22, 214, 4,
    177, 142, 148, 176, 129, 84, 6, 98, 88, 134, 1, 154, 115, 26, 231, 52, 166, 66, 87, 204, 34, 76, 196, 157, 10, 132, 10, 148, 40, 33, 72, 67, 55, 206, 116, 166, 35, 109, 32, 27,
    50, 148, 12, 68, 100, 208, 71, 169, 72, 132, 218, 247, 49, 100, 128, 46, 67, 30, 73, 70, 35, 152, 120, 35, 181, 140, 52, 70, 224, 16, 227, 40, 165, 196, 32, 12, 181, 34, 130, 52,
    9, 193, 194, 241, 44, 132, 5, 6, 134, 152, 200, 198, 58, 148, 38, 50, 34, 14, 108, 36, 226, 80, 155, 72, 194, 112, 27, 113, 154, 216, 68, 177, 32, 251, 89, 76, 35, 152, 135, 194,
    159, 106, 70, 8, 169, 183, 220, 106, 76, 232, 74, 15, 39, 89, 36, 34, 174, 44, 233, 104, 32, 145, 89, 78, 186, 27, 6, 213, 180, 33, 216, 28, 100, 49, 169, 131, 24, 250, 91, 232,
    43, 9, 7, 174, 168, 81, 194, 0, 201, 101, 70, 254, 32, 101, 152, 81, 97, 164, 129, 60, 151, 145, 224, 176, 24, 224, 208, 12, 90, 226, 220, 25, 0, 17, 89, 3, 101, 88, 196, 92,
    175, 188, 12, 185, 133, 65, 214, 15, 150, 80, 158, 67, 111, 106, 240, 157, 160, 56, 160, 209, 34, 196, 124, 214, 202, 208, 69, 210, 88, 52, 49, 41, 66, 5, 0, 85, 72, 80, 197, 161,
    141, 52, 245, 4, 93, 60, 41, 128, 2, 209, 134, 90, 60, 65, 152, 67, 111, 6, 212, 208, 234, 199, 121, 80, 208, 89, 69, 92, 247, 180, 65, 179, 179, 158, 76, 34, 20, 34, 138, 185,
    240, 180, 9, 225, 100, 229, 225, 84, 46, 4, 55, 148, 140, 61, 109, 72, 142, 96, 196, 78, 14, 77, 121, 164, 60, 229, 104, 22, 193, 84, 214, 15, 133, 178, 138, 122, 144, 45, 32, 54,
    60, 10, 6, 160, 15, 208, 37, 131, 1, 183, 160, 1, 92, 130, 124, 81, 44, 137, 32, 22, 112, 105, 224, 174, 253, 185, 64, 8, 136, 216, 11, 49, 0, 90, 59, 238, 9, 14, 171, 98,
    210, 20, 188, 112, 17, 55, 186, 143, 11, 40, 20, 107, 211, 59, 2, 14, 115, 170, 55, 128, 194, 65, 250, 118, 173, 3, 64, 106, 149, 31, 106, 51, 65, 211, 56, 223, 172, 36, 105, 23,
    146, 209, 129, 1, 211, 53, 177, 133, 35, 10, 208, 223, 0, 64, 114, 119, 12, 9, 6, 44, 5, 10, 176, 2, 50, 112, 37, 128, 163, 130, 237, 240, 15, 228, 193, 173, 212, 100, 224, 67,
    107, 225, 13, 184, 15, 189, 225, 221, 88, 251, 110, 49, 143, 189, 27, 9, 119, 76, 40, 67, 1, 255, 91, 225, 177, 225, 33, 216, 231, 184, 191, 16, 150, 151, 240, 156, 243, 1, 207, 13,
    96, 228, 146, 192, 229, 206, 59, 183, 143, 97, 30, 74, 80, 149, 8, 205, 225, 5, 161, 0, 44, 225, 4, 43, 208, 199, 250, 252, 224, 66, 74, 35, 162, 119, 41, 208, 131, 149, 140, 195,
    55, 22, 14, 37, 12, 144, 0, 224, 127, 67, 142, 86, 192, 19, 56, 25, 207, 88, 71, 78, 49, 142, 8, 235, 120, 72, 65, 165, 136, 139, 156, 200, 137, 0, 30, 248, 234, 41, 234, 217,
    26, 12, 12, 245, 116, 13, 122, 134, 246, 116, 133, 139, 57, 215, 161, 160, 140, 69, 100, 119, 198, 211, 213, 251, 74, 196, 198, 19, 118, 156, 22, 69, 118, 33, 83, 179, 77, 139, 148, 144,
    113, 134, 133, 161, 95, 79, 250, 140, 191, 170, 151, 155, 50, 15, 178, 166, 110, 219, 186, 41, 176, 86, 156, 97, 53, 104, 187, 96, 181, 212, 201, 229, 166, 202, 104, 221, 153, 206, 238, 183,
    167, 65, 62, 205, 231, 221, 252, 124, 94, 205, 235, 121, 49, 187, 191, 73, 155, 224, 197, 188, 61, 193, 234, 178, 105, 170, 160, 153, 78, 95, 36, 205, 180, 153, 118, 243, 124, 54, 111, 166,
    21, 250, 204, 230, 109, 82, 207, 95, 156, 158, 182, 31, 95, 156, 157, 157, 129, 152, 237, 108, 126, 62, 123, 120, 156, 178, 155, 110, 39, 108, 230, 197, 252, 197, 236, 126, 152, 44, 159, 158,
    191, 172, 62, 254, 253, 252, 101, 237, 37, 246, 55, 119, 195, 206, 63, 51, 172, 254, 88, 189, 252, 251, 211, 195, 170, 231, 135, 253, 181, 250, 235, 211, 99, 234, 103, 199, 84, 127, 157, 158,
    127, 252, 123, 61, 123, 114, 88, 67, 88, 245, 24, 157, 39, 83, 163, 181, 212, 47, 243, 217, 209, 112, 214, 205, 6, 212, 166, 249, 217, 25, 55, 104, 239, 134, 227, 185, 63, 158, 158, 114,
    243, 177, 239, 122, 254, 48, 8, 28, 185, 1, 224, 23, 65, 1, 87, 165, 85, 150, 215, 151, 193, 175, 69, 213, 185, 215, 77, 147, 222, 125, 252, 56, 45, 146, 42, 191, 13, 126, 201, 63,
    116, 223, 86, 89, 189, 204, 155, 233, 44, 202, 253, 217, 116, 210, 118, 13, 42, 134, 73, 146, 16, 1, 48, 176, 248, 115, 177, 248, 183, 159, 255, 242, 239, 81, 127, 163, 184, 188, 195, 220,
    179, 217, 201, 101, 221, 76, 7, 247, 38, 239, 222, 207, 55, 126, 202, 157, 20, 116, 154, 167, 9, 155, 151, 201, 38, 186, 184, 235, 242, 183, 121, 117, 213, 93, 159, 164, 167, 229, 73, 122,
    116, 52, 107, 163, 245, 166, 189, 158, 254, 236, 231, 140, 46, 155, 122, 245, 6, 37, 210, 27, 210, 96, 243, 46, 125, 63, 219, 26, 63, 54, 9, 88, 109, 133, 2, 237, 100, 130, 236, 132,
    181, 221, 88, 23, 167, 23, 217, 50, 191, 156, 204, 235, 100, 50, 153, 55, 9, 59, 105, 78, 187, 168, 236, 37, 54, 144, 86, 31, 37, 85, 68, 53, 216, 235, 110, 58, 61, 79, 58, 127,
    78, 194, 112, 221, 204, 102, 160, 157, 122, 201, 245, 236, 232, 177, 19, 7, 168, 143, 42, 212, 15, 211, 103, 180, 32, 113, 21, 196, 85, 167, 82, 252, 233, 81, 98, 117, 148, 184, 217, 249,
    81, 242, 148, 113, 221, 187, 234, 236, 76, 191, 135, 196, 234, 107, 41, 94, 10, 173, 31, 197, 156, 239, 137, 241, 60, 42, 222, 189, 160, 222, 31, 19, 46, 220, 233, 233, 11, 140, 152, 23,
    239, 184, 58, 154, 190, 56, 50, 10, 115, 196, 167, 167, 106, 246, 62, 121, 241, 232, 140, 54, 225, 86, 10, 237, 20, 143, 37, 92, 130, 164, 135, 107, 233, 108, 12, 95, 132, 143, 183, 20,
    188, 178, 189, 227, 230, 75, 24, 176, 60, 45, 182, 218, 47, 143, 18, 176, 203, 179, 50, 75, 218, 249, 85, 178, 153, 95, 38, 233, 124, 149, 148, 39, 155, 164, 158, 238, 127, 170, 131, 207,
    249, 193, 167, 219, 255, 64, 139, 110, 154, 66, 122, 55, 45, 65, 155, 110, 218, 206, 209, 54, 47, 97, 213, 242, 136, 189, 159, 219, 121, 104, 28, 195, 202, 24, 75, 51, 243, 183, 232, 6,
    127, 63, 231, 98, 30, 74, 20, 50, 70, 105, 135, 59, 52, 140, 238, 8, 220, 177, 115, 195, 12, 10, 33, 199, 227, 25, 102, 106, 253, 13, 249, 126, 46, 48, 132, 51, 133, 229, 66, 75,
    201, 102, 159, 21, 173, 188, 104, 172, 65, 138, 35, 227, 219, 157, 104, 237, 69, 115, 170, 88, 29, 18, 251, 72, 180, 241, 162, 145, 211, 1, 42, 106, 18, 197, 119, 194, 109, 47, 92, 105,
    203, 116, 236, 228, 231, 69, 59, 18, 205, 173, 197, 234, 162, 21, 31, 89, 29, 247, 86, 163, 200, 130, 203, 148, 226, 118, 39, 155, 179, 94, 184, 194, 250, 39, 119, 114, 57, 31, 172, 142,
    99, 166, 176, 104, 25, 241, 121, 209, 92, 120, 217, 48, 12, 229, 151, 113, 98, 132, 184, 236, 133, 43, 6, 195, 176, 228, 141, 68, 171, 193, 110, 205, 0, 138, 16, 49, 27, 201, 215, 94,
    62, 162, 210, 32, 43, 73, 17, 147, 248, 115, 47, 254, 220, 139, 63, 223, 23, 255, 126, 174, 49, 145, 209, 168, 47, 52, 103, 59, 233, 128, 54, 38, 223, 153, 88, 99, 69, 150, 98, 36,
    157, 168, 160, 230, 70, 161, 84, 183, 150, 143, 108, 7, 34, 130, 129, 35, 22, 44, 177, 146, 137, 207, 139, 214, 94, 180, 101, 120, 4, 112, 38, 230, 35, 195, 25, 201, 150, 14, 114, 25,
    121, 238, 81, 176, 246, 130, 67, 99, 152, 178, 78, 74, 189, 147, 172, 122, 201, 10, 165, 141, 180, 78, 185, 207, 75, 142, 73, 178, 70, 145, 174, 96, 132, 27, 9, 86, 131, 209, 40, 125,
    224, 12, 130, 117, 43, 91, 246, 162, 185, 179, 210, 200, 216, 140, 136, 230, 188, 104, 14, 140, 180, 132, 67, 248, 63, 192, 91, 246, 128, 43, 200, 118, 40, 168, 71, 52, 23, 94, 184, 230,
    240, 55, 76, 216, 137, 182, 94, 52, 18, 5, 188, 233, 192, 244, 145, 175, 69, 111, 54, 143, 5, 48, 65, 245, 161, 72, 120, 229, 133, 87, 94, 120, 117, 136, 184, 34, 247, 56, 32, 190,
    147, 11, 3, 56, 159, 163, 24, 18, 66, 91, 168, 37, 15, 92, 109, 192, 78, 25, 51, 60, 186, 16, 151, 31, 101, 19, 228, 18, 179, 105, 137, 42, 91, 155, 207, 75, 230, 94, 50, 167,
    190, 49, 226, 101, 196, 51, 229, 165, 115, 84, 133, 46, 134, 75, 229, 190, 221, 134, 6, 105, 21, 91, 207, 192, 71, 217, 172, 151, 141, 74, 12, 120, 224, 1, 132, 253, 3, 233, 146, 196,
    3, 111, 97, 99, 110, 213, 78, 56, 235, 77, 199, 3, 40, 104, 35, 132, 216, 247, 55, 132, 163, 81, 11, 30, 219, 81, 86, 51, 94, 182, 53, 40, 186, 185, 139, 63, 47, 56, 246, 102,
    67, 63, 105, 20, 30, 23, 70, 76, 19, 189, 100, 37, 184, 227, 218, 17, 149, 247, 88, 110, 230, 128, 10, 79, 3, 90, 140, 66, 91, 244, 86, 199, 49, 114, 169, 67, 180, 146, 236, 218,
    203, 174, 189, 236, 250, 48, 147, 19, 122, 177, 51, 146, 129, 233, 59, 217, 132, 43, 17, 86, 224, 41, 138, 43, 174, 15, 242, 138, 103, 39, 177, 89, 197, 108, 20, 97, 148, 86, 160, 48,
    24, 34, 41, 202, 62, 47, 155, 204, 3, 109, 144, 79, 21, 184, 102, 71, 177, 45, 189, 112, 196, 81, 172, 160, 25, 22, 141, 131, 132, 74, 210, 153, 230, 90, 140, 105, 222, 139, 22, 12,
    42, 9, 184, 48, 254, 188, 112, 231, 101, 35, 80, 177, 34, 72, 29, 143, 64, 215, 189, 112, 48, 134, 131, 6, 106, 127, 29, 33, 201, 218, 80, 232, 35, 243, 140, 132, 75, 47, 157, 131,
    185, 92, 115, 163, 254, 129, 112, 213, 163, 174, 240, 120, 0, 7, 142, 120, 238, 67, 137, 44, 199, 58, 38, 56, 66, 60, 222, 95, 65, 245, 220, 66, 103, 103, 133, 30, 113, 45, 238, 45,
    151, 192, 28, 56, 146, 199, 91, 84, 238, 237, 60, 195, 188, 56, 217, 204, 175, 72, 155, 6, 218, 92, 98, 16, 78, 202, 249, 106, 54, 212, 161, 239, 6, 181, 222, 63, 95, 56, 245, 53,
    226, 182, 100, 58, 59, 3, 255, 251, 66, 234, 124, 87, 69, 29, 205, 206, 223, 85, 239, 209, 74, 195, 250, 187, 238, 176, 202, 234, 203, 169, 143, 201, 20, 149, 212, 203, 189, 186, 174, 58,
    118, 51, 20, 201, 84, 102, 141, 42, 172, 23, 73, 27, 253, 173, 46, 170, 233, 100, 130, 39, 15, 247, 167, 23, 195, 116, 168, 104, 31, 30, 166, 179, 147, 101, 157, 109, 86, 121, 213, 69,
    87, 121, 247, 109, 153, 211, 233, 55, 119, 223, 47, 167, 147, 146, 126, 40, 251, 102, 211, 117, 117, 53, 153, 69, 233, 114, 249, 237, 13, 238, 189, 45, 218, 46, 175, 80, 63, 79, 178, 178,
    200, 126, 159, 204, 31, 159, 137, 242, 217, 125, 153, 227, 41, 202, 151, 197, 255, 241, 195, 219, 239, 186, 110, 253, 83, 254, 159, 155, 188, 237, 78, 186, 168, 174, 154, 60, 93, 222, 161, 58,
    239, 114, 232, 92, 93, 229, 227, 167, 169, 226, 114, 170, 80, 127, 71, 190, 207, 207, 212, 199, 183, 97, 193, 165, 86, 26, 180, 105, 251, 233, 243, 164, 172, 179, 180, 252, 185, 171, 155, 244,
    42, 39, 165, 191, 239, 242, 213, 116, 178, 74, 139, 234, 124, 211, 148, 147, 217, 201, 109, 81, 45, 235, 219, 136, 250, 209, 244, 152, 116, 93, 166, 25, 158, 211, 102, 15, 121, 217, 230, 129,
    98, 124, 55, 235, 159, 167, 237, 117, 125, 251, 102, 211, 118, 245, 234, 117, 153, 55, 120, 246, 194, 128, 118, 141, 103, 190, 156, 30, 23, 102, 243, 103, 1, 218, 180, 121, 83, 44, 129, 205,
    77, 90, 110, 114, 170, 140, 159, 237, 186, 190, 29, 247, 155, 45, 14, 101, 78, 250, 95, 37, 47, 211, 162, 204, 151, 81, 240, 115, 222, 220, 228, 77, 176, 213, 99, 17, 76, 142, 14, 180,
    122, 120, 56, 33, 52, 206, 159, 65, 195, 251, 110, 128, 3, 216, 175, 115, 184, 255, 199, 191, 252, 252, 203, 4, 207, 153, 115, 152, 158, 119, 131, 103, 190, 3, 224, 228, 204, 55, 253, 15,
    169, 225, 47, 120, 4, 154, 204, 39, 233, 122, 13, 239, 122, 248, 142, 255, 214, 214, 213, 201, 254, 239, 185, 152, 149, 164, 87, 201, 193, 99, 210, 61, 65, 242, 253, 114, 241, 133, 144, 205,
    215, 105, 219, 222, 214, 205, 114, 129, 135, 235, 233, 151, 128, 55, 123, 32, 123, 218, 188, 90, 78, 43, 156, 127, 129, 111, 62, 229, 237, 239, 249, 221, 102, 189, 207, 91, 46, 147, 36, 201,
    35, 220, 161, 80, 122, 249, 242, 11, 99, 194, 71, 192, 244, 179, 122, 244, 186, 255, 191, 40, 225, 93, 66, 196, 250, 165, 88, 229, 245, 166, 59, 121, 204, 68, 135, 108, 131, 176, 103, 39,
    175, 234, 174, 184, 28, 92, 255, 67, 222, 182, 160, 21, 132, 20, 21, 180, 38, 226, 37, 249, 243, 182, 142, 135, 126, 147, 54, 94, 55, 56, 152, 140, 38, 4, 240, 160, 13, 61, 38, 179,
    121, 86, 230, 105, 51, 40, 57, 29, 41, 140, 132, 187, 187, 72, 64, 182, 109, 159, 81, 162, 248, 95, 9, 111, 242, 85, 125, 147, 111, 229, 63, 204, 109, 46, 71, 63, 74, 92, 23, 203,
    124, 140, 206, 236, 254, 121, 5, 255, 47, 196, 167, 237, 93, 149, 237, 158, 242, 17, 134, 205, 221, 227, 203, 136, 239, 171, 203, 122, 186, 205, 116, 79, 36, 210, 252, 139, 18, 105, 62, 74,
    164, 47, 95, 250, 44, 154, 239, 101, 209, 174, 143, 220, 53, 197, 244, 180, 187, 46, 218, 253, 236, 242, 252, 162, 128, 180, 212, 66, 82, 255, 160, 191, 71, 140, 46, 90, 123, 35, 234, 46,
    253, 173, 239, 52, 223, 203, 77, 237, 54, 55, 13, 83, 156, 15, 63, 187, 204, 63, 29, 56, 123, 102, 228, 99, 142, 199, 24, 58, 255, 245, 167, 183, 207, 117, 221, 37, 64, 244, 245, 23,
    212, 249, 225, 97, 158, 15, 217, 240, 95, 191, 69, 50, 156, 28, 63, 138, 62, 254, 212, 15, 160, 106, 222, 231, 154, 241, 47, 95, 213, 219, 58, 69, 203, 253, 161, 29, 72, 223, 99, 85,
    62, 126, 252, 50, 235, 39, 60, 98, 17, 131, 168, 157, 117, 95, 56, 211, 14, 141, 201, 113, 255, 150, 139, 102, 217, 25, 254, 133, 211, 140, 144, 154, 28, 251, 139, 201, 103, 120, 254, 188,
    255, 159, 94, 136, 14, 204, 157, 205, 159, 162, 251, 195, 176, 98, 31, 68, 98, 114, 112, 61, 31, 186, 213, 85, 9, 23, 36, 189, 39, 78, 78, 143, 251, 159, 111, 207, 78, 219, 238, 174,
    204, 207, 46, 234, 229, 221, 253, 69, 154, 253, 126, 213, 212, 155, 106, 185, 248, 138, 199, 244, 135, 146, 10, 203, 219, 101, 186, 42, 202, 187, 69, 155, 86, 109, 72, 43, 196, 101, 223, 220,
    22, 127, 228, 11, 174, 214, 31, 78, 178, 186, 172, 155, 197, 87, 233, 146, 254, 30, 162, 203, 186, 238, 242, 230, 126, 93, 183, 5, 121, 127, 113, 89, 124, 200, 151, 72, 180, 151, 221, 130,
    157, 92, 212, 72, 193, 43, 156, 248, 151, 122, 11, 206, 216, 215, 39, 253, 27, 189, 133, 112, 152, 171, 44, 170, 60, 220, 54, 224, 122, 167, 84, 56, 136, 65, 209, 140, 191, 173, 80, 23,
    211, 223, 73, 7, 52, 195, 180, 44, 174, 170, 69, 6, 220, 243, 102, 172, 163, 92, 127, 120, 240, 220, 255, 231, 226, 230, 126, 89, 180, 168, 108, 238, 22, 151, 101, 254, 225, 100, 149, 54,
    240, 93, 216, 213, 235, 133, 68, 198, 217, 94, 15, 74, 42, 106, 162, 126, 225, 178, 104, 114, 79, 229, 5, 196, 110, 86, 213, 137, 23, 21, 22, 112, 87, 59, 8, 124, 64, 249, 185, 186,
    191, 192, 194, 156, 55, 11, 190, 254, 16, 180, 117, 89, 44, 131, 175, 114, 67, 127, 82, 14, 6, 11, 199, 96, 213, 214, 64, 67, 23, 35, 37, 52, 93, 175, 145, 247, 225, 247, 133, 164,
    139, 126, 194, 176, 73, 151, 197, 166, 93, 208, 43, 207, 79, 109, 125, 136, 174, 125, 69, 242, 83, 125, 59, 40, 176, 181, 224, 19, 61, 120, 54, 6, 126, 144, 60, 184, 102, 184, 106, 188,
    106, 108, 172, 150, 5, 128, 215, 252, 126, 212, 18, 234, 157, 226, 91, 151, 62, 128, 216, 235, 77, 71, 32, 143, 122, 242, 81, 207, 207, 10, 26, 166, 145, 232, 255, 224, 39, 218, 35, 164,
    80, 244, 183, 245, 250, 133, 164, 191, 45, 164, 122, 4, 169, 82, 251, 136, 114, 183, 67, 180, 151, 239, 21, 218, 182, 244, 58, 248, 166, 193, 117, 236, 0, 114, 154, 239, 128, 239, 88, 152,
    154, 203, 178, 190, 93, 32, 214, 150, 121, 245, 16, 141, 138, 139, 71, 126, 21, 149, 167, 178, 167, 217, 158, 33, 75, 125, 153, 103, 91, 67, 114, 5, 175, 92, 156, 100, 155, 166, 197, 229,
    26, 143, 28, 196, 221, 193, 69, 123, 118, 141, 180, 94, 8, 220, 8, 124, 203, 85, 10, 19, 217, 86, 197, 219, 190, 47, 158, 106, 199, 42, 155, 231, 141, 163, 208, 120, 130, 203, 232, 245,
    33, 108, 175, 83, 36, 142, 5, 11, 32, 39, 32, 132, 130, 175, 152, 255, 47, 22, 39, 93, 131, 100, 208, 71, 119, 90, 150, 1, 139, 132, 110, 131, 60, 109, 243, 61, 44, 130, 40, 109,
    154, 250, 54, 188, 109, 80, 26, 35, 35, 140, 67, 239, 169, 142, 123, 180, 129, 98, 91, 166, 142, 2, 102, 253, 36, 152, 143, 169, 166, 201, 75, 84, 19, 55, 249, 88, 65, 175, 220, 83,
    226, 22, 139, 139, 28, 65, 155, 223, 15, 27, 34, 22, 147, 73, 111, 120, 241, 7, 129, 252, 24, 73, 31, 118, 243, 167, 23, 136, 166, 77, 151, 111, 241, 220, 198, 86, 239, 197, 97, 68,
    175, 54, 11, 160, 172, 255, 176, 19, 31, 49, 4, 117, 79, 55, 58, 59, 84, 112, 23, 245, 219, 155, 148, 79, 22, 77, 77, 229, 200, 52, 84, 122, 153, 95, 205, 246, 172, 88, 92, 19,
    15, 239, 63, 77, 144, 106, 233, 196, 229, 229, 19, 125, 183, 48, 143, 17, 236, 85, 127, 190, 243, 22, 163, 33, 88, 247, 59, 166, 25, 129, 253, 132, 10, 140, 41, 157, 155, 145, 29, 126,
    79, 202, 52, 138, 45, 108, 56, 40, 251, 14, 23, 10, 2, 139, 109, 29, 46, 15, 215, 4, 223, 208, 35, 236, 144, 193, 198, 166, 100, 153, 84, 74, 63, 177, 20, 12, 74, 93, 94, 126,
    178, 114, 141, 163, 166, 164, 111, 244, 62, 8, 224, 11, 172, 209, 191, 159, 220, 20, 109, 113, 81, 148, 69, 119, 55, 4, 253, 73, 189, 78, 51, 186, 100, 99, 87, 14, 141, 1, 82, 210,
    170, 15, 136, 176, 168, 230, 187, 193, 193, 168, 185, 239, 116, 16, 144, 148, 105, 15, 1, 138, 168, 6, 190, 31, 105, 224, 79, 203, 252, 81, 5, 62, 82, 33, 92, 230, 164, 60, 102, 126,
    192, 34, 239, 23, 247, 211, 227, 126, 139, 17, 45, 242, 103, 167, 203, 226, 38, 240, 101, 118, 50, 172, 136, 168, 1, 30, 183, 225, 60, 191, 11, 39, 24, 138, 146, 132, 71, 124, 216, 144,
    35, 21, 165, 161, 97, 59, 142, 137, 113, 78, 219, 148, 190, 169, 63, 36, 19, 22, 128, 254, 150, 199, 72, 30, 70, 178, 201, 217, 233, 176, 157, 102, 242, 131, 193, 168, 192, 90, 153, 242,
    88, 5, 244, 65, 87, 22, 162, 77, 10, 150, 25, 17, 104, 27, 24, 70, 223, 86, 107, 127, 96, 52, 151, 101, 6, 223, 78, 50, 220, 76, 53, 77, 27, 83, 51, 227, 1, 38, 97, 90,
    102, 33, 151, 58, 240, 47, 207, 209, 197, 134, 180, 33, 6, 135, 152, 97, 254, 208, 49, 122, 185, 47, 113, 20, 129, 115, 230, 198, 74, 86, 10, 137, 252, 185, 167, 3, 41, 16, 40, 150,
    105, 27, 26, 25, 208, 55, 201, 15, 45, 139, 127, 19, 24, 113, 173, 153, 204, 44, 147, 164, 6, 109, 9, 112, 144, 43, 105, 39, 1, 75, 99, 232, 18, 247, 250, 176, 144, 211, 139, 118,
    43, 73, 35, 171, 66, 252, 207, 149, 12, 45, 15, 99, 193, 66, 171, 75, 204, 199, 66, 25, 42, 218, 161, 179, 178, 2, 218, 114, 150, 133, 176, 139, 155, 80, 243, 64, 66, 44, 105, 94,
    134, 180, 129, 71, 145, 117, 112, 64, 38, 3, 14, 216, 66, 28, 4, 218, 173, 8, 184, 18, 28, 154, 67, 79, 46, 131, 88, 216, 192, 41, 23, 196, 152, 6, 107, 36, 44, 230, 220, 133,
    180, 29, 196, 72, 122, 113, 18, 10, 166, 82, 131, 14, 244, 33, 208, 66, 5, 52, 20, 143, 51, 220, 9, 117, 28, 10, 30, 58, 21, 10, 13, 61, 227, 18, 218, 25, 109, 175, 133, 4,
    60, 206, 65, 49, 250, 242, 0, 9, 154, 142, 101, 92, 216, 80, 197, 164, 66, 40, 36, 181, 134, 146, 51, 18, 135, 9, 160, 36, 190, 81, 227, 224, 67, 54, 200, 80, 222, 132, 82, 137,
    140, 209, 59, 23, 76, 45, 99, 22, 26, 218, 88, 161, 66, 218, 79, 194, 60, 74, 134, 70, 225, 195, 86, 92, 225, 190, 36, 189, 128, 75, 8, 117, 37, 221, 13, 180, 240, 128, 72, 73,
    16, 112, 171, 179, 16, 192, 72, 184, 219, 224, 32, 209, 70, 91, 77, 52, 58, 18, 160, 202, 210, 102, 45, 112, 134, 96, 193, 145, 8, 71, 144, 8, 210, 142, 27, 69, 63, 162, 246, 144,
    72, 30, 208, 167, 135, 68, 66, 158, 54, 228, 54, 210, 135, 182, 133, 208, 39, 38, 135, 221, 128, 17, 186, 20, 10, 10, 103, 146, 105, 72, 149, 232, 130, 145, 116, 128, 195, 105, 122, 45,
    66, 130, 199, 9, 24, 10, 6, 56, 249, 29, 215, 210, 50, 130, 83, 26, 149, 145, 207, 57, 233, 33, 99, 67, 96, 43, 64, 131, 33, 146, 198, 227, 192, 225, 3, 224, 184, 10, 37, 89,
    97, 189, 30, 138, 236, 1, 214, 160, 52, 177, 69, 170, 0, 140, 68, 197, 8, 90, 58, 248, 18, 22, 211, 22, 26, 69, 220, 225, 12, 84, 131, 226, 126, 83, 8, 109, 9, 210, 33, 237,
    198, 146, 6, 132, 78, 157, 229, 1, 125, 188, 153, 0, 24, 94, 18, 192, 19, 12, 17, 223, 129, 40, 138, 60, 202, 117, 64, 211, 16, 29, 129, 44, 151, 196, 9, 68, 92, 104, 129, 177,
    229, 26, 209, 101, 141, 127, 137, 25, 114, 161, 221, 10, 74, 35, 244, 36, 152, 171, 136, 33, 80, 159, 66, 83, 11, 25, 198, 82, 80, 96, 208, 120, 28, 97, 18, 113, 22, 151, 52, 173,
    36, 126, 162, 59, 124, 34, 232, 35, 52, 248, 206, 3, 141, 38, 11, 212, 2, 2, 219, 127, 27, 138, 121, 200, 21, 1, 164, 27, 154, 144, 133, 177, 225, 41, 237, 213, 162, 143, 15, 124,
    67, 105, 195, 105, 40, 47, 189, 20, 71, 125, 252, 65, 248, 225, 158, 252, 184, 39, 4, 89, 170, 40, 40, 87, 70, 123, 98, 165, 130, 182, 225, 225, 211, 71, 172, 48, 132, 32, 108, 1,
    78, 160, 37, 229, 24, 196, 30, 225, 97, 227, 82, 145, 122, 172, 247, 83, 32, 29, 186, 17, 50, 154, 89, 28, 209, 83, 129, 11, 208, 69, 105, 10, 77, 194, 80, 121, 109, 40, 90, 85,
    108, 83, 216, 44, 200, 81, 244, 237, 181, 166, 173, 72, 128, 49, 163, 188, 128, 11, 135, 94, 14, 153, 136, 2, 139, 54, 192, 105, 135, 232, 32, 233, 180, 211, 204, 208, 29, 70, 239, 144,
    104, 255, 32, 189, 119, 246, 198, 8, 7, 17, 224, 34, 167, 123, 206, 223, 209, 208, 2, 1, 40, 209, 209, 145, 227, 201, 18, 104, 40, 65, 24, 71, 76, 5, 172, 78, 210, 8, 74, 11,
    46, 180, 82, 16, 109, 41, 33, 209, 180, 62, 255, 134, 180, 3, 142, 2, 132, 248, 3, 31, 56, 179, 2, 188, 20, 62, 134, 18, 20, 216, 135, 36, 102, 98, 13, 221, 132, 63, 90, 78,
    142, 128, 11, 1, 95, 12, 49, 58, 136, 175, 241, 141, 12, 23, 82, 246, 115, 72, 18, 72, 45, 26, 74, 91, 71, 214, 64, 115, 19, 179, 73, 191, 177, 232, 43, 145, 93, 168, 84, 249,
    139, 176, 217, 148, 121, 146, 223, 228, 85, 189, 92, 6, 199, 163, 181, 66, 16, 99, 116, 28, 167, 92, 67, 42, 192, 237, 15, 158, 200, 126, 39, 19, 161, 47, 28, 237, 78, 244, 223, 125,
    32, 199, 54, 16, 14, 25, 20, 206, 2, 199, 24, 69, 52, 242, 51, 165, 106, 218, 59, 230, 66, 218, 52, 166, 117, 169, 181, 242, 41, 31, 206, 134, 195, 40, 100, 192, 150, 12, 125, 73,
    87, 178, 42, 164, 149, 1, 65, 139, 204, 35, 82, 110, 16, 42, 32, 103, 127, 240, 233, 16, 19, 132, 180, 104, 113, 44, 3, 152, 218, 90, 56, 19, 60, 176, 20, 221, 72, 229, 156, 232,
    7, 111, 194, 45, 14, 166, 3, 118, 197, 88, 106, 5, 37, 166, 237, 90, 129, 110, 86, 175, 64, 51, 218, 98, 199, 237, 27, 122, 233, 100, 131, 152, 81, 214, 245, 234, 27, 138, 238, 24,
    101, 13, 220, 32, 109, 230, 144, 250, 99, 218, 121, 41, 49, 64, 99, 129, 20, 22, 124, 55, 196, 87, 6, 151, 10, 124, 105, 103, 40, 239, 18, 53, 192, 12, 33, 12, 95, 241, 56, 166,
    165, 44, 165, 245, 130, 62, 94, 54, 81, 134, 169, 12, 28, 131, 222, 113, 96, 41, 177, 130, 77, 86, 94, 35, 218, 76, 137, 252, 44, 100, 74, 145, 228, 163, 137, 70, 32, 77, 105, 11,
    42, 88, 90, 53, 12, 165, 80, 122, 17, 134, 69, 128, 93, 211, 11, 105, 85, 250, 85, 77, 174, 36, 237, 34, 139, 83, 100, 116, 170, 112, 6, 75, 41, 65, 51, 218, 157, 170, 4, 165,
    181, 254, 48, 132, 159, 160, 124, 224, 136, 201, 218, 127, 60, 186, 156, 226, 163, 47, 9, 40, 165, 104, 204, 228, 87, 73, 218, 217, 72, 225, 26, 194, 125, 196, 87, 4, 84, 64, 20, 71,
    6, 68, 106, 71, 234, 85, 68, 107, 80, 205, 210, 129, 226, 29, 93, 17, 49, 64, 134, 242, 50, 226, 20, 94, 139, 177, 86, 130, 230, 148, 133, 98, 154, 67, 32, 112, 144, 130, 161, 61,
    86, 84, 29, 99, 85, 165, 29, 182, 112, 166, 65, 36, 209, 219, 127, 192, 199, 73, 28, 90, 104, 199, 34, 178, 55, 173, 127, 148, 144, 105, 237, 35, 75, 99, 2, 2, 162, 253, 226, 33,
    104, 65, 68, 13, 140, 51, 5, 255, 51, 205, 67, 42, 37, 128, 169, 162, 141, 139, 184, 137, 163, 65, 132, 97, 57, 167, 193, 206, 129, 165, 130, 106, 30, 138, 234, 128, 248, 2, 197, 165,
    118, 84, 235, 112, 31, 4, 254, 48, 96, 233, 27, 244, 27, 32, 7, 208, 144, 138, 161, 43, 129, 202, 226, 237, 153, 230, 246, 70, 26, 81, 66, 113, 2, 15, 253, 173, 201, 56, 140, 183,
    148, 204, 192, 48, 229, 35, 65, 114, 91, 146, 87, 53, 133, 135, 166, 37, 29, 137, 92, 164, 244, 50, 152, 24, 37, 7, 23, 33, 206, 176, 166, 163, 151, 21, 198, 250, 133, 213, 31, 122,
    55, 33, 56, 104, 233, 201, 176, 244, 192, 35, 152, 71, 185, 208, 113, 162, 54, 173, 96, 40, 196, 250, 210, 139, 38, 64, 10, 4, 215, 105, 137, 166, 148, 194, 253, 222, 79, 164, 75, 78,
    41, 16, 125, 81, 38, 105, 4, 162, 0, 139, 44, 90, 28, 86, 47, 129, 238, 72, 212, 214, 159, 132, 84, 223, 0, 97, 32, 109, 124, 93, 197, 105, 73, 242, 251, 55, 185, 250, 65, 250,
    68, 45, 21, 2, 31, 171, 2, 32, 101, 41, 10, 1, 6, 15, 13, 135, 30, 59, 68, 25, 156, 138, 245, 24, 171, 115, 64, 202, 209, 1, 170, 34, 180, 181, 43, 133, 163, 45, 164, 38,
    35, 71, 11, 73, 5, 7, 72, 136, 168, 208, 156, 8, 137, 24, 71, 104, 195, 243, 72, 215, 212, 145, 188, 197, 216, 107, 216, 7, 91, 130, 225, 224, 179, 188, 116, 200, 76, 130, 97, 81,
    209, 136, 79, 100, 127, 248, 203, 208, 75, 82, 42, 135, 17, 65, 26, 171, 47, 85, 167, 196, 10, 172, 192, 158, 18, 202, 215, 78, 160, 41, 133, 26, 50, 166, 166, 204, 227, 183, 128, 250,
    42, 13, 89, 53, 20, 134, 196, 184, 21, 189, 1, 166, 249, 157, 47, 148, 168, 43, 85, 97, 168, 67, 40, 141, 75, 10, 7, 170, 168, 66, 218, 20, 14, 126, 149, 20, 218, 146, 12, 130,
    61, 25, 49, 157, 104, 67, 43, 45, 113, 140, 118, 200, 130, 5, 84, 146, 254, 38, 156, 48, 25, 209, 23, 35, 201, 111, 20, 80, 126, 17, 69, 173, 226, 124, 177, 70, 73, 92, 121, 162,
    75, 247, 131, 162, 172, 101, 21, 146, 61, 100, 162, 34, 211, 148, 235, 60, 14, 94, 36, 37, 108, 170, 14, 80, 105, 161, 128, 166, 77, 191, 254, 187, 175, 181, 137, 58, 86, 100, 200, 75,
    1, 165, 91, 34, 45, 197, 166, 64, 209, 137, 24, 215, 30, 110, 174, 135, 26, 31, 148, 5, 103, 64, 50, 31, 28, 80, 28, 217, 138, 56, 131, 92, 134, 43, 65, 27, 177, 49, 57, 130,
    137, 170, 122, 28, 160, 41, 168, 65, 145, 130, 197, 135, 194, 155, 122, 152, 84, 24, 67, 123, 223, 253, 119, 191, 84, 32, 41, 11, 11, 46, 130, 82, 40, 165, 156, 79, 25, 152, 81, 58,
    242, 35, 56, 135, 111, 170, 215, 0, 28, 5, 72, 160, 123, 231, 216, 173, 115, 168, 146, 135, 4, 218, 194, 128, 111, 37, 236, 13, 106, 8, 16, 208, 13, 96, 33, 50, 88, 214, 231, 73,
    90, 84, 8, 68, 78, 155, 129, 25, 213, 202, 68, 94, 148, 73, 70, 248, 88, 241, 123, 142, 41, 121, 162, 30, 3, 89, 168, 108, 15, 98, 131, 80, 20, 40, 164, 250, 239, 62, 109, 211,
    191, 59, 240, 233, 81, 208, 195, 200, 112, 240, 183, 104, 15, 47, 150, 24, 36, 37, 170, 142, 232, 171, 127, 180, 146, 180, 137, 95, 103, 190, 86, 160, 93, 238, 0, 140, 246, 205, 83, 164,
    129, 20, 148, 30, 176, 184, 4, 30, 85, 184, 59, 213, 180, 103, 37, 232, 191, 251, 66, 75, 50, 95, 73, 0, 86, 78, 25, 190, 63, 12, 142, 161, 114, 94, 184, 76, 80, 137, 136, 170,
    136, 158, 100, 168, 200, 64, 111, 229, 139, 120, 225, 151, 160, 144, 54, 86, 11, 42, 189, 113, 138, 60, 24, 208, 250, 68, 121, 32, 222, 214, 3, 249, 146, 254, 158, 174, 7, 232, 241, 243,
    236, 148, 126, 70, 56, 59, 189, 230, 103, 175, 55, 221, 53, 158, 235, 135, 231, 99, 60, 220, 242, 241, 67, 237, 227, 47, 161, 24, 183, 164, 135, 219, 221, 173, 237, 175, 147, 103, 167, 254,
    44, 40, 150, 73, 255, 198, 179, 255, 39, 50, 195, 185, 127, 237, 125, 93, 151, 152, 37, 249, 21, 77, 116, 239, 44, 216, 13, 89, 223, 14, 253, 233, 100, 220, 249, 199, 225, 189, 108, 191,
    37, 122, 123, 181, 85, 227, 162, 255, 229, 201, 223, 27, 206, 49, 217, 248, 71, 169, 94, 201, 81, 203, 240, 175, 110, 78, 219, 117, 186, 189, 187, 247, 123, 218, 217, 39, 119, 8, 43, 52,
    237, 14, 189, 36, 156, 244, 232, 17, 22, 144, 122, 240, 251, 194, 48, 195, 65, 235, 48, 251, 65, 247, 225, 237, 230, 78, 130, 55, 238, 16, 233, 254, 13, 0, 42, 185, 179, 199, 151, 22,
    65, 24, 12, 47, 170, 130, 199, 137, 247, 222, 139, 156, 249, 119, 58, 195, 188, 232, 253, 223, 255, 133, 12, 39, 244, 233, 241, 250, 81, 74, 255, 3, 198, 177, 255, 71, 84, 255, 3, 38,
    65, 255, 37, 84, 53, 0, 0
};
