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

const uint8_t PrettyOTA::PRETTY_OTA_WEBSITE_DATA[12662] = {
    31, 139, 8, 8, 187, 243, 235, 103, 0, 3, 112, 114, 101, 116, 116, 121, 79, 84, 65, 95, 109, 105, 110, 105, 102, 121, 46, 104, 116, 109, 108, 0, 229, 125, 139, 118, 219, 86, 150, 229, 175,
    32, 172, 78, 66, 182, 9, 248, 62, 241, 144, 68, 101, 18, 39, 85, 174, 89, 118, 87, 173, 56, 229, 233, 233, 172, 116, 26, 34, 33, 137, 29, 138, 80, 145, 148, 28, 71, 81, 255, 207,
    252, 198, 124, 217, 236, 125, 46, 72, 2, 20, 41, 43, 233, 84, 205, 244, 154, 56, 34, 128, 251, 58, 231, 158, 247, 125, 224, 226, 228, 163, 73, 61, 94, 189, 191, 174, 162, 203, 213, 213,
    236, 244, 132, 191, 209, 172, 156, 95, 140, 170, 57, 158, 170, 114, 114, 122, 114, 85, 173, 202, 104, 124, 89, 46, 150, 213, 106, 244, 151, 111, 126, 31, 231, 77, 218, 188, 188, 170, 70, 183,
    211, 234, 221, 117, 189, 88, 69, 227, 122, 190, 170, 230, 171, 81, 239, 221, 116, 178, 186, 28, 77, 170, 219, 233, 184, 138, 229, 97, 56, 157, 79, 87, 211, 114, 22, 47, 199, 229, 172, 26,
    233, 94, 187, 129, 73, 181, 28, 47, 166, 215, 171, 105, 61, 223, 182, 241, 121, 116, 86, 173, 86, 213, 34, 154, 213, 245, 15, 211, 249, 69, 244, 167, 111, 62, 143, 222, 85, 103, 209, 205,
    245, 164, 68, 122, 130, 38, 86, 211, 213, 172, 58, 253, 243, 2, 5, 223, 35, 251, 228, 121, 72, 56, 153, 77, 231, 63, 68, 139, 106, 54, 154, 162, 185, 136, 157, 27, 77, 175, 202, 139,
    234, 249, 242, 246, 226, 217, 143, 232, 223, 229, 162, 58, 31, 245, 208, 78, 121, 212, 201, 24, 126, 108, 95, 224, 54, 194, 237, 124, 57, 250, 244, 114, 181, 186, 62, 122, 254, 252, 221, 187,
    119, 201, 59, 155, 212, 139, 139, 231, 70, 41, 197, 194, 159, 70, 161, 143, 159, 122, 109, 62, 141, 46, 171, 233, 197, 229, 170, 121, 144, 186, 71, 183, 161, 246, 18, 213, 111, 171, 241, 170,
    76, 166, 245, 243, 121, 57, 175, 63, 253, 216, 126, 5, 32, 215, 229, 234, 50, 154, 140, 62, 125, 173, 34, 117, 137, 106, 183, 248, 123, 169, 222, 170, 159, 62, 141, 206, 167, 179, 217, 232,
    211, 143, 141, 117, 158, 255, 62, 125, 190, 83, 67, 123, 159, 88, 159, 71, 121, 145, 228, 222, 206, 108, 98, 51, 29, 39, 202, 152, 200, 38, 153, 50, 184, 85, 57, 110, 243, 162, 96, 106,
    164, 77, 146, 155, 20, 183, 78, 71, 46, 113, 214, 226, 86, 155, 200, 168, 36, 207, 152, 138, 91, 155, 20, 41, 75, 100, 89, 164, 243, 196, 231, 172, 232, 242, 72, 235, 68, 73, 186, 77,
    95, 152, 194, 36, 153, 73, 9, 212, 2, 16, 106, 155, 44, 141, 10, 159, 56, 147, 69, 214, 165, 0, 163, 198, 168, 224, 181, 102, 189, 220, 163, 41, 20, 69, 43, 38, 77, 116, 238, 34,
    227, 34, 103, 102, 0, 228, 129, 155, 86, 126, 236, 19, 159, 2, 54, 96, 56, 27, 153, 36, 69, 25, 231, 18, 19, 123, 41, 147, 178, 3, 126, 22, 235, 196, 42, 214, 80, 230, 133, 245,
    54, 241, 168, 129, 75, 129, 171, 181, 22, 149, 80, 53, 51, 9, 160, 89, 0, 54, 185, 30, 199, 232, 65, 138, 142, 164, 73, 86, 248, 216, 166, 73, 106, 138, 40, 75, 76, 17, 251, 52,
    177, 232, 120, 150, 104, 54, 156, 38, 133, 97, 255, 85, 193, 26, 74, 72, 33, 183, 94, 145, 66, 238, 149, 206, 60, 26, 204, 103, 66, 78, 246, 200, 36, 218, 101, 196, 49, 5, 68, 149,
    105, 226, 158, 42, 160, 230, 83, 146, 45, 7, 44, 101, 125, 84, 0, 255, 12, 248, 90, 210, 65, 59, 38, 90, 116, 192, 106, 59, 38, 63, 136, 140, 74, 93, 156, 120, 80, 94, 219, 196,
    104, 244, 24, 196, 97, 11, 222, 226, 62, 79, 65, 136, 36, 75, 129, 140, 74, 84, 30, 144, 183, 177, 206, 208, 161, 76, 42, 91, 32, 175, 129, 55, 19, 164, 16, 16, 7, 105, 188, 137,
    209, 94, 150, 217, 56, 79, 108, 154, 33, 73, 89, 19, 59, 16, 208, 197, 36, 85, 17, 103, 137, 103, 73, 136, 139, 8, 5, 168, 64, 177, 97, 138, 8, 136, 202, 81, 90, 129, 106, 72,
    149, 122, 66, 20, 20, 118, 137, 246, 65, 108, 144, 156, 103, 34, 76, 38, 54, 38, 41, 180, 17, 177, 137, 193, 100, 39, 228, 116, 121, 12, 217, 112, 182, 16, 177, 33, 28, 163, 40, 157,
    26, 152, 234, 196, 137, 200, 177, 21, 163, 220, 56, 84, 5, 178, 142, 37, 216, 23, 8, 54, 56, 10, 9, 64, 25, 80, 151, 29, 6, 185, 13, 43, 104, 11, 225, 75, 10, 75, 1, 201,
    64, 46, 15, 186, 123, 185, 55, 80, 1, 83, 8, 144, 20, 132, 246, 185, 22, 1, 71, 175, 10, 98, 10, 185, 200, 19, 157, 250, 160, 23, 64, 168, 240, 105, 96, 4, 24, 150, 187, 208,
    1, 170, 131, 149, 116, 239, 35, 144, 52, 115, 82, 53, 27, 27, 54, 147, 75, 178, 179, 196, 46, 102, 167, 163, 20, 146, 238, 41, 45, 26, 90, 128, 242, 41, 8, 72, 118, 23, 128, 144,
    66, 74, 65, 5, 244, 2, 48, 240, 100, 64, 71, 135, 190, 131, 63, 128, 7, 182, 50, 41, 5, 15, 179, 12, 220, 0, 251, 80, 26, 220, 45, 188, 20, 43, 116, 33, 108, 36, 221, 209,
    160, 141, 13, 248, 159, 25, 161, 141, 142, 33, 125, 185, 150, 7, 147, 233, 25, 56, 151, 139, 194, 235, 20, 100, 212, 150, 196, 213, 185, 48, 55, 232, 176, 142, 45, 68, 149, 2, 173, 193,
    5, 227, 64, 88, 210, 9, 189, 64, 153, 76, 236, 67, 30, 211, 140, 152, 192, 82, 80, 15, 189, 84, 26, 188, 201, 192, 80, 210, 0, 6, 0, 252, 79, 201, 104, 7, 122, 130, 78, 169,
    72, 108, 78, 166, 164, 57, 5, 54, 215, 49, 149, 202, 81, 22, 53, 133, 19, 10, 220, 200, 171, 136, 168, 72, 107, 212, 72, 168, 136, 107, 20, 36, 52, 136, 43, 88, 172, 181, 143, 13,
    45, 22, 133, 61, 79, 69, 92, 133, 87, 166, 72, 69, 96, 219, 102, 209, 140, 207, 108, 153, 174, 205, 34, 141, 49, 238, 224, 12, 130, 15, 9, 214, 254, 170, 158, 220, 204, 170, 104, 188,
    168, 151, 203, 122, 49, 189, 152, 206, 79, 225, 9, 150, 171, 104, 57, 171, 170, 235, 81, 53, 58, 157, 87, 239, 162, 63, 47, 234, 171, 233, 178, 234, 175, 70, 167, 112, 108, 223, 76, 175,
    170, 250, 102, 213, 95, 13, 171, 193, 96, 120, 53, 241, 163, 243, 155, 249, 152, 78, 169, 63, 184, 91, 223, 70, 85, 191, 26, 174, 134, 243, 97, 61, 92, 12, 103, 131, 187, 219, 114, 17,
    149, 195, 233, 49, 92, 208, 205, 98, 30, 45, 251, 253, 114, 180, 236, 47, 165, 145, 225, 178, 95, 163, 204, 96, 56, 29, 45, 134, 229, 201, 201, 244, 231, 242, 244, 244, 20, 18, 60, 29,
    12, 231, 131, 251, 77, 147, 4, 25, 26, 92, 14, 103, 195, 114, 112, 215, 52, 86, 245, 231, 159, 212, 63, 255, 199, 252, 147, 133, 64, 12, 153, 219, 106, 243, 71, 170, 45, 126, 174, 63,
    249, 143, 253, 213, 234, 195, 213, 254, 181, 254, 215, 253, 117, 22, 7, 235, 212, 255, 218, 159, 255, 252, 31, 139, 193, 222, 106, 75, 210, 42, 208, 104, 62, 234, 167, 222, 91, 255, 73, 53,
    120, 214, 220, 173, 6, 13, 213, 250, 213, 233, 169, 78, 145, 190, 106, 174, 115, 185, 158, 156, 232, 244, 231, 80, 116, 126, 223, 0, 108, 177, 1, 196, 159, 69, 83, 240, 180, 156, 143, 171,
    250, 60, 250, 203, 116, 190, 202, 63, 95, 44, 202, 247, 63, 255, 220, 159, 141, 200, 223, 111, 170, 31, 87, 95, 205, 199, 245, 164, 90, 244, 7, 73, 37, 119, 253, 222, 114, 181, 64, 56,
    209, 27, 141, 40, 41, 168, 56, 251, 108, 118, 244, 223, 223, 252, 233, 159, 146, 144, 49, 61, 127, 143, 182, 7, 131, 227, 243, 122, 209, 111, 216, 59, 250, 246, 187, 225, 68, 154, 220, 66,
    65, 161, 225, 205, 72, 13, 199, 163, 73, 114, 246, 126, 85, 189, 170, 230, 23, 171, 203, 227, 155, 147, 241, 241, 205, 179, 103, 131, 105, 114, 125, 179, 188, 236, 191, 145, 54, 147, 115, 72,
    218, 11, 196, 79, 47, 136, 193, 228, 219, 155, 239, 6, 235, 206, 183, 187, 4, 90, 173, 129, 130, 218, 163, 30, 204, 24, 130, 128, 52, 203, 139, 242, 108, 60, 169, 206, 123, 195, 197, 168,
    215, 27, 46, 71, 234, 120, 121, 178, 74, 102, 1, 226, 18, 208, 22, 207, 70, 117, 194, 0, 237, 243, 85, 191, 63, 31, 173, 228, 158, 192, 240, 188, 28, 12, 32, 118, 238, 19, 237, 7,
    207, 54, 133, 52, 136, 186, 65, 97, 113, 223, 63, 128, 5, 193, 213, 0, 87, 159, 88, 243, 143, 27, 136, 245, 179, 81, 62, 152, 63, 27, 237, 235, 220, 234, 219, 250, 244, 212, 127, 7,
    136, 245, 199, 214, 124, 98, 188, 223, 128, 153, 119, 192, 136, 28, 205, 190, 45, 89, 250, 231, 145, 54, 249, 201, 73, 137, 26, 195, 217, 183, 218, 61, 235, 151, 207, 82, 135, 54, 138, 147,
    19, 55, 248, 110, 84, 110, 152, 49, 29, 233, 204, 26, 159, 59, 93, 88, 176, 4, 214, 17, 207, 54, 207, 10, 240, 34, 222, 100, 57, 112, 101, 157, 147, 15, 191, 71, 7, 190, 63, 153,
    173, 177, 255, 254, 217, 8, 210, 37, 82, 121, 53, 154, 14, 47, 70, 147, 225, 63, 140, 110, 134, 151, 163, 241, 241, 100, 180, 232, 119, 255, 234, 157, 191, 249, 206, 223, 170, 251, 7, 44,
    86, 253, 27, 64, 95, 245, 199, 16, 155, 85, 127, 58, 68, 218, 112, 140, 94, 125, 255, 76, 125, 55, 204, 134, 113, 154, 43, 184, 208, 194, 166, 3, 201, 98, 134, 254, 110, 168, 205, 48,
    182, 136, 120, 82, 231, 115, 228, 176, 26, 115, 12, 114, 178, 97, 170, 82, 68, 76, 185, 46, 6, 104, 105, 42, 25, 246, 187, 161, 65, 21, 173, 28, 252, 138, 183, 86, 13, 30, 5, 237,
    4, 52, 156, 149, 211, 112, 13, 217, 22, 180, 23, 208, 154, 97, 109, 14, 15, 208, 2, 157, 10, 104, 24, 127, 16, 21, 193, 139, 211, 91, 224, 89, 0, 238, 124, 166, 124, 145, 219, 199,
    65, 231, 4, 173, 179, 12, 110, 200, 59, 221, 234, 117, 17, 122, 141, 104, 12, 44, 115, 78, 103, 91, 216, 90, 5, 224, 14, 142, 210, 110, 225, 106, 221, 244, 186, 40, 148, 131, 119, 75,
    205, 227, 160, 181, 17, 216, 232, 24, 226, 180, 52, 55, 45, 138, 219, 0, 220, 41, 116, 12, 190, 177, 5, 218, 53, 253, 246, 10, 68, 49, 166, 80, 45, 248, 94, 224, 67, 43, 83, 88,
    37, 107, 10, 130, 159, 11, 248, 185, 128, 159, 119, 193, 127, 55, 244, 104, 40, 245, 8, 68, 188, 86, 91, 232, 32, 109, 65, 222, 165, 133, 135, 235, 182, 166, 5, 157, 162, 224, 134, 169,
    67, 76, 159, 101, 186, 213, 119, 80, 196, 40, 200, 72, 6, 41, 201, 172, 50, 143, 131, 246, 2, 58, 83, 24, 43, 228, 105, 161, 91, 29, 87, 132, 109, 115, 192, 85, 228, 220, 6, 176,
    23, 192, 113, 154, 42, 151, 229, 214, 250, 45, 100, 23, 32, 59, 196, 64, 54, 203, 93, 254, 56, 228, 130, 144, 61, 162, 121, 135, 78, 228, 45, 192, 174, 233, 52, 98, 36, 48, 131, 100,
    93, 195, 182, 1, 180, 206, 51, 155, 218, 34, 109, 9, 90, 46, 160, 53, 104, 228, 45, 24, 162, 63, 64, 111, 27, 8, 238, 0, 59, 71, 228, 221, 18, 115, 35, 192, 189, 6, 191, 209,
    133, 45, 232, 76, 64, 195, 80, 128, 155, 57, 36, 189, 197, 107, 19, 186, 173, 11, 3, 154, 32, 76, 113, 4, 94, 11, 240, 90, 128, 215, 187, 20, 119, 100, 79, 14, 138, 111, 225, 162,
    3, 90, 15, 17, 53, 25, 227, 51, 160, 101, 119, 88, 157, 66, 58, 109, 161, 48, 198, 161, 44, 111, 96, 147, 228, 22, 173, 121, 139, 112, 220, 167, 143, 67, 214, 2, 89, 179, 108, 1,
    125, 105, 201, 153, 19, 232, 26, 225, 99, 94, 128, 165, 182, 219, 239, 148, 149, 188, 43, 50, 145, 192, 13, 108, 21, 96, 35, 100, 3, 61, 48, 82, 81, 31, 128, 110, 9, 30, 244, 54,
    89, 161, 51, 183, 5, 174, 66, 215, 49, 82, 133, 216, 24, 99, 186, 252, 6, 112, 36, 122, 163, 139, 172, 101, 213, 82, 129, 157, 165, 136, 206, 117, 94, 60, 14, 184, 144, 110, 3, 63,
    155, 58, 140, 43, 90, 146, 102, 2, 100, 103, 116, 174, 125, 78, 81, 238, 72, 121, 58, 4, 169, 48, 108, 240, 166, 165, 218, 38, 244, 186, 40, 96, 75, 115, 104, 43, 97, 47, 4, 246,
    66, 96, 47, 118, 45, 57, 169, 87, 228, 169, 85, 144, 244, 45, 108, 210, 149, 2, 107, 48, 220, 210, 78, 251, 29, 187, 34, 210, 73, 105, 118, 133, 106, 105, 24, 205, 10, 16, 134, 132,
    88, 106, 217, 227, 176, 217, 61, 136, 13, 236, 169, 131, 172, 101, 45, 221, 182, 2, 28, 122, 84, 56, 96, 6, 167, 177, 99, 80, 9, 93, 121, 237, 77, 91, 204, 3, 104, 163, 128, 146,
    1, 11, 139, 199, 129, 231, 2, 27, 138, 10, 143, 96, 125, 209, 34, 186, 15, 192, 33, 49, 26, 98, 224, 186, 126, 132, 144, 125, 74, 213, 135, 229, 105, 1, 183, 2, 93, 67, 114, 181,
    215, 169, 251, 0, 112, 23, 168, 238, 48, 142, 0, 3, 91, 114, 46, 170, 196, 158, 195, 143, 25, 13, 21, 47, 186, 30, 212, 15, 51, 224, 156, 103, 198, 183, 100, 173, 8, 61, 183, 160,
    57, 232, 72, 142, 79, 17, 185, 79, 135, 87, 104, 23, 55, 147, 225, 5, 177, 89, 2, 155, 127, 64, 37, 220, 140, 135, 151, 131, 38, 14, 253, 182, 65, 235, 187, 195, 129, 83, 136, 17,
    215, 33, 211, 233, 41, 228, 63, 4, 82, 243, 109, 20, 245, 108, 48, 255, 182, 254, 14, 169, 172, 22, 114, 243, 221, 40, 43, 132, 83, 63, 143, 250, 136, 164, 62, 233, 196, 117, 245, 243,
    124, 128, 32, 153, 97, 86, 43, 194, 42, 71, 211, 228, 223, 235, 233, 188, 223, 235, 97, 228, 145, 255, 99, 217, 52, 135, 136, 246, 254, 190, 63, 24, 94, 150, 203, 203, 223, 35, 96, 251,
    253, 116, 86, 141, 202, 229, 251, 249, 56, 218, 25, 13, 49, 214, 31, 140, 78, 239, 102, 213, 42, 170, 37, 232, 101, 217, 175, 171, 18, 97, 244, 113, 157, 212, 243, 89, 93, 78, 182, 99,
    163, 106, 32, 37, 231, 187, 225, 113, 149, 172, 202, 197, 69, 181, 74, 22, 213, 242, 102, 134, 96, 127, 213, 199, 152, 170, 63, 7, 30, 195, 26, 137, 229, 228, 243, 165, 148, 252, 226, 230,
    252, 28, 1, 122, 53, 184, 31, 28, 7, 132, 182, 227, 142, 155, 249, 95, 100, 182, 143, 80, 46, 167, 147, 234, 171, 89, 117, 85, 205, 87, 253, 222, 205, 53, 177, 120, 81, 207, 110, 174,
    230, 61, 244, 170, 157, 135, 177, 220, 10, 113, 233, 114, 127, 238, 89, 93, 46, 14, 84, 60, 187, 89, 173, 234, 249, 38, 175, 124, 87, 78, 155, 17, 99, 223, 80, 222, 150, 151, 245, 187,
    77, 225, 235, 69, 125, 129, 174, 109, 161, 0, 236, 159, 155, 180, 111, 56, 13, 217, 239, 189, 1, 5, 86, 235, 169, 203, 48, 109, 217, 3, 29, 22, 239, 133, 98, 171, 81, 0, 208, 230,
    8, 250, 57, 156, 143, 38, 245, 248, 134, 64, 18, 144, 175, 129, 247, 197, 251, 63, 78, 250, 189, 122, 85, 190, 6, 243, 123, 131, 228, 182, 156, 221, 84, 144, 168, 131, 69, 23, 213, 89,
    93, 175, 94, 92, 86, 227, 31, 206, 234, 31, 255, 56, 191, 190, 89, 161, 218, 152, 207, 213, 4, 227, 136, 0, 251, 188, 90, 141, 47, 251, 255, 246, 252, 90, 166, 80, 209, 252, 243, 37,
    113, 254, 12, 227, 231, 106, 244, 15, 119, 243, 251, 79, 136, 29, 238, 86, 247, 159, 132, 22, 113, 95, 223, 255, 219, 224, 120, 122, 222, 255, 104, 145, 212, 63, 12, 86, 151, 139, 250, 93,
    244, 213, 98, 1, 25, 238, 189, 168, 111, 102, 147, 104, 94, 131, 108, 108, 167, 219, 113, 118, 122, 41, 98, 242, 207, 175, 95, 189, 92, 173, 174, 191, 174, 254, 122, 83, 45, 87, 199, 203,
    36, 176, 19, 178, 181, 166, 106, 71, 190, 0, 171, 106, 196, 248, 69, 125, 133, 158, 148, 103, 179, 70, 236, 86, 163, 215, 229, 234, 50, 89, 212, 55, 243, 9, 11, 161, 149, 106, 242, 28,
    178, 135, 190, 204, 254, 81, 43, 53, 56, 62, 72, 162, 53, 172, 47, 202, 5, 72, 179, 92, 189, 159, 85, 73, 152, 213, 93, 61, 235, 125, 220, 27, 126, 176, 226, 91, 50, 1, 85, 167,
    243, 121, 181, 120, 249, 205, 235, 87, 161, 226, 253, 253, 112, 137, 174, 80, 196, 223, 131, 12, 171, 10, 74, 59, 191, 88, 107, 91, 107, 82, 193, 141, 70, 75, 209, 132, 247, 111, 88, 236,
    147, 79, 250, 191, 2, 215, 30, 58, 249, 20, 100, 67, 205, 45, 170, 77, 189, 142, 2, 60, 144, 233, 7, 42, 128, 152, 152, 72, 179, 91, 55, 203, 207, 250, 29, 141, 88, 222, 140, 199,
    59, 10, 241, 38, 36, 189, 198, 95, 121, 1, 141, 8, 218, 28, 53, 201, 231, 55, 179, 13, 12, 254, 252, 190, 94, 188, 169, 22, 183, 213, 226, 107, 17, 181, 55, 104, 252, 107, 49, 30,
    253, 193, 224, 200, 61, 2, 185, 162, 244, 181, 225, 138, 56, 54, 90, 248, 23, 145, 173, 232, 188, 132, 126, 77, 90, 217, 176, 104, 75, 176, 129, 28, 88, 94, 215, 243, 101, 197, 233, 2,
    0, 250, 237, 154, 238, 133, 222, 68, 193, 58, 87, 147, 40, 32, 31, 113, 30, 34, 234, 61, 91, 119, 134, 166, 89, 148, 35, 204, 90, 128, 10, 87, 95, 150, 171, 242, 120, 150, 148, 215,
    215, 21, 228, 186, 119, 142, 246, 123, 195, 106, 88, 37, 92, 47, 25, 80, 188, 144, 209, 239, 253, 249, 79, 111, 190, 233, 13, 123, 45, 245, 13, 138, 68, 84, 146, 37, 171, 206, 246, 217,
    165, 128, 54, 13, 83, 239, 89, 211, 228, 253, 184, 164, 37, 40, 119, 204, 236, 135, 5, 226, 55, 35, 86, 153, 92, 5, 41, 129, 159, 218, 78, 86, 205, 105, 21, 197, 122, 209, 16, 52,
    243, 69, 68, 241, 197, 205, 114, 85, 95, 125, 62, 171, 22, 144, 142, 225, 218, 60, 156, 234, 65, 16, 141, 118, 118, 239, 79, 243, 217, 251, 168, 140, 150, 232, 241, 172, 226, 68, 98, 21,
    141, 203, 121, 116, 86, 69, 129, 92, 224, 76, 9, 95, 55, 31, 87, 9, 240, 250, 72, 15, 142, 122, 103, 211, 121, 239, 163, 81, 245, 173, 250, 78, 232, 147, 44, 175, 103, 83, 180, 132,
    252, 228, 186, 190, 238, 239, 129, 242, 169, 64, 233, 37, 172, 41, 48, 150, 187, 64, 146, 79, 67, 227, 253, 150, 91, 3, 0, 36, 170, 193, 253, 97, 67, 94, 207, 102, 103, 229, 248, 135,
    47, 196, 57, 1, 126, 57, 153, 124, 117, 139, 236, 87, 211, 229, 170, 130, 54, 247, 123, 227, 217, 116, 252, 67, 111, 184, 99, 95, 26, 151, 217, 37, 212, 223, 219, 137, 30, 7, 35, 189,
    199, 232, 175, 158, 106, 34, 87, 93, 19, 41, 22, 104, 245, 171, 45, 208, 215, 13, 57, 127, 185, 13, 2, 151, 26, 43, 116, 0, 250, 163, 210, 191, 129, 123, 72, 254, 87, 255, 9, 59,
    244, 193, 198, 63, 96, 137, 86, 45, 75, 52, 92, 29, 52, 46, 147, 122, 13, 8, 16, 86, 193, 192, 32, 106, 59, 236, 123, 66, 200, 240, 95, 83, 114, 31, 154, 186, 46, 148, 182, 168,
    189, 121, 251, 135, 3, 210, 38, 4, 224, 116, 243, 142, 165, 220, 145, 212, 191, 181, 154, 60, 81, 190, 143, 250, 135, 251, 248, 138, 54, 172, 169, 213, 123, 132, 231, 157, 74, 161, 120, 67,
    142, 110, 248, 241, 6, 210, 67, 23, 20, 100, 4, 23, 233, 111, 35, 193, 73, 244, 136, 192, 30, 181, 36, 246, 48, 30, 23, 245, 23, 109, 171, 57, 153, 46, 25, 53, 78, 70, 31, 233,
    167, 213, 49, 221, 74, 31, 210, 140, 215, 229, 252, 166, 156, 109, 200, 243, 20, 237, 152, 213, 23, 245, 205, 175, 210, 142, 191, 177, 180, 192, 16, 85, 171, 183, 211, 234, 93, 191, 145, 136,
    174, 38, 62, 240, 175, 175, 234, 139, 8, 61, 217, 88, 159, 199, 105, 21, 186, 253, 139, 44, 200, 238, 48, 230, 32, 169, 58, 68, 170, 199, 229, 236, 205, 170, 94, 64, 244, 0, 105, 245,
    199, 85, 117, 181, 110, 240, 251, 113, 211, 226, 35, 129, 243, 163, 35, 40, 14, 86, 201, 133, 201, 162, 190, 254, 28, 164, 60, 60, 16, 99, 137, 159, 234, 57, 7, 64, 155, 176, 134, 105,
    47, 167, 23, 151, 51, 110, 27, 33, 174, 235, 102, 146, 241, 172, 92, 46, 217, 45, 246, 113, 91, 57, 190, 92, 151, 238, 181, 214, 215, 152, 251, 151, 249, 229, 7, 26, 90, 84, 87, 245,
    109, 245, 161, 182, 218, 214, 137, 237, 28, 232, 78, 53, 216, 211, 50, 68, 100, 82, 205, 219, 173, 181, 205, 200, 83, 91, 147, 14, 63, 108, 234, 65, 248, 250, 72, 123, 155, 120, 85, 74,
    118, 236, 77, 213, 105, 113, 199, 78, 63, 214, 228, 178, 83, 244, 145, 54, 91, 14, 249, 177, 246, 170, 77, 177, 15, 181, 213, 248, 238, 15, 54, 22, 202, 237, 180, 182, 17, 132, 135, 186,
    50, 129, 70, 128, 111, 139, 174, 186, 84, 9, 84, 148, 5, 191, 172, 206, 75, 25, 115, 81, 47, 31, 107, 165, 190, 254, 80, 11, 141, 91, 171, 18, 238, 180, 250, 102, 81, 206, 151, 231,
    213, 34, 145, 224, 248, 184, 29, 218, 175, 62, 8, 11, 164, 159, 175, 136, 114, 71, 117, 62, 88, 41, 116, 243, 151, 213, 153, 85, 229, 109, 21, 42, 181, 148, 235, 9, 180, 248, 37, 53,
    246, 216, 171, 131, 76, 62, 95, 211, 137, 230, 135, 245, 250, 107, 235, 67, 165, 109, 182, 45, 28, 119, 52, 185, 109, 158, 171, 225, 138, 254, 235, 112, 251, 115, 68, 40, 231, 83, 12, 0,
    81, 123, 71, 204, 25, 138, 142, 208, 192, 103, 79, 170, 28, 166, 24, 118, 52, 122, 167, 64, 163, 121, 189, 193, 209, 175, 106, 114, 109, 114, 14, 181, 122, 216, 156, 127, 16, 81, 210, 13,
    13, 140, 193, 255, 197, 122, 47, 72, 139, 192, 193, 239, 53, 15, 163, 214, 126, 145, 150, 99, 253, 79, 117, 41, 192, 191, 31, 102, 149, 221, 177, 164, 29, 247, 123, 119, 24, 193, 223, 2,
    252, 206, 12, 44, 194, 138, 197, 251, 205, 6, 203, 63, 206, 207, 235, 126, 8, 63, 170, 125, 225, 71, 181, 47, 252, 104, 209, 103, 122, 222, 71, 236, 81, 117, 98, 15, 9, 61, 170, 245,
    0, 164, 9, 109, 100, 63, 198, 53, 247, 155, 246, 87, 151, 211, 157, 41, 154, 195, 51, 122, 208, 246, 37, 32, 133, 125, 9, 29, 25, 94, 37, 155, 0, 228, 109, 40, 52, 220, 31, 31,
    52, 77, 124, 223, 236, 18, 25, 62, 172, 56, 56, 80, 243, 170, 156, 206, 191, 191, 89, 204, 88, 135, 247, 127, 249, 250, 213, 161, 162, 8, 129, 182, 101, 229, 65, 10, 67, 16, 111, 86,
    151, 232, 77, 195, 170, 175, 230, 18, 125, 126, 214, 25, 57, 116, 163, 198, 163, 78, 192, 222, 205, 187, 191, 31, 86, 77, 20, 246, 135, 175, 118, 130, 176, 135, 124, 237, 113, 22, 165, 9,
    200, 246, 9, 193, 111, 207, 123, 73, 251, 45, 217, 127, 62, 93, 92, 189, 43, 23, 213, 247, 107, 38, 174, 80, 126, 71, 12, 214, 101, 214, 82, 112, 176, 177, 179, 155, 233, 108, 242, 61,
    103, 105, 246, 53, 35, 185, 95, 34, 243, 67, 13, 172, 160, 156, 7, 27, 160, 230, 130, 235, 235, 41, 158, 63, 215, 203, 229, 20, 28, 255, 236, 240, 60, 240, 131, 217, 160, 39, 141, 107,
    214, 181, 214, 136, 200, 252, 241, 168, 55, 174, 103, 245, 226, 232, 119, 74, 157, 159, 43, 117, 252, 88, 40, 188, 83, 127, 219, 145, 222, 255, 172, 104, 203, 127, 21, 194, 234, 215, 34, 124,
    126, 238, 241, 239, 87, 34, 252, 79, 144, 244, 251, 106, 182, 172, 34, 215, 22, 189, 207, 184, 63, 176, 158, 113, 9, 225, 162, 223, 219, 72, 252, 209, 131, 129, 40, 167, 76, 59, 242, 120,
    244, 212, 154, 221, 57, 151, 141, 204, 127, 80, 77, 63, 160, 157, 123, 70, 245, 27, 61, 213, 226, 251, 101, 125, 177, 61, 157, 97, 101, 97, 164, 58, 209, 234, 120, 112, 215, 206, 208, 158,
    25, 235, 21, 170, 249, 62, 61, 159, 55, 43, 128, 192, 165, 173, 222, 128, 165, 8, 76, 221, 15, 89, 66, 2, 211, 78, 254, 179, 103, 146, 179, 191, 159, 173, 177, 22, 122, 58, 95, 247,
    84, 38, 165, 165, 234, 122, 3, 224, 234, 9, 189, 111, 205, 105, 84, 18, 249, 4, 163, 242, 235, 6, 122, 178, 208, 181, 250, 228, 147, 143, 158, 48, 70, 248, 224, 156, 199, 231, 55, 171,
    122, 61, 225, 49, 93, 70, 107, 85, 72, 162, 63, 195, 167, 67, 34, 155, 172, 43, 153, 75, 152, 189, 143, 80, 250, 6, 201, 240, 9, 17, 57, 177, 182, 93, 73, 239, 145, 185, 168, 238,
    60, 77, 179, 50, 124, 120, 122, 249, 224, 52, 201, 35, 218, 121, 120, 154, 68, 29, 7, 185, 57, 56, 223, 212, 127, 196, 124, 255, 198, 51, 54, 195, 249, 35, 118, 244, 169, 28, 11, 89,
    92, 163, 5, 245, 231, 211, 229, 101, 53, 25, 98, 128, 38, 138, 13, 14, 46, 110, 230, 115, 110, 129, 124, 58, 67, 30, 179, 149, 79, 69, 106, 187, 202, 186, 168, 96, 124, 230, 213, 120,
    149, 68, 13, 166, 99, 201, 187, 196, 16, 166, 153, 142, 137, 234, 197, 3, 1, 138, 38, 117, 181, 148, 6, 206, 42, 41, 58, 174, 23, 104, 106, 53, 123, 255, 75, 122, 210, 218, 31, 188,
    157, 48, 186, 123, 55, 157, 79, 234, 119, 9, 3, 31, 230, 193, 86, 210, 90, 244, 219, 59, 144, 165, 33, 20, 125, 48, 25, 51, 157, 71, 237, 128, 233, 231, 159, 159, 56, 135, 243, 145,
    26, 12, 119, 35, 183, 39, 182, 181, 27, 239, 245, 116, 162, 18, 5, 35, 180, 141, 231, 158, 216, 210, 54, 254, 235, 61, 95, 175, 121, 15, 91, 161, 222, 19, 155, 105, 197, 134, 189, 231,
    242, 240, 216, 168, 230, 81, 219, 53, 234, 173, 22, 55, 85, 111, 52, 234, 64, 186, 56, 68, 198, 71, 192, 28, 14, 172, 247, 55, 189, 67, 213, 193, 112, 223, 56, 98, 216, 138, 43, 239,
    27, 177, 105, 205, 10, 140, 90, 247, 195, 38, 123, 35, 104, 163, 205, 221, 112, 83, 83, 246, 165, 4, 225, 58, 62, 121, 30, 94, 7, 56, 61, 145, 208, 225, 148, 111, 181, 221, 157, 215,
    243, 85, 124, 94, 94, 77, 103, 239, 143, 150, 229, 124, 25, 67, 145, 167, 231, 247, 103, 245, 228, 253, 29, 163, 133, 11, 217, 70, 16, 55, 81, 134, 46, 248, 239, 184, 121, 170, 82, 254,
    187, 79, 206, 65, 178, 106, 113, 119, 93, 47, 167, 20, 230, 163, 243, 233, 143, 112, 18, 179, 234, 124, 117, 164, 142, 207, 106, 216, 161, 43, 220, 200, 210, 252, 17, 87, 216, 143, 195, 187,
    97, 71, 38, 191, 254, 241, 120, 54, 229, 244, 91, 72, 176, 120, 126, 8, 212, 106, 254, 91, 3, 205, 11, 254, 59, 22, 188, 151, 211, 159, 170, 35, 45, 181, 234, 31, 227, 229, 101, 137,
    78, 31, 169, 72, 69, 104, 56, 66, 12, 167, 238, 101, 212, 241, 229, 244, 246, 14, 70, 240, 122, 86, 190, 63, 58, 159, 85, 63, 30, 95, 149, 11, 200, 80, 188, 170, 175, 143, 44, 198,
    122, 235, 231, 6, 85, 199, 36, 150, 139, 39, 83, 90, 0, 118, 105, 44, 202, 126, 92, 206, 166, 23, 243, 120, 10, 126, 46, 143, 198, 50, 251, 114, 159, 92, 202, 46, 160, 175, 235, 119,
    119, 103, 245, 2, 119, 235, 102, 52, 112, 64, 12, 52, 157, 68, 13, 161, 244, 120, 13, 72, 72, 163, 253, 245, 6, 147, 133, 116, 159, 41, 247, 97, 191, 198, 226, 139, 250, 71, 12, 8,
    198, 63, 220, 201, 203, 129, 71, 38, 49, 126, 77, 54, 175, 80, 49, 80, 211, 169, 109, 27, 13, 88, 223, 106, 150, 29, 116, 25, 27, 5, 125, 182, 252, 129, 249, 129, 29, 186, 173, 142,
    235, 235, 114, 60, 93, 189, 63, 82, 129, 89, 90, 177, 232, 18, 182, 78, 48, 220, 86, 40, 207, 208, 145, 155, 85, 245, 144, 57, 151, 203, 89, 95, 103, 54, 74, 213, 199, 145, 49, 31,
    15, 214, 92, 46, 128, 196, 26, 93, 220, 174, 100, 158, 171, 94, 92, 29, 45, 127, 128, 69, 84, 147, 234, 98, 24, 27, 143, 11, 34, 43, 32, 169, 29, 37, 97, 7, 7, 33, 202, 47,
    69, 194, 217, 95, 132, 196, 94, 28, 226, 98, 131, 3, 50, 126, 41, 6, 214, 111, 48, 48, 106, 139, 129, 220, 47, 106, 14, 242, 142, 28, 161, 238, 226, 19, 155, 134, 44, 188, 12, 132,
    101, 177, 190, 43, 231, 211, 171, 50, 104, 213, 162, 190, 18, 190, 68, 110, 25, 77, 231, 116, 189, 171, 42, 20, 51, 187, 197, 132, 116, 237, 114, 199, 155, 2, 241, 164, 162, 30, 232, 101,
    168, 106, 63, 4, 225, 65, 77, 211, 212, 116, 191, 28, 168, 93, 222, 255, 183, 31, 170, 247, 231, 139, 242, 10, 190, 118, 3, 238, 78, 125, 124, 247, 83, 12, 147, 85, 253, 8, 50, 181,
    164, 82, 40, 52, 35, 197, 98, 146, 47, 138, 83, 48, 198, 180, 74, 235, 109, 105, 221, 42, 13, 19, 112, 239, 90, 197, 138, 78, 30, 248, 124, 159, 182, 114, 243, 78, 46, 76, 199, 125,
    222, 202, 205, 14, 64, 208, 6, 5, 105, 205, 54, 37, 125, 39, 223, 146, 223, 155, 174, 220, 63, 232, 120, 144, 238, 15, 247, 252, 191, 124, 199, 27, 131, 214, 140, 67, 222, 254, 225, 174,
    209, 13, 219, 86, 201, 56, 188, 145, 214, 24, 213, 173, 224, 28, 5, 141, 113, 145, 89, 70, 244, 20, 124, 221, 101, 45, 93, 45, 35, 23, 235, 173, 229, 12, 128, 94, 76, 23, 227, 89,
    117, 199, 55, 228, 142, 230, 24, 123, 29, 195, 237, 214, 63, 84, 71, 191, 51, 254, 76, 21, 103, 205, 99, 120, 17, 27, 93, 109, 30, 39, 37, 156, 8, 55, 96, 30, 105, 110, 235, 106,
    39, 215, 231, 231, 240, 174, 71, 155, 52, 98, 51, 46, 175, 143, 196, 12, 180, 16, 102, 89, 23, 233, 196, 47, 35, 142, 95, 64, 162, 152, 235, 128, 27, 133, 109, 201, 65, 211, 183, 59,
    33, 230, 214, 26, 132, 228, 190, 77, 131, 33, 104, 215, 144, 198, 41, 52, 79, 199, 247, 222, 239, 43, 94, 168, 3, 229, 99, 235, 215, 236, 221, 147, 169, 13, 115, 239, 147, 246, 94, 131,
    187, 182, 179, 121, 232, 143, 88, 99, 87, 146, 130, 57, 109, 18, 35, 5, 223, 182, 33, 214, 176, 113, 212, 221, 212, 8, 67, 191, 250, 29, 252, 49, 34, 152, 138, 86, 111, 189, 112, 215,
    8, 147, 117, 45, 75, 171, 229, 33, 56, 99, 241, 194, 236, 65, 181, 113, 195, 214, 54, 121, 241, 162, 156, 76, 111, 150, 226, 114, 90, 241, 68, 146, 103, 158, 17, 64, 59, 48, 209, 64,
    134, 105, 156, 58, 137, 37, 8, 88, 75, 106, 171, 63, 77, 171, 226, 17, 34, 147, 169, 171, 6, 125, 174, 68, 140, 111, 22, 75, 248, 137, 235, 122, 26, 130, 134, 53, 254, 71, 151, 92,
    142, 185, 107, 87, 93, 199, 85, 103, 249, 182, 216, 118, 125, 114, 167, 168, 85, 103, 174, 76, 183, 5, 25, 127, 54, 12, 17, 102, 116, 115, 190, 156, 94, 221, 53, 21, 179, 138, 255, 238,
    147, 16, 216, 188, 148, 24, 166, 27, 36, 237, 68, 64, 139, 250, 221, 241, 191, 223, 44, 87, 211, 243, 247, 113, 115, 32, 193, 70, 91, 31, 68, 69, 237, 240, 204, 236, 4, 121, 58, 165,
    226, 147, 144, 91, 145, 191, 185, 190, 174, 22, 99, 16, 235, 24, 99, 251, 5, 98, 208, 25, 160, 6, 189, 109, 73, 151, 40, 121, 27, 225, 86, 111, 67, 1, 255, 64, 252, 16, 253, 172,
    35, 199, 51, 197, 127, 221, 22, 104, 143, 30, 198, 69, 77, 133, 198, 84, 180, 0, 164, 187, 24, 160, 254, 235, 23, 127, 185, 235, 134, 113, 102, 79, 169, 63, 192, 116, 117, 139, 229, 219,
    82, 29, 41, 110, 9, 110, 39, 124, 220, 47, 183, 45, 228, 254, 54, 154, 22, 48, 124, 17, 56, 254, 168, 132, 52, 49, 114, 155, 215, 73, 122, 124, 128, 61, 15, 66, 224, 134, 95, 249,
    38, 182, 181, 202, 111, 41, 212, 192, 255, 106, 206, 121, 184, 95, 42, 166, 75, 116, 191, 138, 207, 170, 213, 187, 170, 218, 23, 195, 31, 191, 187, 196, 99, 44, 197, 32, 116, 239, 22, 229,
    117, 16, 80, 234, 230, 57, 200, 113, 52, 158, 77, 175, 143, 55, 79, 97, 65, 126, 7, 53, 217, 248, 124, 215, 17, 181, 117, 28, 42, 1, 123, 203, 116, 8, 255, 143, 175, 203, 9, 55,
    251, 52, 210, 0, 111, 120, 31, 196, 254, 174, 99, 5, 90, 177, 38, 4, 210, 241, 223, 186, 230, 17, 252, 185, 120, 227, 61, 34, 99, 115, 254, 219, 17, 152, 180, 99, 231, 66, 188, 219,
    98, 150, 68, 168, 220, 94, 91, 46, 248, 254, 176, 168, 95, 131, 211, 94, 51, 165, 84, 122, 118, 126, 126, 159, 236, 25, 111, 111, 88, 36, 109, 36, 171, 250, 226, 98, 86, 189, 121, 55,
    229, 212, 101, 135, 123, 123, 152, 113, 192, 200, 60, 212, 210, 70, 76, 90, 81, 190, 209, 251, 7, 144, 133, 211, 126, 151, 24, 162, 45, 93, 179, 220, 82, 153, 120, 114, 179, 8, 254, 92,
    37, 218, 47, 187, 93, 56, 58, 42, 207, 57, 224, 93, 99, 216, 235, 29, 63, 28, 35, 52, 40, 165, 27, 121, 78, 215, 195, 139, 253, 163, 220, 53, 187, 59, 72, 194, 119, 31, 64, 202,
    44, 219, 99, 94, 244, 37, 130, 32, 68, 153, 140, 123, 115, 254, 115, 102, 45, 22, 126, 215, 146, 236, 101, 217, 81, 51, 65, 242, 108, 111, 87, 183, 166, 122, 19, 234, 253, 51, 70, 60,
    215, 63, 14, 14, 19, 237, 96, 39, 127, 1, 252, 61, 115, 16, 65, 236, 30, 227, 85, 88, 68, 104, 162, 147, 131, 3, 127, 241, 250, 79, 30, 229, 183, 55, 66, 110, 218, 156, 206, 69,
    127, 158, 210, 52, 237, 210, 30, 97, 191, 40, 175, 155, 97, 127, 64, 90, 54, 193, 60, 193, 173, 73, 149, 73, 181, 42, 167, 51, 41, 189, 163, 214, 93, 51, 212, 106, 234, 64, 75, 205,
    172, 116, 8, 157, 191, 252, 141, 154, 221, 88, 184, 246, 192, 190, 61, 119, 250, 63, 218, 80, 15, 50, 74, 63, 196, 240, 112, 89, 113, 170, 237, 9, 240, 110, 209, 142, 49, 157, 248, 243,
    106, 188, 153, 203, 114, 144, 204, 179, 93, 131, 208, 24, 240, 118, 116, 233, 30, 246, 204, 175, 237, 234, 187, 80, 36, 83, 106, 215, 206, 54, 170, 168, 118, 93, 56, 109, 193, 30, 177, 232,
    76, 103, 81, 127, 9, 67, 102, 180, 240, 95, 97, 218, 190, 29, 254, 186, 229, 193, 119, 197, 176, 75, 140, 181, 25, 127, 160, 83, 110, 146, 27, 154, 242, 118, 225, 211, 229, 237, 197, 58,
    48, 217, 76, 159, 4, 152, 27, 107, 208, 64, 158, 227, 182, 156, 29, 135, 169, 42, 157, 216, 125, 80, 35, 54, 183, 215, 140, 196, 32, 194, 96, 167, 74, 57, 166, 137, 111, 149, 151, 182,
    251, 73, 145, 14, 246, 152, 21, 165, 156, 167, 89, 233, 52, 177, 94, 246, 216, 211, 221, 198, 59, 54, 79, 69, 201, 127, 109, 154, 75, 224, 217, 200, 64, 44, 219, 183, 150, 141, 39, 235,
    46, 221, 254, 38, 194, 229, 119, 133, 235, 255, 21, 81, 218, 132, 146, 187, 221, 254, 160, 24, 117, 139, 139, 32, 61, 116, 144, 205, 12, 166, 57, 44, 90, 15, 37, 203, 236, 71, 37, 250,
    29, 64, 124, 31, 198, 205, 15, 7, 210, 177, 206, 155, 41, 181, 157, 186, 191, 78, 200, 118, 26, 249, 59, 136, 89, 219, 31, 132, 8, 66, 52, 187, 253, 38, 193, 255, 63, 146, 216, 234,
    244, 135, 229, 176, 85, 248, 113, 41, 36, 202, 107, 33, 211, 110, 7, 204, 175, 148, 147, 118, 19, 127, 27, 41, 105, 65, 120, 32, 35, 222, 134, 41, 177, 237, 238, 167, 61, 3, 93, 12,
    103, 202, 213, 222, 241, 136, 132, 199, 235, 41, 156, 180, 21, 98, 239, 143, 94, 207, 207, 207, 213, 70, 198, 198, 252, 183, 150, 14, 65, 127, 119, 250, 163, 141, 86, 195, 197, 245, 188, 132,
    63, 63, 175, 202, 157, 18, 13, 3, 154, 34, 126, 60, 78, 207, 210, 251, 223, 133, 34, 251, 71, 240, 50, 41, 104, 54, 19, 250, 156, 249, 108, 202, 11, 161, 14, 84, 144, 121, 255, 214,
    203, 161, 28, 218, 149, 136, 240, 22, 123, 35, 190, 61, 17, 222, 58, 156, 219, 27, 66, 174, 27, 190, 219, 25, 210, 121, 179, 27, 246, 203, 200, 126, 61, 202, 83, 155, 121, 173, 237, 186,
    143, 201, 84, 27, 213, 88, 94, 125, 190, 107, 41, 144, 20, 131, 10, 229, 91, 27, 186, 7, 68, 7, 17, 159, 90, 88, 134, 135, 176, 212, 22, 142, 140, 113, 127, 131, 192, 176, 233, 132,
    4, 118, 59, 251, 48, 239, 110, 167, 203, 233, 217, 116, 70, 117, 15, 227, 236, 227, 157, 117, 69, 54, 187, 161, 137, 125, 176, 132, 184, 157, 64, 200, 49, 120, 106, 247, 112, 60, 182, 206,
    249, 61, 115, 120, 91, 25, 222, 181, 112, 109, 3, 40, 211, 111, 124, 221, 191, 59, 73, 223, 157, 97, 49, 126, 51, 237, 55, 157, 15, 183, 125, 137, 90, 201, 161, 208, 14, 63, 178, 61,
    180, 72, 184, 201, 177, 77, 16, 185, 157, 117, 236, 225, 254, 77, 191, 93, 17, 211, 99, 107, 224, 57, 3, 57, 59, 67, 243, 214, 60, 253, 201, 243, 176, 42, 124, 242, 60, 156, 111, 202,
    21, 224, 211, 147, 201, 244, 54, 146, 125, 177, 163, 102, 33, 245, 244, 100, 123, 22, 232, 225, 163, 64, 163, 102, 177, 123, 4, 107, 218, 156, 10, 42, 147, 91, 235, 83, 65, 83, 104, 90,
    196, 51, 82, 191, 168, 127, 28, 245, 184, 98, 107, 50, 93, 192, 43, 164, 86, 245, 78, 79, 154, 115, 61, 123, 175, 83, 212, 138, 178, 204, 150, 186, 112, 17, 255, 80, 84, 197, 72, 179,
    70, 141, 83, 19, 249, 44, 74, 21, 127, 51, 239, 229, 162, 216, 86, 166, 82, 174, 1, 91, 133, 204, 210, 179, 217, 130, 201, 74, 71, 104, 68, 121, 59, 142, 181, 245, 145, 156, 226, 135,
    34, 89, 204, 147, 57, 113, 41, 20, 218, 143, 115, 197, 83, 6, 45, 174, 38, 202, 243, 244, 54, 179, 106, 102, 108, 228, 124, 7, 7, 34, 16, 57, 53, 246, 89, 156, 218, 136, 191, 132,
    31, 103, 170, 120, 107, 80, 227, 210, 43, 59, 206, 148, 37, 26, 60, 155, 48, 7, 92, 203, 35, 13, 85, 89, 0, 151, 34, 224, 163, 98, 205, 19, 255, 50, 75, 140, 50, 23, 227, 127,
    237, 108, 156, 233, 184, 48, 42, 206, 252, 12, 237, 169, 216, 198, 142, 71, 133, 94, 101, 6, 216, 106, 53, 142, 209, 47, 157, 198, 94, 71, 22, 96, 137, 249, 44, 230, 73, 162, 142, 189,
    3, 3, 198, 54, 210, 32, 91, 140, 139, 65, 122, 102, 34, 237, 140, 6, 230, 192, 83, 219, 168, 48, 89, 148, 187, 60, 42, 208, 140, 51, 236, 177, 214, 121, 204, 115, 41, 83, 203, 131,
    153, 98, 163, 92, 153, 162, 0, 255, 72, 180, 216, 129, 26, 78, 23, 99, 228, 196, 190, 136, 141, 142, 115, 23, 27, 15, 60, 139, 25, 176, 75, 125, 118, 105, 44, 200, 147, 231, 64, 140,
    63, 66, 32, 195, 230, 212, 88, 155, 44, 118, 5, 81, 136, 141, 101, 106, 108, 181, 34, 56, 52, 0, 36, 241, 107, 114, 92, 114, 246, 193, 198, 246, 54, 182, 206, 140, 21, 207, 116, 66,
    211, 182, 80, 113, 202, 19, 30, 93, 204, 131, 45, 149, 80, 41, 101, 45, 252, 169, 43, 237, 144, 111, 137, 23, 232, 18, 3, 93, 203, 220, 200, 27, 33, 136, 181, 36, 129, 206, 252, 56,
    6, 97, 44, 216, 157, 226, 98, 145, 198, 51, 47, 61, 10, 146, 160, 46, 227, 169, 177, 144, 25, 146, 5, 87, 10, 28, 73, 98, 136, 157, 78, 29, 15, 105, 9, 36, 177, 58, 226, 95,
    32, 137, 5, 60, 159, 146, 109, 196, 135, 231, 83, 242, 175, 32, 195, 110, 33, 17, 126, 102, 28, 16, 30, 91, 229, 1, 213, 162, 8, 106, 242, 2, 134, 179, 121, 111, 98, 146, 39, 55,
    232, 40, 36, 32, 183, 47, 181, 183, 153, 34, 57, 109, 234, 198, 228, 185, 38, 30, 182, 72, 73, 108, 7, 210, 160, 138, 101, 125, 92, 52, 120, 0, 58, 94, 197, 150, 189, 200, 4, 15,
    199, 254, 128, 214, 16, 105, 74, 139, 117, 17, 36, 210, 164, 10, 98, 153, 131, 151, 232, 49, 207, 242, 116, 148, 29, 173, 32, 106, 64, 92, 78, 167, 228, 217, 164, 62, 230, 177, 176, 54,
    133, 64, 151, 121, 166, 35, 254, 73, 55, 65, 96, 112, 201, 128, 158, 144, 16, 243, 18, 130, 226, 200, 81, 237, 35, 54, 67, 113, 4, 101, 181, 165, 76, 64, 227, 226, 12, 52, 206, 180,
    135, 118, 101, 169, 28, 146, 198, 245, 162, 252, 10, 72, 67, 245, 44, 36, 215, 81, 66, 128, 62, 85, 211, 27, 27, 23, 214, 80, 49, 88, 31, 87, 116, 137, 50, 139, 71, 54, 107, 41,
    159, 40, 14, 158, 24, 254, 25, 15, 121, 215, 145, 71, 82, 6, 170, 69, 36, 182, 252, 166, 212, 121, 192, 53, 17, 160, 167, 108, 80, 197, 69, 170, 75, 30, 26, 203, 63, 81, 252, 148,
    102, 35, 247, 64, 222, 10, 148, 156, 101, 228, 98, 164, 186, 8, 63, 242, 140, 97, 79, 29, 149, 242, 42, 245, 34, 88, 165, 225, 121, 192, 248, 11, 26, 107, 82, 82, 16, 125, 1, 157,
    32, 150, 180, 49, 208, 61, 210, 35, 43, 102, 142, 232, 169, 192, 167, 200, 230, 40, 70, 202, 120, 149, 225, 138, 146, 14, 178, 0, 92, 156, 167, 106, 146, 134, 78, 176, 161, 182, 186, 34,
    43, 209, 103, 67, 70, 241, 87, 176, 230, 153, 168, 32, 227, 152, 118, 1, 15, 57, 74, 229, 176, 68, 84, 44, 158, 196, 235, 115, 104, 7, 161, 243, 200, 219, 148, 57, 138, 103, 84, 241,
    32, 99, 158, 107, 39, 157, 49, 57, 64, 64, 22, 53, 243, 114, 201, 241, 192, 2, 10, 104, 81, 48, 39, 227, 217, 19, 96, 104, 33, 48, 57, 37, 21, 100, 205, 45, 107, 208, 44, 228,
    113, 102, 13, 197, 150, 6, 137, 205, 138, 253, 141, 121, 20, 47, 21, 132, 242, 3, 30, 228, 233, 21, 200, 75, 245, 73, 105, 160, 32, 125, 48, 98, 105, 225, 129, 155, 145, 107, 166, 201,
    8, 176, 16, 228, 43, 0, 198, 71, 197, 37, 126, 97, 225, 98, 90, 191, 28, 70, 2, 166, 197, 3, 233, 44, 103, 111, 128, 121, 90, 168, 94, 56, 225, 244, 119, 102, 124, 230, 74, 39,
    15, 241, 226, 102, 86, 141, 24, 6, 215, 147, 73, 244, 188, 229, 43, 12, 37, 198, 23, 69, 169, 61, 160, 130, 184, 225, 34, 130, 44, 71, 170, 146, 250, 38, 231, 49, 201, 242, 27, 20,
    185, 200, 34, 147, 195, 130, 130, 89, 144, 49, 69, 141, 134, 125, 166, 169, 230, 33, 182, 121, 204, 211, 107, 189, 159, 121, 239, 196, 228, 131, 217, 96, 24, 85, 6, 210, 50, 70, 89, 226,
    202, 94, 197, 244, 12, 80, 90, 88, 30, 83, 234, 20, 170, 2, 225, 12, 23, 49, 135, 104, 32, 166, 211, 210, 112, 3, 104, 58, 203, 192, 76, 200, 65, 70, 237, 134, 41, 215, 20, 63,
    112, 19, 108, 201, 209, 117, 144, 221, 41, 85, 102, 134, 134, 105, 237, 43, 80, 44, 243, 87, 16, 51, 158, 245, 171, 179, 23, 60, 212, 42, 139, 10, 69, 171, 43, 232, 167, 212, 238, 2,
    65, 14, 216, 96, 179, 113, 14, 211, 95, 240, 8, 104, 139, 10, 30, 14, 210, 100, 144, 247, 148, 242, 170, 192, 82, 131, 31, 159, 167, 180, 187, 20, 13, 72, 134, 49, 169, 190, 210, 69,
    65, 87, 86, 210, 95, 240, 79, 96, 83, 100, 148, 27, 67, 198, 128, 119, 17, 101, 52, 172, 144, 166, 204, 94, 66, 219, 210, 25, 236, 179, 177, 37, 53, 73, 180, 137, 53, 96, 166, 124,
    6, 81, 200, 232, 53, 82, 154, 80, 30, 180, 5, 39, 160, 46, 121, 224, 157, 155, 137, 87, 179, 87, 150, 199, 217, 22, 37, 44, 58, 195, 162, 166, 167, 52, 208, 138, 199, 100, 59, 67,
    179, 22, 46, 141, 250, 25, 218, 131, 156, 146, 236, 229, 79, 168, 171, 169, 31, 33, 36, 160, 73, 241, 158, 219, 16, 72, 127, 200, 18, 213, 53, 6, 251, 40, 175, 80, 168, 136, 34, 14,
    11, 8, 211, 14, 211, 235, 40, 214, 16, 181, 140, 23, 234, 59, 138, 66, 99, 64, 25, 218, 101, 232, 41, 184, 86, 192, 87, 66, 204, 105, 133, 10, 182, 97, 160, 56, 48, 193, 192, 30,
    30, 213, 23, 240, 170, 60, 234, 27, 204, 76, 161, 73, 60, 93, 16, 228, 211, 4, 135, 20, 30, 157, 12, 235, 77, 255, 71, 131, 76, 223, 199, 158, 22, 36, 4, 64, 139, 243, 48, 116,
    136, 24, 53, 226, 206, 129, 255, 202, 235, 152, 161, 4, 104, 234, 120, 130, 50, 50, 113, 77, 161, 97, 112, 231, 172, 156, 231, 144, 82, 195, 152, 135, 90, 29, 81, 94, 128, 184, 245, 57,
    99, 29, 45, 74, 32, 151, 134, 150, 146, 224, 95, 128, 114, 32, 26, 76, 49, 112, 37, 81, 85, 177, 190, 243, 58, 187, 181, 169, 153, 1, 113, 18, 15, 229, 179, 116, 172, 209, 249, 140,
    198, 12, 18, 230, 68, 19, 172, 206, 102, 228, 170, 167, 122, 120, 186, 116, 24, 114, 83, 242, 176, 57, 74, 148, 109, 88, 4, 61, 131, 79, 71, 169, 204, 164, 153, 56, 86, 185, 4, 54,
    65, 57, 232, 122, 198, 112, 61, 224, 8, 218, 113, 121, 156, 107, 138, 54, 61, 24, 2, 177, 16, 122, 177, 1, 152, 64, 200, 58, 93, 52, 77, 138, 150, 67, 168, 97, 46, 53, 77, 32,
    202, 34, 76, 242, 80, 68, 3, 41, 202, 144, 146, 195, 123, 25, 20, 135, 161, 206, 228, 38, 102, 124, 3, 10, 131, 210, 169, 196, 85, 154, 46, 73, 14, 146, 214, 238, 181, 21, 67, 109,
    29, 20, 31, 94, 1, 36, 85, 37, 2, 1, 5, 14, 53, 151, 64, 59, 104, 25, 152, 10, 127, 12, 239, 28, 17, 57, 94, 128, 42, 84, 219, 231, 51, 147, 243, 44, 235, 116, 76, 70,
    27, 203, 128, 3, 66, 8, 173, 240, 154, 2, 9, 29, 135, 106, 131, 243, 48, 215, 44, 72, 110, 41, 245, 57, 250, 135, 190, 68, 205, 69, 172, 188, 205, 97, 153, 140, 130, 83, 241, 208,
    79, 88, 127, 240, 43, 229, 33, 108, 12, 135, 161, 65, 30, 222, 151, 209, 41, 165, 2, 30, 88, 68, 194, 73, 236, 4, 49, 165, 170, 193, 98, 122, 90, 30, 57, 139, 90, 162, 52, 88,
    213, 216, 164, 4, 147, 95, 241, 132, 57, 182, 159, 75, 160, 196, 162, 140, 194, 16, 135, 208, 140, 115, 203, 154, 68, 84, 49, 79, 167, 135, 124, 205, 168, 218, 150, 29, 66, 127, 198, 148,
    116, 138, 13, 61, 45, 101, 140, 71, 117, 67, 10, 24, 146, 190, 53, 185, 73, 199, 20, 95, 212, 36, 223, 168, 80, 226, 68, 17, 171, 228, 18, 172, 209, 136, 59, 17, 116, 155, 191, 118,
    180, 90, 153, 131, 177, 7, 76, 68, 100, 158, 182, 78, 232, 32, 32, 105, 176, 25, 29, 32, 210, 66, 0, 205, 211, 199, 229, 55, 196, 218, 20, 157, 204, 140, 97, 151, 34, 154, 91, 10,
    45, 117, 211, 32, 232, 132, 142, 123, 33, 183, 246, 77, 140, 15, 145, 133, 204, 64, 200, 68, 57, 128, 56, 172, 21, 101, 6, 182, 12, 79, 134, 39, 194, 163, 113, 40, 19, 163, 122, 92,
    128, 41, 68, 131, 154, 2, 231, 67, 245, 102, 137, 180, 52, 105, 202, 67, 248, 229, 55, 184, 10, 24, 101, 140, 187, 199, 8, 206, 97, 15, 233, 178, 200, 153, 12, 236, 35, 31, 33, 115,
    248, 101, 188, 6, 194, 81, 65, 34, 31, 152, 147, 173, 153, 195, 72, 30, 16, 120, 68, 34, 126, 157, 201, 110, 17, 67, 64, 0, 243, 134, 88, 208, 12, 53, 14, 118, 146, 78, 133, 68,
    212, 60, 149, 92, 49, 86, 166, 240, 34, 76, 74, 141, 232, 138, 28, 126, 78, 227, 137, 120, 12, 194, 194, 176, 61, 42, 82, 168, 162, 65, 32, 21, 126, 131, 217, 230, 7, 16, 196, 60,
    26, 14, 70, 154, 139, 100, 241, 48, 113, 184, 24, 24, 37, 70, 71, 252, 9, 67, 43, 203, 175, 9, 248, 177, 196, 10, 60, 110, 31, 4, 227, 1, 254, 212, 52, 8, 5, 205, 3, 156,
    75, 36, 84, 5, 187, 75, 207, 51, 49, 163, 240, 27, 2, 45, 171, 36, 146, 0, 89, 53, 45, 124, 184, 52, 140, 97, 56, 111, 242, 177, 97, 136, 136, 168, 136, 35, 25, 6, 25, 40,
    237, 36, 136, 55, 226, 130, 98, 158, 240, 110, 24, 122, 227, 22, 118, 48, 162, 127, 162, 29, 40, 214, 241, 64, 53, 225, 191, 253, 241, 0, 135, 159, 97, 220, 58, 157, 140, 218, 251, 148,
    154, 113, 108, 59, 233, 244, 132, 211, 121, 155, 210, 235, 173, 50, 77, 201, 245, 35, 98, 140, 157, 20, 78, 129, 156, 126, 185, 40, 47, 162, 114, 62, 145, 35, 7, 48, 176, 93, 84, 39,
    103, 11, 12, 143, 175, 203, 249, 158, 226, 95, 78, 175, 78, 235, 5, 75, 200, 235, 202, 124, 141, 37, 44, 173, 71, 125, 30, 143, 52, 144, 227, 145, 128, 60, 106, 163, 15, 215, 167, 39,
    83, 46, 138, 134, 147, 219, 229, 116, 38, 224, 183, 121, 233, 185, 105, 63, 12, 232, 163, 18, 67, 254, 235, 213, 72, 142, 89, 26, 70, 252, 77, 46, 126, 234, 241, 236, 166, 240, 194, 97,
    251, 173, 114, 121, 207, 124, 0, 8, 19, 14, 229, 159, 135, 238, 135, 135, 134, 8, 221, 227, 173, 26, 72, 189, 246, 146, 106, 212, 28, 72, 208, 158, 29, 232, 110, 90, 110, 231, 244, 206,
    234, 31, 35, 217, 203, 218, 169, 176, 217, 101, 220, 6, 223, 202, 146, 89, 200, 3, 121, 171, 250, 122, 211, 131, 157, 252, 13, 52, 243, 119, 133, 102, 255, 174, 208, 220, 223, 14, 90, 248,
    189, 110, 11, 130, 44, 73, 175, 37, 122, 179, 52, 28, 132, 116, 219, 220, 190, 89, 211, 125, 249, 15, 228, 12, 21, 118, 138, 132, 217, 204, 40, 188, 223, 216, 204, 65, 126, 252, 8, 130,
    50, 43, 185, 211, 198, 102, 166, 242, 84, 125, 44, 152, 238, 146, 20, 245, 59, 107, 209, 143, 11, 58, 167, 180, 118, 107, 188, 121, 251, 135, 39, 204, 131, 181, 231, 184, 188, 69, 112, 96,
    179, 94, 51, 35, 150, 182, 39, 196, 120, 223, 154, 52, 107, 198, 53, 193, 220, 169, 243, 113, 97, 207, 162, 176, 31, 115, 196, 121, 187, 61, 166, 143, 67, 32, 134, 164, 137, 98, 64, 195,
    47, 141, 68, 47, 34, 126, 167, 34, 67, 212, 110, 125, 82, 104, 63, 140, 16, 90, 37, 244, 123, 24, 31, 160, 132, 30, 50, 2, 76, 48, 206, 141, 92, 145, 38, 26, 99, 161, 23, 176,
    250, 40, 107, 25, 23, 152, 196, 23, 118, 136, 129, 186, 79, 178, 162, 136, 92, 158, 38, 38, 119, 72, 176, 105, 146, 49, 60, 207, 243, 4, 195, 125, 212, 65, 167, 228, 59, 47, 8, 9,
    146, 44, 20, 201, 146, 148, 120, 100, 184, 22, 158, 9, 121, 162, 249, 165, 26, 36, 56, 149, 74, 157, 34, 177, 12, 216, 50, 193, 96, 40, 9, 48, 251, 28, 214, 74, 121, 222, 52, 109,
    115, 58, 163, 73, 78, 147, 162, 16, 23, 197, 207, 205, 52, 9, 57, 19, 184, 69, 83, 73, 121, 164, 208, 87, 17, 5, 75, 252, 249, 189, 15, 14, 225, 85, 129, 162, 108, 196, 240, 171,
    55, 156, 17, 211, 32, 150, 67, 29, 135, 158, 168, 20, 67, 3, 151, 20, 38, 29, 130, 60, 6, 69, 85, 196, 143, 138, 100, 186, 24, 238, 208, 21, 116, 70, 87, 188, 77, 210, 84, 163,
    118, 166, 18, 208, 6, 67, 220, 4, 142, 15, 52, 230, 55, 74, 60, 201, 227, 19, 56, 248, 33, 99, 156, 196, 49, 222, 210, 169, 124, 201, 6, 52, 6, 53, 60, 35, 69, 7, 10, 166,
    106, 24, 57, 2, 116, 160, 113, 102, 18, 157, 161, 142, 3, 37, 25, 193, 34, 108, 0, 69, 11, 226, 88, 100, 252, 94, 10, 35, 207, 164, 72, 65, 47, 139, 34, 94, 49, 140, 35, 191,
    134, 109, 156, 94, 211, 235, 35, 19, 245, 45, 174, 5, 235, 195, 177, 38, 50, 124, 72, 249, 113, 19, 192, 196, 56, 38, 81, 8, 104, 173, 210, 73, 145, 25, 38, 240, 75, 63, 105, 72,
    0, 77, 95, 112, 66, 41, 41, 16, 234, 75, 74, 193, 34, 236, 10, 163, 213, 28, 25, 14, 141, 104, 200, 141, 145, 161, 37, 240, 196, 245, 21, 34, 98, 16, 145, 163, 106, 176, 211, 43,
    14, 19, 88, 66, 147, 127, 184, 166, 44, 129, 86, 189, 10, 194, 161, 248, 53, 166, 12, 212, 87, 28, 95, 51, 93, 163, 68, 192, 4, 168, 73, 14, 34, 100, 93, 240, 75, 43, 2, 150,
    37, 95, 113, 164, 13, 162, 231, 2, 95, 190, 237, 84, 24, 201, 1, 241, 80, 147, 52, 182, 185, 78, 48, 44, 6, 62, 89, 130, 150, 65, 175, 204, 10, 147, 181, 151, 126, 51, 1, 4,
    100, 172, 142, 4, 142, 102, 95, 112, 130, 9, 253, 245, 33, 37, 39, 141, 217, 9, 198, 151, 16, 21, 4, 191, 195, 7, 116, 125, 29, 169, 68, 194, 157, 52, 151, 244, 23, 242, 204, 136,
    25, 90, 128, 34, 140, 188, 33, 224, 136, 238, 248, 152, 81, 170, 51, 126, 224, 40, 149, 146, 5, 6, 140, 164, 28, 164, 145, 217, 5, 134, 154, 136, 218, 147, 60, 60, 102, 148, 250, 116,
    91, 218, 51, 18, 79, 249, 97, 29, 105, 12, 58, 204, 236, 97, 23, 131, 222, 38, 4, 186, 110, 89, 172, 230, 149, 201, 181, 233, 239, 110, 53, 58, 125, 112, 2, 233, 142, 109, 63, 188,
    105, 103, 191, 101, 108, 191, 19, 217, 137, 15, 54, 239, 0, 108, 237, 162, 97, 168, 200, 89, 61, 207, 137, 255, 177, 236, 218, 223, 83, 39, 108, 231, 143, 22, 35, 132, 137, 227, 247, 35,
    148, 31, 255, 136, 95, 244, 53, 84, 217, 215, 233, 61, 239, 140, 54, 45, 31, 216, 238, 116, 186, 57, 154, 46, 10, 223, 105, 75, 146, 164, 229, 60, 194, 22, 176, 205, 27, 202, 132, 212,
    222, 112, 194, 128, 139, 161, 221, 168, 245, 230, 103, 136, 223, 154, 138, 1, 118, 103, 139, 205, 211, 22, 83, 130, 187, 224, 130, 212, 218, 93, 200, 125, 119, 253, 132, 179, 190, 77, 124, 44,
    30, 162, 241, 22, 178, 181, 53, 106, 191, 237, 48, 50, 81, 247, 21, 134, 145, 172, 19, 181, 19, 121, 88, 118, 72, 221, 206, 175, 93, 105, 35, 115, 174, 113, 134, 49, 100, 214, 107, 207,
    188, 105, 104, 185, 121, 233, 55, 162, 23, 253, 161, 142, 216, 201, 147, 231, 103, 77, 55, 59, 126, 183, 117, 108, 227, 135, 189, 238, 223, 199, 195, 158, 159, 99, 216, 103, 158, 228, 97, 225,
    90, 160, 130, 208, 189, 23, 252, 154, 155, 76, 160, 192, 233, 165, 41, 157, 43, 108, 18, 191, 238, 86, 240, 163, 115, 72, 160, 175, 131, 23, 113, 158, 95, 48, 19, 27, 108, 29, 172, 84,
    134, 209, 105, 218, 248, 86, 126, 238, 137, 227, 103, 3, 140, 216, 134, 183, 252, 120, 20, 219, 40, 26, 123, 66, 127, 230, 44, 236, 105, 209, 248, 85, 199, 241, 107, 238, 18, 67, 251, 75,
    191, 202, 143, 173, 209, 150, 194, 108, 72, 121, 248, 7, 19, 236, 188, 14, 46, 50, 167, 173, 22, 83, 2, 227, 214, 248, 98, 250, 22, 191, 173, 147, 5, 235, 2, 255, 209, 52, 11, 4,
    101, 92, 230, 96, 60, 125, 192, 171, 160, 140, 89, 241, 201, 232, 50, 220, 71, 36, 198, 63, 167, 43, 130, 59, 80, 244, 151, 22, 197, 233, 47, 55, 84, 34, 197, 96, 188, 217, 71, 128,
    23, 111, 155, 21, 73, 134, 24, 132, 182, 214, 161, 79, 177, 11, 84, 75, 249, 149, 59, 192, 46, 248, 141, 60, 35, 131, 211, 23, 156, 176, 226, 103, 180, 34, 24, 97, 64, 160, 99, 4,
    210, 158, 179, 185, 160, 128, 167, 27, 164, 167, 116, 222, 145, 62, 8, 53, 72, 101, 208, 13, 14, 31, 190, 0, 182, 210, 209, 64, 218, 28, 221, 202, 56, 46, 79, 114, 227, 134, 187, 24,
    189, 22, 175, 145, 114, 233, 0, 166, 154, 62, 227, 149, 120, 217, 28, 230, 88, 35, 26, 74, 57, 47, 129, 43, 103, 134, 141, 165, 87, 81, 244, 81, 184, 19, 79, 0, 255, 82, 52, 37,
    12, 231, 130, 149, 227, 199, 233, 154, 54, 184, 166, 104, 225, 161, 83, 248, 85, 157, 121, 80, 7, 104, 160, 11, 116, 188, 16, 32, 116, 194, 114, 102, 57, 133, 23, 43, 10, 186, 83, 198,
    1, 104, 36, 115, 172, 194, 4, 80, 7, 18, 99, 81, 183, 240, 130, 25, 226, 0, 149, 5, 223, 136, 240, 66, 102, 33, 65, 47, 193, 229, 149, 120, 1, 174, 240, 89, 5, 6, 202, 151,
    0, 129, 101, 74, 39, 95, 72, 16, 244, 66, 252, 143, 124, 11, 14, 30, 212, 82, 166, 76, 94, 4, 234, 240, 131, 117, 18, 88, 40, 6, 109, 252, 132, 33, 130, 71, 137, 169, 152, 197,
    21, 139, 16, 54, 146, 225, 252, 120, 27, 216, 2, 36, 194, 67, 206, 201, 195, 76, 124, 168, 163, 108, 152, 38, 11, 108, 203, 33, 188, 22, 194, 152, 210, 37, 90, 68, 33, 244, 249, 214,
    211, 163, 103, 192, 216, 66, 28, 56, 7, 71, 42, 113, 234, 217, 58, 202, 160, 19, 58, 102, 142, 190, 158, 248, 40, 101, 165, 111, 174, 176, 77, 9, 200, 188, 53, 18, 89, 172, 219, 104,
    69, 3, 41, 189, 180, 17, 190, 18, 218, 43, 193, 209, 115, 206, 8, 180, 23, 40, 10, 220, 146, 15, 50, 82, 145, 140, 80, 174, 16, 175, 238, 184, 216, 132, 150, 51, 206, 221, 109, 114,
    217, 50, 177, 92, 215, 223, 149, 24, 137, 3, 68, 235, 242, 16, 3, 24, 21, 104, 159, 121, 137, 3, 148, 9, 132, 39, 241, 148, 136, 63, 115, 67, 196, 170, 66, 188, 10, 18, 9, 249,
    215, 143, 212, 192, 109, 233, 116, 205, 139, 166, 49, 6, 140, 161, 116, 0, 11, 49, 49, 126, 251, 152, 239, 196, 1, 219, 19, 246, 30, 143, 1, 194, 249, 8, 226, 244, 182, 245, 194, 97,
    122, 15, 135, 128, 205, 9, 29, 171, 197, 251, 168, 188, 192, 136, 79, 170, 53, 206, 110, 199, 57, 154, 191, 189, 119, 220, 250, 198, 255, 178, 158, 177, 117, 16, 111, 67, 143, 113, 51, 79,
    181, 13, 198, 218, 239, 21, 5, 10, 53, 62, 116, 231, 133, 163, 232, 225, 107, 74, 189, 15, 19, 83, 168, 52, 190, 89, 44, 170, 249, 42, 188, 200, 246, 112, 39, 7, 223, 178, 88, 19,
    91, 238, 59, 228, 46, 184, 232, 198, 159, 246, 62, 14, 159, 21, 58, 202, 225, 133, 74, 113, 136, 235, 61, 2, 5, 215, 12, 110, 227, 44, 243, 151, 49, 198, 25, 111, 89, 226, 50, 214,
    63, 93, 169, 56, 119, 169, 186, 69, 198, 203, 20, 98, 255, 214, 229, 221, 154, 44, 29, 169, 159, 94, 59, 238, 41, 64, 34, 75, 94, 162, 181, 61, 5, 9, 2, 13, 70, 108, 240, 17,
    232, 168, 75, 232, 63, 189, 134, 61, 111, 53, 9, 164, 14, 192, 254, 5, 77, 170, 40, 69, 148, 223, 45, 217, 60, 92, 162, 232, 45, 91, 124, 137, 135, 207, 59, 37, 66, 173, 159, 174,
    216, 70, 236, 178, 226, 146, 205, 190, 37, 57, 94, 62, 164, 164, 96, 69, 72, 46, 211, 143, 66, 74, 213, 203, 7, 29, 106, 30, 214, 160, 80, 150, 160, 110, 89, 118, 47, 164, 84, 250,
    196, 175, 79, 253, 86, 144, 208, 255, 131, 125, 66, 16, 147, 114, 21, 212, 149, 116, 113, 190, 89, 96, 140, 154, 135, 75, 135, 49, 253, 131, 28, 78, 189, 191, 53, 8, 30, 58, 57, 113,
    147, 243, 114, 111, 14, 31, 110, 217, 90, 219, 116, 62, 212, 57, 177, 124, 95, 80, 81, 249, 78, 111, 221, 26, 31, 108, 117, 116, 115, 36, 196, 195, 172, 206, 59, 99, 7, 51, 228, 61,
    55, 192, 63, 253, 253, 250, 116, 154, 70, 13, 5, 156, 76, 49, 203, 124, 240, 158, 179, 221, 246, 53, 39, 179, 97, 167, 155, 217, 229, 199, 80, 218, 64, 254, 130, 135, 177, 69, 116, 10,
    29, 152, 59, 71, 192, 253, 182, 208, 120, 48, 220, 30, 104, 155, 243, 226, 126, 43, 104, 155, 179, 225, 175, 155, 211, 229, 58, 64, 59, 7, 165, 61, 21, 228, 190, 249, 197, 206, 161, 235,
    191, 185, 65, 231, 27, 165, 191, 202, 162, 63, 197, 138, 27, 134, 223, 252, 105, 91, 113, 195, 79, 47, 23, 89, 126, 25, 167, 178, 242, 38, 171, 156, 97, 163, 16, 23, 179, 221, 91, 140,
    1, 144, 46, 171, 122, 205, 6, 22, 174, 83, 165, 51, 151, 198, 46, 109, 231, 200, 150, 27, 159, 191, 210, 140, 165, 157, 118, 157, 60, 238, 23, 138, 212, 44, 70, 20, 212, 173, 197, 111,
    52, 135, 69, 168, 54, 108, 174, 238, 66, 219, 17, 207, 126, 174, 229, 75, 219, 186, 89, 108, 150, 207, 95, 195, 66, 112, 73, 175, 108, 103, 197, 225, 65, 221, 238, 118, 131, 75, 148, 48,
    15, 187, 221, 32, 88, 32, 5, 140, 30, 244, 131, 189, 136, 212, 43, 116, 129, 139, 254, 59, 93, 148, 85, 98, 4, 170, 46, 253, 188, 67, 21, 12, 89, 162, 0, 163, 75, 194, 40, 115,
    176, 135, 106, 23, 87, 174, 223, 249, 219, 221, 78, 68, 33, 67, 95, 166, 174, 211, 80, 20, 26, 138, 58, 29, 32, 205, 140, 116, 32, 122, 192, 8, 193, 82, 51, 22, 230, 174, 143, 118,
    150, 244, 237, 33, 243, 184, 91, 69, 201, 122, 93, 27, 108, 198, 181, 89, 144, 52, 221, 225, 2, 101, 198, 144, 13, 123, 58, 192, 157, 150, 250, 118, 87, 154, 162, 192, 209, 168, 11, 146,
    51, 195, 102, 182, 167, 3, 1, 75, 205, 197, 241, 221, 14, 8, 123, 246, 176, 77, 203, 50, 171, 221, 233, 129, 8, 177, 185, 220, 237, 1, 145, 23, 97, 186, 221, 39, 72, 34, 76, 255,
    242, 90, 75, 161, 20, 76, 165, 226, 184, 64, 87, 174, 197, 114, 183, 84, 72, 8, 137, 92, 72, 14, 15, 255, 242, 4, 63, 243, 166, 49, 33, 127, 99, 47, 195, 79, 82, 241, 35, 90,
    193, 12, 134, 101, 73, 24, 176, 230, 211, 90, 167, 39, 245, 181, 28, 82, 38, 235, 50, 163, 243, 69, 179, 114, 89, 77, 54, 238, 233, 228, 121, 40, 178, 91, 116, 121, 202, 165, 199, 104,
    249, 126, 185, 170, 174, 182, 133, 158, 135, 6, 158, 108, 174, 195, 76, 162, 188, 137, 218, 124, 58, 107, 119, 137, 116, 125, 96, 151, 216, 239, 135, 47, 151, 54, 205, 239, 205, 9, 175, 157,
    158, 70, 39, 179, 242, 172, 154, 69, 231, 245, 226, 145, 22, 218, 239, 166, 2, 125, 169, 242, 136, 11, 104, 191, 53, 218, 180, 208, 78, 218, 59, 167, 216, 125, 247, 39, 226, 167, 118, 118,
    211, 30, 142, 155, 118, 222, 184, 58, 217, 14, 140, 76, 107, 14, 76, 238, 59, 118, 94, 43, 227, 228, 167, 215, 9, 244, 159, 230, 85, 218, 35, 168, 240, 208, 14, 249, 57, 77, 165, 108,
    162, 199, 177, 46, 18, 203, 205, 172, 28, 62, 39, 25, 175, 22, 246, 140, 99, 235, 49, 23, 253, 19, 31, 165, 73, 198, 113, 154, 206, 18, 14, 205, 19, 251, 42, 245, 220, 149, 128, 81,
    248, 216, 51, 41, 161, 205, 79, 160, 251, 73, 22, 10, 201, 141, 73, 168, 134, 198, 38, 121, 156, 38, 86, 42, 198, 146, 91, 0, 138, 102, 155, 46, 230, 92, 151, 124, 253, 29, 33, 116,
    2, 91, 160, 37, 1, 225, 125, 108, 50, 55, 86, 204, 44, 88, 205, 39, 41, 16, 139, 173, 75, 10, 92, 127, 218, 142, 216, 54, 51, 220, 155, 55, 204, 254, 47, 19, 182, 72, 83, 144,
    195, 153, 60, 225, 182, 113, 13, 228, 83, 254, 0, 115, 203, 173, 220, 232, 71, 154, 11, 33, 84, 98, 248, 173, 251, 34, 118, 5, 126, 56, 163, 20, 23, 38, 225, 54, 51, 139, 103, 174,
    252, 57, 102, 129, 70, 180, 183, 46, 230, 116, 32, 55, 174, 162, 50, 87, 115, 98, 78, 159, 113, 70, 143, 53, 12, 9, 229, 120, 155, 51, 1, 108, 69, 128, 159, 112, 91, 83, 34, 219,
    84, 146, 28, 236, 66, 162, 241, 42, 225, 54, 107, 159, 216, 183, 133, 108, 15, 106, 168, 155, 9, 117, 249, 255, 114, 71, 16, 56, 45, 230, 41, 8, 148, 18, 166, 71, 146, 142, 255, 47,
    57, 203, 162, 199, 65, 124, 34, 217, 146, 42, 185, 210, 72, 167, 205, 203, 56, 79, 147, 116, 236, 61, 58, 230, 83, 32, 195, 53, 166, 60, 230, 164, 29, 132, 48, 163, 56, 112, 245, 143,
    12, 97, 215, 11, 73, 212, 144, 43, 43, 179, 181, 22, 67, 45, 160, 205, 5, 206, 136, 19, 83, 220, 179, 151, 112, 11, 95, 78, 49, 75, 45, 91, 241, 154, 247, 235, 38, 164, 38, 219,
    136, 165, 166, 52, 18, 123, 34, 138, 70, 184, 75, 77, 106, 162, 21, 19, 179, 102, 42, 173, 24, 217, 167, 79, 170, 131, 90, 9, 247, 74, 3, 37, 185, 1, 215, 196, 89, 129, 108, 49,
    184, 195, 221, 73, 26, 229, 210, 2, 117, 164, 65, 98, 21, 135, 246, 216, 54, 249, 100, 155, 182, 193, 40, 82, 130, 237, 144, 239, 25, 171, 147, 215, 154, 75, 100, 145, 150, 254, 178, 26,
    89, 200, 185, 228, 216, 138, 184, 136, 140, 72, 6, 187, 147, 178, 168, 148, 200, 169, 73, 44, 1, 121, 138, 156, 0, 129, 70, 229, 89, 228, 89, 4, 58, 70, 247, 71, 138, 241, 135, 66,
    23, 137, 208, 69, 20, 186, 72, 132, 46, 162, 208, 69, 20, 186, 136, 66, 23, 81, 232, 34, 17, 58, 89, 110, 118, 204, 226, 172, 40, 55, 123, 69, 20, 186, 72, 132, 142, 235, 168, 25,
    235, 102, 81, 150, 112, 183, 164, 240, 11, 63, 69, 65, 152, 188, 131, 204, 83, 227, 193, 97, 98, 5, 134, 81, 230, 217, 128, 104, 128, 160, 21, 52, 32, 224, 37, 26, 32, 120, 137, 6,
    8, 90, 162, 1, 130, 86, 80, 128, 128, 151, 13, 154, 16, 5, 21, 0, 90, 162, 0, 1, 45, 104, 128, 23, 93, 0, 63, 19, 31, 116, 129, 22, 41, 168, 66, 199, 82, 108, 183, 254,
    60, 124, 129, 115, 59, 232, 216, 58, 205, 102, 0, 209, 204, 5, 69, 173, 185, 179, 246, 171, 125, 141, 11, 104, 167, 236, 113, 0, 237, 87, 29, 127, 201, 196, 153, 105, 45, 43, 153, 7,
    203, 74, 45, 51, 182, 94, 41, 177, 103, 246, 44, 90, 159, 133, 178, 222, 131, 36, 192, 142, 110, 5, 220, 18, 240, 110, 225, 222, 203, 100, 90, 63, 159, 151, 243, 186, 101, 188, 44, 168,
    153, 242, 149, 20, 15, 170, 218, 162, 228, 164, 111, 90, 68, 205, 69, 32, 114, 154, 62, 179, 154, 235, 3, 8, 197, 100, 81, 152, 51, 200, 205, 85, 133, 66, 228, 60, 116, 85, 139, 7,
    201, 149, 172, 87, 115, 165, 57, 45, 114, 41, 154, 238, 92, 222, 228, 104, 21, 79, 41, 39, 216, 81, 182, 121, 148, 6, 184, 119, 17, 72, 121, 218, 81, 238, 100, 6, 131, 83, 110, 170,
    131, 206, 101, 220, 138, 154, 115, 225, 60, 11, 168, 6, 76, 5, 77, 68, 119, 220, 88, 224, 105, 44, 173, 202, 63, 119, 176, 48, 156, 204, 95, 95, 67, 103, 10, 67, 237, 15, 136, 26,
    72, 156, 108, 47, 132, 224, 112, 178, 156, 37, 17, 154, 242, 55, 220, 191, 161, 113, 129, 240, 65, 9, 57, 133, 30, 158, 80, 183, 100, 174, 179, 161, 20, 175, 161, 109, 3, 137, 231, 86,
    64, 235, 243, 196, 165, 250, 39, 248, 220, 166, 210, 165, 250, 235, 26, 209, 22, 218, 183, 2, 228, 175, 77, 90, 220, 202, 65, 249, 230, 81, 197, 173, 204, 219, 184, 169, 209, 46, 27, 238,
    15, 201, 253, 206, 43, 169, 77, 236, 182, 43, 234, 221, 40, 105, 231, 29, 182, 166, 169, 157, 212, 237, 248, 124, 207, 183, 57, 246, 14, 198, 183, 97, 101, 56, 160, 148, 113, 118, 216, 84,
    244, 224, 21, 192, 211, 205, 49, 172, 81, 28, 53, 199, 224, 71, 27, 128, 157, 147, 94, 79, 229, 48, 220, 6, 30, 74, 255, 239, 255, 5, 71, 96, 252, 206, 220, 119, 251, 245, 213, 160,
    191, 157, 148, 135, 250, 219, 249, 78, 193, 131, 141, 71, 155, 87, 93, 247, 12, 231, 215, 186, 203, 243, 95, 26, 149, 54, 221, 165, 206, 95, 184, 136, 234, 10, 37, 38, 19, 191, 192, 224,
    98, 163, 189, 175, 213, 80, 67, 154, 21, 98, 55, 184, 32, 8, 244, 16, 102, 214, 12, 185, 71, 100, 8, 75, 169, 183, 63, 151, 104, 24, 238, 88, 178, 149, 164, 196, 155, 82, 116, 152,
    154, 130, 197, 22, 224, 186, 242, 216, 139, 85, 165, 1, 95, 255, 44, 229, 119, 184, 206, 24, 242, 231, 54, 212, 24, 154, 96, 153, 209, 26, 55, 248, 196, 252, 145, 187, 151, 108, 151, 251,
    103, 147, 108, 168, 36, 89, 74, 197, 155, 82, 136, 248, 2, 218, 161, 204, 38, 115, 219, 78, 131, 118, 104, 66, 146, 135, 27, 64, 242, 179, 198, 1, 88, 19, 185, 225, 6, 57, 249, 89,
    10, 254, 235, 116, 193, 124, 211, 79, 43, 145, 0, 104, 16, 111, 104, 32, 63, 130, 245, 11, 33, 14, 87, 11, 61, 224, 194, 223, 103, 188, 6, 90, 255, 212, 122, 199, 229, 181, 229, 150,
    162, 161, 37, 42, 126, 12, 53, 31, 242, 143, 0, 97, 84, 135, 136, 56, 120, 93, 74, 252, 1, 194, 231, 140, 10, 146, 116, 150, 51, 218, 227, 207, 216, 49, 10, 6, 234, 188, 50, 236,
    30, 242, 125, 158, 196, 206, 226, 109, 145, 184, 41, 35, 249, 225, 6, 37, 134, 106, 41, 21, 67, 165, 161, 84, 74, 237, 48, 181, 47, 13, 221, 237, 152, 108, 100, 99, 15, 152, 118, 144,
    86, 151, 220, 125, 132, 112, 92, 90, 121, 97, 97, 193, 65, 97, 131, 112, 13, 125, 9, 15, 244, 214, 124, 216, 246, 88, 72, 241, 252, 162, 107, 118, 54, 202, 33, 214, 166, 249, 234, 218,
    1, 115, 243, 60, 188, 211, 250, 156, 7, 31, 159, 254, 31, 11, 146, 214, 40, 228, 143, 0, 0
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
