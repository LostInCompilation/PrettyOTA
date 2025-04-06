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
    The main source file.

*/

#include "PrettyOTA.h"

// Static variables
Stream* PrettyOTA::m_SerialMonitorStream = nullptr;
bool    PrettyOTA::m_DefaultCallbackPrintWithColor = false;

std::string PrettyOTA::m_AppBuildTime = "";
std::string PrettyOTA::m_AppBuildDate = "";
std::string PrettyOTA::m_AppVersion = "";
std::string PrettyOTA::m_HardwareID = "MyBoard1";

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
        jsonInfo["hardwareID"] = m_HardwareID;
        jsonInfo["rollbackPossible"] = m_UpdateManager.IsRollbackPossible();
        //jsonInfo["sdkVersion"] = appDesc->idf_ver;
        //jsonInfo["projectName"] = appDesc->project_name;
        //jsonInfo["firmwareSHA256"] = SHA256ToString(appDesc->app_elf_sha256);

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

void PrettyOTA::UseDefaultCallbacks(bool printWithColor)
{
    m_DefaultCallbackPrintWithColor = printWithColor;

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

const uint8_t PrettyOTA::PRETTY_OTA_WEBSITE_DATA[12583] = {
    31, 139, 8, 8, 98, 199, 241, 103, 0, 3, 112, 114, 101, 116, 116, 121, 79, 84, 65, 95, 109, 105, 110, 105, 102, 121, 46, 104, 116, 109, 108, 0, 229, 125, 139, 118, 219, 86, 150, 229, 175,
    160, 88, 157, 132, 108, 19, 240, 125, 226, 33, 137, 170, 73, 156, 84, 185, 102, 217, 93, 181, 226, 196, 211, 211, 89, 233, 52, 68, 66, 18, 59, 20, 161, 38, 41, 57, 142, 162, 254, 159,
    249, 141, 249, 178, 217, 251, 92, 144, 4, 40, 82, 150, 211, 169, 158, 233, 53, 113, 68, 0, 247, 117, 206, 61, 239, 251, 192, 197, 201, 239, 38, 245, 120, 245, 254, 186, 138, 46, 87, 87,
    179, 211, 19, 254, 70, 179, 114, 126, 49, 170, 230, 120, 170, 202, 201, 233, 201, 85, 181, 42, 163, 241, 101, 185, 88, 86, 171, 209, 183, 223, 252, 49, 206, 155, 180, 121, 121, 85, 141, 110,
    167, 213, 187, 235, 122, 177, 138, 198, 245, 124, 85, 205, 87, 163, 222, 187, 233, 100, 117, 57, 154, 84, 183, 211, 113, 21, 203, 195, 112, 58, 159, 174, 166, 229, 44, 94, 142, 203, 89, 53,
    210, 189, 118, 3, 147, 106, 57, 94, 76, 175, 87, 211, 122, 190, 109, 227, 243, 232, 172, 90, 173, 170, 69, 52, 171, 235, 31, 167, 243, 139, 232, 47, 223, 124, 30, 189, 171, 206, 162, 155,
    235, 73, 137, 244, 4, 77, 172, 166, 171, 89, 117, 250, 215, 5, 10, 190, 71, 246, 201, 243, 144, 112, 50, 155, 206, 127, 140, 22, 213, 108, 52, 69, 115, 17, 59, 55, 154, 94, 149, 23,
    213, 243, 229, 237, 197, 179, 159, 208, 191, 203, 69, 117, 62, 234, 161, 157, 242, 168, 147, 49, 252, 196, 190, 192, 109, 132, 219, 249, 114, 244, 217, 229, 106, 117, 125, 244, 252, 249, 187, 119,
    239, 146, 119, 54, 169, 23, 23, 207, 141, 82, 138, 133, 63, 139, 66, 31, 63, 243, 218, 124, 22, 93, 86, 211, 139, 203, 85, 243, 32, 117, 143, 110, 67, 237, 37, 170, 223, 86, 227, 85,
    153, 76, 235, 231, 243, 114, 94, 127, 246, 137, 253, 10, 64, 174, 203, 213, 101, 52, 25, 125, 246, 90, 69, 234, 18, 213, 110, 241, 247, 82, 189, 85, 63, 127, 22, 157, 79, 103, 179, 209,
    103, 159, 24, 235, 60, 255, 125, 246, 124, 167, 134, 246, 62, 177, 62, 143, 242, 34, 201, 189, 157, 217, 196, 102, 58, 78, 148, 49, 145, 77, 50, 101, 112, 171, 114, 220, 230, 69, 193, 212,
    72, 155, 36, 55, 41, 110, 157, 142, 92, 226, 172, 197, 173, 54, 145, 81, 73, 158, 49, 21, 183, 54, 41, 82, 150, 200, 178, 72, 231, 137, 207, 89, 209, 229, 145, 214, 137, 146, 116, 155,
    190, 48, 133, 73, 50, 147, 18, 168, 5, 32, 212, 54, 89, 26, 21, 62, 113, 38, 139, 172, 75, 1, 70, 141, 81, 193, 107, 205, 122, 185, 71, 83, 40, 138, 86, 76, 154, 232, 220, 69,
    198, 69, 206, 204, 0, 200, 3, 55, 173, 252, 216, 39, 62, 5, 108, 192, 112, 54, 50, 73, 138, 50, 206, 37, 38, 246, 82, 38, 101, 7, 252, 44, 214, 137, 85, 172, 161, 204, 11, 235,
    109, 226, 81, 3, 151, 2, 87, 107, 45, 42, 161, 106, 102, 18, 64, 179, 0, 108, 114, 61, 142, 209, 131, 20, 29, 73, 147, 172, 240, 177, 77, 147, 212, 20, 81, 150, 152, 34, 246, 105,
    98, 209, 241, 44, 209, 108, 56, 77, 10, 195, 254, 171, 130, 53, 148, 144, 66, 110, 189, 34, 133, 220, 43, 157, 121, 52, 152, 207, 132, 156, 236, 145, 73, 180, 203, 136, 99, 10, 136, 42,
    211, 196, 61, 85, 64, 205, 167, 36, 91, 14, 88, 202, 250, 168, 0, 254, 25, 240, 181, 164, 131, 118, 76, 180, 232, 128, 213, 118, 76, 126, 16, 25, 149, 186, 56, 241, 160, 188, 182, 137,
    209, 232, 49, 136, 195, 22, 188, 197, 125, 158, 130, 16, 73, 150, 2, 25, 149, 168, 60, 32, 111, 99, 157, 161, 67, 153, 84, 182, 64, 94, 3, 111, 38, 72, 33, 32, 14, 210, 120, 19,
    163, 189, 44, 179, 113, 158, 216, 52, 67, 146, 178, 38, 118, 32, 160, 139, 73, 170, 34, 206, 18, 207, 146, 16, 23, 17, 10, 80, 129, 98, 195, 20, 17, 16, 149, 163, 180, 2, 213, 144,
    42, 245, 132, 40, 40, 236, 18, 237, 131, 216, 32, 57, 207, 68, 152, 76, 108, 76, 82, 104, 35, 98, 19, 131, 201, 78, 200, 233, 242, 24, 178, 225, 108, 33, 98, 67, 56, 70, 81, 58,
    53, 48, 213, 137, 19, 145, 99, 43, 70, 185, 113, 168, 10, 100, 29, 75, 176, 47, 16, 108, 112, 20, 18, 128, 50, 160, 46, 59, 12, 114, 27, 86, 208, 22, 194, 151, 20, 150, 2, 146,
    129, 92, 30, 116, 247, 114, 111, 160, 2, 166, 16, 32, 41, 8, 237, 115, 45, 2, 142, 94, 21, 196, 20, 114, 145, 39, 58, 245, 65, 47, 128, 80, 225, 211, 192, 8, 48, 44, 119, 161,
    3, 84, 7, 43, 233, 222, 71, 32, 105, 230, 164, 106, 54, 54, 108, 38, 151, 100, 103, 137, 93, 204, 78, 71, 41, 36, 221, 83, 90, 52, 180, 0, 229, 83, 16, 144, 236, 46, 0, 33,
    133, 148, 130, 10, 232, 5, 96, 224, 201, 128, 142, 14, 125, 7, 127, 0, 15, 108, 101, 82, 10, 30, 102, 25, 184, 1, 246, 161, 52, 184, 91, 120, 41, 86, 232, 66, 216, 72, 186, 163,
    65, 27, 27, 240, 63, 51, 66, 27, 29, 67, 250, 114, 45, 15, 38, 211, 51, 112, 46, 23, 133, 215, 41, 200, 168, 45, 137, 171, 115, 97, 110, 208, 97, 29, 91, 136, 42, 5, 90, 131,
    11, 198, 129, 176, 164, 19, 122, 129, 50, 153, 216, 135, 60, 166, 25, 49, 129, 165, 160, 30, 122, 169, 52, 120, 147, 129, 161, 164, 1, 12, 0, 248, 159, 146, 209, 14, 244, 4, 157, 82,
    145, 216, 156, 76, 73, 115, 10, 108, 174, 99, 42, 149, 163, 44, 106, 10, 39, 20, 184, 145, 87, 17, 81, 145, 214, 168, 145, 80, 17, 215, 40, 72, 104, 16, 87, 176, 88, 107, 31, 27,
    90, 44, 10, 123, 158, 138, 184, 10, 175, 76, 145, 138, 192, 182, 205, 162, 25, 159, 217, 50, 93, 155, 69, 26, 99, 220, 193, 25, 4, 31, 18, 172, 253, 85, 61, 185, 153, 85, 209, 120,
    81, 47, 151, 245, 98, 122, 49, 157, 159, 194, 19, 44, 87, 209, 114, 86, 85, 215, 163, 106, 116, 58, 175, 222, 69, 127, 93, 212, 87, 211, 101, 213, 95, 141, 78, 225, 216, 190, 153, 94,
    85, 245, 205, 170, 191, 26, 86, 131, 193, 240, 106, 226, 71, 231, 55, 243, 49, 157, 82, 127, 112, 183, 190, 141, 170, 126, 53, 92, 13, 231, 195, 122, 184, 24, 206, 6, 119, 183, 229, 34,
    42, 135, 211, 99, 184, 160, 155, 197, 60, 90, 246, 251, 229, 104, 217, 95, 74, 35, 195, 101, 191, 70, 153, 193, 112, 58, 90, 12, 203, 147, 147, 233, 47, 229, 233, 233, 41, 36, 120, 58,
    24, 206, 7, 247, 155, 38, 9, 50, 52, 184, 28, 206, 134, 229, 224, 174, 105, 172, 234, 207, 63, 173, 127, 249, 247, 249, 167, 11, 129, 24, 50, 183, 213, 230, 143, 84, 91, 252, 82, 127,
    250, 239, 251, 171, 213, 135, 171, 253, 115, 253, 207, 251, 235, 44, 14, 214, 169, 255, 185, 63, 255, 229, 223, 23, 131, 189, 213, 150, 164, 85, 160, 209, 124, 212, 79, 189, 183, 254, 211, 106,
    240, 172, 185, 91, 13, 26, 170, 245, 171, 211, 83, 157, 34, 125, 213, 92, 231, 114, 61, 57, 209, 233, 47, 161, 232, 252, 190, 1, 216, 98, 3, 136, 63, 139, 166, 224, 105, 57, 31, 87,
    245, 121, 244, 237, 116, 190, 202, 63, 95, 44, 202, 247, 191, 252, 210, 159, 141, 200, 223, 111, 170, 159, 86, 95, 205, 199, 245, 164, 90, 244, 7, 73, 37, 119, 253, 222, 114, 181, 64, 56,
    209, 27, 141, 40, 41, 168, 56, 251, 195, 236, 232, 191, 191, 249, 203, 63, 36, 33, 99, 122, 254, 30, 109, 15, 6, 199, 231, 245, 162, 223, 176, 119, 244, 221, 247, 195, 137, 52, 185, 133,
    130, 66, 195, 155, 145, 26, 142, 71, 147, 228, 236, 253, 170, 122, 85, 205, 47, 86, 151, 199, 55, 39, 227, 227, 155, 103, 207, 6, 211, 228, 250, 102, 121, 217, 127, 35, 109, 38, 231, 144,
    180, 23, 136, 159, 94, 16, 131, 201, 119, 55, 223, 15, 214, 157, 111, 119, 9, 180, 90, 3, 5, 181, 71, 61, 152, 49, 4, 1, 105, 150, 23, 229, 217, 120, 82, 157, 247, 134, 139, 81,
    175, 55, 92, 142, 212, 241, 242, 100, 149, 204, 2, 196, 37, 160, 45, 158, 141, 234, 132, 1, 218, 231, 171, 126, 127, 62, 90, 201, 61, 129, 225, 121, 57, 24, 64, 236, 220, 167, 218, 15,
    158, 109, 10, 105, 16, 117, 131, 194, 226, 190, 127, 0, 11, 130, 171, 1, 174, 62, 177, 230, 239, 55, 16, 235, 103, 163, 124, 48, 127, 54, 218, 215, 185, 213, 119, 245, 233, 169, 255, 30,
    16, 235, 79, 172, 249, 212, 120, 191, 1, 51, 239, 128, 17, 57, 154, 125, 87, 178, 244, 47, 35, 109, 242, 147, 147, 18, 53, 134, 179, 239, 180, 123, 214, 47, 159, 165, 14, 109, 20, 39,
    39, 110, 240, 253, 168, 220, 48, 99, 58, 210, 153, 53, 62, 119, 186, 176, 96, 9, 172, 35, 158, 109, 158, 21, 224, 69, 188, 201, 114, 224, 202, 58, 39, 31, 254, 128, 14, 252, 112, 50,
    91, 99, 255, 195, 179, 17, 164, 75, 164, 242, 106, 52, 29, 94, 140, 38, 195, 191, 27, 221, 12, 47, 71, 227, 227, 201, 104, 209, 239, 254, 213, 59, 127, 243, 157, 191, 85, 247, 15, 88,
    172, 250, 55, 128, 190, 234, 143, 33, 54, 171, 254, 116, 136, 180, 225, 24, 189, 250, 225, 153, 250, 126, 152, 13, 227, 52, 87, 112, 161, 133, 77, 7, 146, 197, 12, 253, 253, 80, 155, 97,
    108, 17, 241, 164, 206, 231, 200, 97, 53, 230, 24, 228, 100, 195, 84, 165, 136, 152, 114, 93, 12, 208, 210, 84, 50, 236, 247, 67, 131, 42, 90, 57, 248, 21, 111, 173, 26, 60, 10, 218,
    9, 104, 56, 43, 167, 225, 26, 178, 45, 104, 47, 160, 53, 195, 218, 28, 30, 160, 5, 58, 21, 208, 48, 254, 32, 42, 130, 23, 167, 183, 192, 179, 0, 220, 249, 76, 249, 34, 183, 143,
    131, 206, 9, 90, 103, 25, 220, 144, 119, 186, 213, 235, 34, 244, 26, 209, 24, 88, 230, 156, 206, 182, 176, 181, 10, 192, 29, 28, 165, 221, 194, 213, 186, 233, 117, 81, 40, 7, 239, 150,
    154, 199, 65, 107, 35, 176, 209, 49, 196, 105, 105, 110, 90, 20, 183, 1, 184, 83, 232, 24, 124, 99, 11, 180, 107, 250, 237, 21, 136, 98, 76, 161, 90, 240, 189, 192, 135, 86, 166, 176,
    74, 214, 20, 4, 63, 23, 240, 115, 1, 63, 239, 130, 255, 126, 232, 209, 80, 234, 17, 136, 120, 173, 182, 208, 65, 218, 130, 188, 75, 11, 15, 215, 109, 77, 11, 58, 69, 193, 13, 83,
    135, 152, 62, 203, 116, 171, 239, 160, 136, 81, 144, 145, 12, 82, 146, 89, 101, 30, 7, 237, 5, 116, 166, 48, 86, 200, 211, 66, 183, 58, 174, 8, 219, 230, 128, 171, 200, 185, 13, 96,
    47, 128, 227, 52, 85, 46, 203, 173, 245, 91, 200, 46, 64, 118, 136, 129, 108, 150, 187, 252, 113, 200, 5, 33, 123, 68, 243, 14, 157, 200, 91, 128, 93, 211, 105, 196, 72, 96, 6, 201,
    186, 134, 109, 3, 104, 157, 103, 54, 181, 69, 218, 18, 180, 92, 64, 107, 208, 200, 91, 48, 68, 127, 128, 222, 54, 16, 220, 1, 118, 142, 200, 187, 37, 230, 70, 128, 123, 13, 126, 163,
    11, 91, 208, 153, 128, 134, 161, 0, 55, 115, 72, 122, 139, 215, 38, 116, 91, 23, 6, 52, 65, 152, 226, 8, 188, 22, 224, 181, 0, 175, 119, 41, 238, 200, 158, 28, 20, 223, 194, 69,
    7, 180, 30, 34, 106, 50, 198, 103, 64, 203, 238, 176, 58, 133, 116, 218, 66, 97, 140, 67, 89, 222, 192, 38, 201, 45, 90, 243, 22, 225, 184, 79, 31, 135, 172, 5, 178, 102, 217, 2,
    250, 210, 146, 51, 39, 208, 53, 194, 199, 188, 0, 75, 109, 183, 223, 41, 43, 121, 87, 100, 34, 129, 27, 216, 42, 192, 70, 200, 6, 122, 96, 164, 162, 62, 0, 221, 18, 60, 232, 109,
    178, 66, 103, 110, 11, 92, 133, 174, 99, 164, 10, 177, 49, 198, 116, 249, 13, 224, 72, 244, 70, 23, 89, 203, 170, 165, 2, 59, 75, 17, 157, 235, 188, 120, 28, 112, 33, 221, 6, 126,
    54, 117, 24, 87, 180, 36, 205, 4, 200, 206, 232, 92, 251, 156, 162, 220, 145, 242, 116, 8, 82, 97, 216, 224, 77, 75, 181, 77, 232, 117, 81, 192, 150, 230, 208, 86, 194, 94, 8, 236,
    133, 192, 94, 236, 90, 114, 82, 175, 200, 83, 171, 32, 233, 91, 216, 164, 43, 5, 214, 96, 184, 165, 157, 246, 59, 118, 69, 164, 147, 210, 236, 10, 213, 210, 48, 154, 21, 32, 12, 9,
    177, 212, 178, 199, 97, 179, 123, 16, 27, 216, 83, 7, 89, 203, 90, 186, 109, 5, 56, 244, 168, 112, 192, 12, 78, 99, 199, 160, 18, 186, 242, 218, 155, 182, 152, 7, 208, 70, 1, 37,
    3, 22, 22, 143, 3, 207, 5, 54, 20, 21, 30, 193, 250, 162, 69, 116, 31, 128, 67, 98, 52, 196, 192, 117, 253, 8, 33, 251, 148, 170, 15, 203, 211, 2, 110, 5, 186, 134, 228, 106,
    175, 83, 247, 1, 224, 46, 80, 221, 97, 28, 1, 6, 182, 228, 92, 84, 137, 61, 135, 31, 51, 26, 42, 94, 116, 61, 168, 31, 102, 192, 57, 207, 140, 111, 201, 90, 17, 122, 110, 65,
    115, 208, 145, 28, 159, 34, 114, 159, 14, 175, 208, 46, 110, 38, 195, 11, 98, 179, 4, 54, 127, 135, 74, 184, 25, 15, 47, 7, 77, 28, 250, 93, 131, 214, 247, 135, 3, 167, 16, 35,
    174, 67, 166, 211, 83, 200, 127, 8, 164, 230, 219, 40, 234, 217, 96, 254, 93, 253, 61, 82, 89, 45, 228, 230, 187, 81, 86, 8, 167, 126, 25, 245, 17, 73, 125, 218, 137, 235, 234, 231,
    249, 0, 65, 50, 195, 172, 86, 132, 85, 142, 166, 201, 191, 214, 211, 121, 191, 215, 195, 200, 35, 255, 251, 178, 105, 14, 17, 237, 253, 125, 127, 48, 188, 44, 151, 151, 127, 68, 192, 246,
    199, 233, 172, 26, 149, 203, 247, 243, 113, 180, 51, 26, 98, 172, 63, 24, 157, 222, 205, 170, 85, 84, 75, 208, 203, 178, 95, 87, 37, 194, 232, 227, 58, 169, 231, 179, 186, 156, 108, 199,
    70, 213, 64, 74, 206, 119, 195, 227, 42, 89, 149, 139, 139, 106, 149, 44, 170, 229, 205, 12, 193, 254, 170, 143, 49, 85, 127, 14, 60, 134, 53, 18, 203, 201, 231, 75, 41, 249, 197, 205,
    249, 57, 2, 244, 106, 112, 63, 56, 14, 8, 109, 199, 29, 55, 243, 111, 101, 182, 143, 80, 46, 167, 147, 234, 171, 89, 117, 85, 205, 87, 253, 222, 205, 53, 177, 120, 81, 207, 110, 174,
    230, 61, 244, 170, 157, 135, 177, 220, 10, 113, 233, 114, 127, 238, 89, 93, 46, 14, 84, 60, 187, 89, 173, 234, 249, 38, 175, 124, 87, 78, 155, 17, 99, 223, 80, 222, 150, 151, 245, 187,
    77, 225, 235, 69, 125, 129, 174, 109, 161, 0, 236, 95, 155, 180, 111, 56, 13, 217, 239, 189, 1, 5, 86, 235, 169, 203, 48, 109, 217, 3, 29, 22, 239, 133, 98, 171, 81, 0, 208, 230,
    8, 250, 57, 156, 143, 38, 245, 248, 134, 64, 18, 144, 175, 129, 247, 197, 251, 63, 79, 250, 189, 122, 85, 190, 6, 243, 123, 131, 228, 182, 156, 221, 84, 144, 168, 131, 69, 23, 213, 89,
    93, 175, 94, 92, 86, 227, 31, 207, 234, 159, 254, 60, 191, 190, 89, 161, 218, 152, 207, 213, 4, 227, 136, 0, 251, 188, 90, 141, 47, 251, 255, 242, 252, 90, 166, 80, 209, 252, 243, 37,
    113, 254, 3, 198, 207, 213, 232, 239, 238, 230, 247, 159, 18, 59, 220, 173, 238, 63, 13, 45, 226, 190, 190, 255, 151, 193, 241, 244, 188, 255, 187, 69, 82, 255, 56, 88, 93, 46, 234, 119,
    209, 87, 139, 5, 100, 184, 247, 162, 190, 153, 77, 162, 121, 13, 178, 177, 157, 110, 199, 217, 233, 165, 136, 201, 63, 190, 126, 245, 114, 181, 186, 254, 186, 250, 183, 155, 106, 185, 58, 94,
    38, 129, 157, 144, 173, 53, 85, 59, 242, 5, 88, 85, 35, 198, 47, 234, 43, 244, 164, 60, 155, 53, 98, 183, 26, 189, 46, 87, 151, 201, 162, 190, 153, 79, 88, 8, 173, 84, 147, 231,
    144, 61, 244, 101, 246, 247, 90, 169, 193, 241, 65, 18, 173, 97, 125, 81, 46, 64, 154, 229, 234, 253, 172, 74, 194, 172, 238, 234, 89, 239, 147, 222, 240, 131, 21, 223, 146, 9, 168, 58,
    157, 207, 171, 197, 203, 111, 94, 191, 10, 21, 239, 239, 135, 75, 116, 133, 34, 254, 30, 100, 88, 85, 80, 218, 249, 197, 90, 219, 90, 147, 10, 110, 52, 90, 138, 38, 188, 127, 195, 98,
    159, 126, 218, 255, 21, 184, 246, 208, 201, 167, 32, 27, 106, 110, 81, 109, 234, 117, 20, 224, 129, 76, 63, 80, 1, 196, 196, 68, 154, 221, 186, 89, 254, 161, 223, 209, 136, 229, 205, 120,
    188, 163, 16, 111, 66, 210, 107, 252, 149, 23, 208, 136, 160, 205, 81, 147, 124, 126, 51, 219, 192, 224, 207, 31, 235, 197, 155, 106, 113, 91, 45, 190, 22, 81, 123, 131, 198, 191, 22, 227,
    209, 31, 12, 142, 220, 35, 144, 43, 74, 95, 27, 174, 136, 99, 163, 133, 223, 138, 108, 69, 231, 37, 244, 107, 210, 202, 134, 69, 91, 130, 13, 228, 192, 242, 186, 158, 47, 43, 78, 23,
    0, 208, 111, 215, 116, 47, 244, 38, 10, 214, 185, 154, 68, 1, 249, 136, 243, 16, 81, 239, 217, 186, 51, 52, 205, 162, 28, 97, 214, 2, 84, 184, 250, 178, 92, 149, 199, 179, 164, 188,
    190, 174, 32, 215, 189, 115, 180, 223, 27, 86, 195, 42, 225, 122, 201, 128, 226, 133, 140, 126, 239, 175, 127, 121, 243, 77, 111, 216, 107, 169, 111, 80, 36, 162, 146, 44, 89, 117, 182, 207,
    46, 5, 180, 105, 152, 122, 207, 154, 38, 239, 199, 37, 45, 65, 185, 99, 102, 63, 44, 16, 191, 25, 177, 202, 228, 42, 72, 9, 252, 212, 118, 178, 106, 78, 171, 40, 214, 139, 134, 160,
    153, 47, 34, 138, 47, 110, 150, 171, 250, 234, 243, 89, 181, 128, 116, 12, 215, 230, 225, 84, 15, 130, 104, 180, 179, 123, 127, 153, 207, 222, 71, 101, 180, 68, 143, 103, 21, 39, 18, 171,
    104, 92, 206, 163, 179, 42, 10, 228, 2, 103, 74, 248, 186, 249, 184, 74, 128, 215, 239, 244, 224, 168, 119, 54, 157, 247, 126, 55, 170, 190, 83, 223, 11, 125, 146, 229, 245, 108, 138, 150,
    144, 159, 92, 215, 215, 253, 61, 80, 62, 19, 40, 189, 132, 53, 5, 198, 114, 23, 72, 242, 89, 104, 188, 223, 114, 107, 0, 128, 68, 53, 184, 63, 108, 200, 235, 217, 236, 172, 28, 255,
    248, 133, 56, 39, 192, 47, 39, 147, 175, 110, 145, 253, 106, 186, 92, 85, 208, 230, 126, 111, 60, 155, 142, 127, 236, 13, 119, 236, 75, 227, 50, 187, 132, 250, 207, 118, 162, 199, 193, 72,
    239, 49, 250, 171, 167, 154, 200, 85, 215, 68, 138, 5, 90, 253, 106, 11, 244, 117, 67, 206, 143, 183, 65, 224, 82, 99, 133, 14, 64, 127, 84, 250, 55, 112, 15, 201, 255, 234, 63, 96,
    135, 62, 216, 248, 7, 44, 209, 170, 101, 137, 134, 171, 131, 198, 101, 82, 175, 1, 1, 194, 42, 24, 24, 68, 109, 135, 125, 79, 8, 25, 254, 107, 74, 238, 67, 83, 215, 133, 210, 22,
    181, 55, 111, 255, 116, 64, 218, 132, 0, 156, 110, 222, 177, 148, 59, 146, 250, 183, 86, 147, 39, 202, 247, 81, 255, 112, 31, 95, 209, 134, 53, 181, 122, 143, 240, 188, 83, 41, 20, 111,
    200, 209, 13, 63, 222, 64, 122, 232, 130, 130, 140, 224, 34, 253, 109, 36, 56, 137, 30, 17, 216, 163, 150, 196, 30, 198, 227, 162, 254, 162, 109, 53, 39, 211, 37, 163, 198, 201, 232, 119,
    250, 105, 117, 76, 183, 210, 135, 52, 227, 117, 57, 191, 41, 103, 27, 242, 60, 69, 59, 102, 245, 69, 125, 243, 171, 180, 227, 111, 44, 45, 48, 68, 213, 234, 237, 180, 122, 215, 111, 36,
    162, 171, 137, 15, 252, 235, 171, 250, 34, 66, 79, 54, 214, 231, 113, 90, 133, 110, 127, 148, 5, 217, 29, 198, 28, 36, 85, 135, 72, 245, 184, 156, 189, 89, 213, 11, 136, 30, 32, 173,
    254, 188, 170, 174, 214, 13, 254, 48, 110, 90, 124, 36, 112, 126, 116, 4, 197, 193, 42, 185, 48, 89, 212, 215, 159, 131, 148, 135, 7, 98, 44, 241, 115, 61, 231, 0, 104, 19, 214, 48,
    237, 229, 244, 226, 114, 198, 109, 35, 196, 117, 221, 76, 50, 158, 149, 203, 37, 187, 197, 62, 110, 43, 199, 151, 235, 210, 189, 214, 250, 26, 115, 191, 157, 95, 126, 160, 161, 69, 117, 85,
    223, 86, 31, 106, 171, 109, 157, 216, 206, 129, 238, 84, 131, 61, 45, 67, 68, 38, 213, 188, 221, 90, 219, 140, 60, 181, 53, 233, 240, 195, 166, 30, 132, 175, 143, 180, 183, 137, 87, 165,
    100, 199, 222, 84, 157, 22, 119, 236, 244, 99, 77, 46, 59, 69, 31, 105, 179, 229, 144, 31, 107, 175, 218, 20, 251, 80, 91, 141, 239, 254, 96, 99, 161, 220, 78, 107, 27, 65, 120, 168,
    43, 19, 104, 4, 248, 182, 232, 170, 75, 149, 64, 69, 89, 240, 203, 234, 188, 148, 49, 23, 245, 242, 177, 86, 234, 235, 15, 181, 208, 184, 181, 42, 225, 78, 171, 111, 22, 229, 124, 121,
    94, 45, 18, 9, 142, 143, 219, 161, 253, 234, 131, 176, 64, 250, 249, 138, 40, 119, 84, 231, 131, 149, 66, 55, 63, 174, 206, 172, 42, 111, 171, 80, 169, 165, 92, 79, 160, 197, 199, 212,
    216, 99, 175, 14, 50, 249, 124, 77, 39, 154, 31, 214, 235, 175, 173, 15, 149, 182, 217, 182, 112, 220, 209, 228, 182, 121, 174, 134, 43, 250, 175, 195, 237, 207, 17, 161, 156, 79, 49, 0,
    68, 237, 29, 49, 103, 40, 58, 66, 3, 127, 120, 82, 229, 48, 197, 176, 163, 209, 59, 5, 26, 205, 235, 13, 142, 126, 85, 147, 107, 147, 115, 168, 213, 195, 230, 252, 131, 136, 146, 110,
    104, 96, 12, 254, 47, 214, 123, 65, 90, 4, 14, 126, 175, 121, 24, 181, 246, 139, 180, 28, 235, 127, 168, 75, 1, 254, 253, 48, 171, 236, 142, 37, 237, 184, 223, 187, 195, 8, 254, 22,
    224, 119, 102, 96, 17, 86, 44, 222, 111, 54, 88, 254, 121, 126, 94, 247, 67, 248, 81, 237, 11, 63, 170, 125, 225, 71, 139, 62, 211, 243, 62, 98, 143, 170, 19, 123, 72, 232, 81, 173,
    7, 32, 77, 104, 35, 251, 49, 174, 185, 223, 180, 191, 186, 156, 238, 76, 209, 28, 158, 209, 131, 182, 47, 1, 41, 236, 75, 232, 200, 240, 42, 217, 4, 32, 111, 67, 161, 225, 254, 248,
    160, 105, 226, 135, 102, 151, 200, 240, 97, 197, 193, 129, 154, 87, 229, 116, 254, 195, 205, 98, 198, 58, 188, 255, 246, 235, 87, 135, 138, 34, 4, 218, 150, 149, 7, 41, 12, 65, 188, 89,
    93, 162, 55, 13, 171, 190, 154, 75, 244, 249, 135, 206, 200, 161, 27, 53, 30, 117, 2, 246, 110, 222, 253, 253, 176, 106, 162, 176, 63, 125, 181, 19, 132, 61, 228, 107, 143, 179, 40, 77,
    64, 182, 79, 8, 126, 123, 222, 75, 218, 111, 201, 254, 75, 12, 237, 222, 149, 139, 234, 135, 233, 228, 135, 21, 138, 238, 72, 192, 58, 251, 207, 95, 30, 214, 148, 61, 77, 200, 158, 226,
    39, 86, 63, 159, 46, 174, 164, 250, 90, 140, 246, 160, 177, 46, 179, 150, 195, 143, 110, 108, 141, 208, 147, 27, 58, 187, 153, 206, 38, 63, 112, 194, 105, 31, 62, 146, 251, 37, 50, 63,
    166, 129, 53, 14, 79, 174, 188, 130, 145, 58, 8, 157, 22, 236, 99, 26, 232, 64, 151, 202, 176, 99, 205, 212, 196, 95, 235, 229, 114, 10, 181, 249, 195, 225, 201, 244, 7, 83, 106, 79,
    26, 28, 174, 107, 173, 145, 144, 73, 248, 81, 111, 92, 207, 234, 197, 209, 239, 149, 58, 63, 87, 234, 248, 177, 241, 196, 78, 253, 45, 21, 122, 255, 179, 162, 67, 252, 85, 8, 171, 95,
    139, 240, 249, 185, 199, 191, 95, 137, 240, 63, 192, 92, 220, 87, 179, 101, 21, 185, 182, 254, 254, 129, 155, 44, 235, 25, 215, 97, 46, 250, 189, 141, 217, 56, 122, 48, 154, 231, 188, 115,
    71, 169, 143, 158, 90, 179, 59, 113, 181, 49, 28, 31, 180, 117, 31, 48, 113, 123, 166, 70, 54, 198, 78, 75, 0, 37, 139, 180, 237, 57, 33, 43, 171, 75, 213, 137, 86, 199, 131, 187,
    118, 134, 246, 204, 88, 47, 243, 205, 247, 25, 203, 121, 179, 140, 10, 92, 218, 54, 18, 176, 20, 129, 169, 251, 33, 75, 72, 116, 223, 201, 127, 246, 76, 114, 246, 247, 179, 53, 96, 69,
    79, 231, 235, 158, 202, 204, 190, 84, 93, 239, 162, 92, 61, 161, 247, 173, 137, 161, 74, 194, 199, 96, 153, 127, 221, 104, 89, 86, 11, 87, 159, 126, 250, 187, 39, 12, 180, 62, 56, 113,
    244, 249, 205, 170, 94, 207, 26, 77, 151, 209, 90, 21, 146, 232, 175, 8, 140, 32, 145, 77, 214, 149, 76, 200, 204, 222, 71, 40, 125, 131, 100, 56, 214, 136, 156, 88, 91, 205, 164, 247,
    200, 132, 94, 119, 178, 171, 89, 94, 63, 60, 71, 127, 112, 174, 233, 17, 237, 60, 60, 215, 164, 142, 131, 220, 28, 156, 180, 235, 63, 226, 3, 127, 227, 105, 175, 225, 252, 17, 59, 250,
    84, 142, 133, 44, 46, 116, 131, 250, 243, 233, 242, 178, 154, 12, 49, 202, 21, 197, 6, 7, 23, 55, 243, 57, 247, 145, 62, 157, 33, 143, 217, 202, 167, 34, 181, 93, 170, 94, 84, 48,
    62, 243, 106, 188, 74, 162, 6, 211, 177, 228, 93, 98, 28, 216, 204, 105, 69, 245, 226, 129, 0, 69, 147, 186, 90, 74, 3, 103, 149, 20, 29, 215, 11, 52, 181, 154, 189, 255, 152, 158,
    180, 54, 89, 111, 103, 221, 238, 222, 77, 231, 147, 250, 93, 194, 232, 145, 121, 176, 149, 180, 22, 253, 246, 54, 110, 105, 8, 69, 31, 204, 104, 77, 231, 81, 59, 234, 252, 229, 151, 39,
    78, 132, 253, 78, 13, 134, 187, 225, 239, 19, 219, 218, 13, 154, 123, 58, 81, 137, 130, 17, 218, 6, 197, 79, 108, 105, 27, 68, 247, 158, 175, 55, 14, 12, 91, 241, 242, 19, 155, 105,
    5, 216, 189, 231, 242, 240, 216, 208, 240, 81, 219, 53, 234, 173, 22, 55, 85, 111, 52, 234, 64, 186, 56, 68, 198, 71, 192, 28, 30, 157, 236, 111, 122, 135, 170, 131, 225, 190, 193, 216,
    176, 21, 156, 223, 55, 98, 211, 154, 90, 25, 181, 238, 135, 77, 246, 70, 208, 70, 155, 187, 225, 166, 166, 108, 238, 9, 194, 117, 124, 242, 60, 188, 83, 113, 122, 34, 161, 195, 41, 95,
    13, 188, 59, 175, 231, 171, 248, 188, 188, 154, 206, 222, 31, 45, 203, 249, 50, 134, 34, 79, 207, 239, 207, 234, 201, 251, 59, 70, 11, 23, 178, 23, 35, 110, 162, 12, 93, 240, 223, 113,
    243, 84, 165, 252, 119, 159, 156, 131, 100, 213, 226, 238, 186, 94, 78, 41, 204, 71, 231, 211, 159, 224, 36, 102, 213, 249, 234, 72, 29, 159, 213, 176, 67, 87, 184, 145, 253, 13, 71, 220,
    166, 112, 28, 94, 176, 59, 50, 249, 245, 79, 199, 179, 41, 231, 48, 67, 130, 197, 243, 67, 160, 86, 243, 223, 26, 104, 94, 240, 223, 177, 224, 189, 156, 254, 92, 29, 105, 169, 85, 255,
    20, 47, 47, 75, 116, 250, 72, 69, 42, 66, 195, 17, 98, 56, 117, 47, 67, 183, 47, 167, 183, 119, 48, 130, 215, 179, 242, 253, 209, 249, 172, 250, 233, 248, 170, 92, 64, 134, 226, 85,
    125, 125, 100, 49, 96, 94, 63, 55, 168, 58, 38, 177, 92, 60, 153, 210, 2, 176, 75, 99, 81, 246, 227, 114, 54, 189, 152, 199, 83, 240, 115, 121, 52, 150, 41, 172, 251, 228, 82, 182,
    82, 125, 93, 191, 187, 59, 171, 23, 184, 91, 55, 163, 129, 3, 98, 160, 233, 36, 106, 8, 165, 199, 107, 64, 66, 26, 237, 175, 55, 152, 44, 164, 251, 76, 185, 15, 155, 94, 22, 95,
    212, 63, 97, 84, 53, 254, 241, 78, 222, 176, 60, 50, 137, 241, 107, 178, 121, 133, 138, 129, 154, 78, 109, 219, 104, 192, 250, 86, 179, 236, 160, 203, 216, 40, 232, 179, 229, 15, 204, 15,
    236, 208, 109, 117, 92, 95, 151, 227, 233, 234, 253, 145, 10, 204, 210, 138, 69, 151, 176, 117, 130, 225, 182, 66, 121, 134, 142, 220, 172, 170, 135, 204, 185, 92, 206, 250, 58, 179, 81, 170,
    62, 137, 140, 249, 100, 176, 230, 114, 1, 36, 214, 232, 226, 118, 37, 147, 133, 245, 226, 234, 104, 249, 35, 44, 162, 154, 84, 23, 195, 216, 120, 92, 16, 89, 1, 73, 237, 40, 9, 59,
    56, 8, 81, 62, 22, 9, 103, 63, 10, 137, 189, 56, 196, 197, 6, 7, 100, 124, 44, 6, 214, 111, 48, 48, 106, 139, 129, 220, 47, 106, 142, 148, 143, 28, 161, 238, 226, 19, 155, 134,
    44, 188, 12, 132, 101, 177, 190, 43, 231, 211, 171, 50, 104, 213, 162, 190, 18, 190, 68, 110, 25, 77, 231, 116, 189, 171, 42, 20, 51, 187, 197, 132, 116, 237, 114, 199, 155, 2, 241, 164,
    162, 30, 232, 101, 168, 106, 63, 4, 225, 65, 77, 211, 212, 116, 31, 15, 212, 46, 239, 255, 219, 143, 213, 251, 243, 69, 121, 5, 95, 187, 1, 119, 167, 62, 185, 251, 57, 134, 201, 170,
    126, 2, 153, 90, 82, 41, 20, 154, 145, 98, 49, 201, 23, 197, 41, 24, 99, 90, 165, 245, 182, 180, 110, 149, 134, 9, 184, 119, 173, 98, 69, 39, 15, 124, 190, 79, 91, 185, 121, 39,
    23, 166, 227, 62, 111, 229, 102, 7, 32, 104, 131, 130, 180, 102, 155, 146, 190, 147, 111, 201, 239, 77, 87, 238, 31, 116, 60, 72, 247, 135, 123, 254, 95, 190, 227, 141, 65, 107, 198, 33,
    111, 255, 116, 215, 232, 134, 109, 171, 100, 28, 94, 235, 107, 140, 234, 86, 112, 142, 130, 198, 184, 200, 44, 35, 122, 10, 190, 51, 180, 150, 174, 150, 145, 139, 245, 214, 114, 6, 64, 47,
    166, 139, 241, 172, 186, 227, 107, 134, 71, 115, 140, 189, 142, 225, 118, 235, 31, 171, 163, 223, 27, 127, 166, 138, 179, 230, 49, 188, 205, 142, 174, 54, 143, 147, 18, 78, 132, 187, 88, 143,
    52, 247, 198, 181, 147, 235, 243, 115, 120, 215, 163, 77, 26, 177, 25, 151, 215, 71, 98, 6, 90, 8, 179, 172, 139, 116, 226, 151, 17, 199, 47, 32, 81, 204, 197, 212, 141, 194, 182, 228,
    160, 233, 219, 157, 16, 115, 107, 13, 66, 114, 223, 166, 193, 16, 180, 107, 72, 227, 20, 154, 167, 227, 123, 239, 247, 21, 47, 212, 129, 242, 177, 245, 107, 246, 238, 201, 212, 134, 185, 247,
    73, 123, 195, 198, 93, 219, 217, 60, 244, 71, 172, 177, 43, 73, 193, 156, 54, 137, 145, 130, 111, 219, 16, 107, 216, 56, 234, 110, 106, 132, 161, 95, 253, 14, 254, 24, 17, 76, 69, 171,
    183, 94, 253, 108, 132, 201, 186, 150, 165, 213, 242, 16, 156, 177, 120, 97, 246, 160, 218, 184, 97, 107, 155, 188, 120, 81, 78, 166, 55, 75, 113, 57, 173, 120, 34, 201, 51, 207, 8, 160,
    29, 152, 104, 32, 195, 52, 78, 157, 196, 18, 4, 172, 37, 181, 213, 159, 166, 85, 241, 8, 145, 201, 212, 85, 131, 62, 151, 115, 198, 55, 139, 37, 252, 196, 117, 61, 13, 65, 195, 26,
    255, 163, 75, 174, 105, 221, 181, 171, 174, 227, 170, 179, 124, 91, 108, 187, 200, 187, 83, 212, 170, 51, 87, 166, 219, 130, 140, 63, 27, 134, 8, 51, 186, 57, 95, 78, 175, 238, 154, 138,
    89, 197, 127, 247, 73, 8, 108, 94, 74, 12, 211, 13, 146, 118, 34, 160, 69, 253, 238, 248, 95, 111, 150, 171, 233, 249, 251, 184, 57, 213, 97, 163, 173, 15, 162, 162, 118, 120, 102, 118,
    130, 60, 157, 82, 241, 73, 200, 173, 200, 223, 92, 95, 87, 139, 49, 136, 117, 140, 177, 253, 2, 49, 232, 12, 80, 131, 222, 182, 164, 75, 148, 188, 141, 112, 171, 183, 161, 128, 127, 32,
    126, 136, 126, 214, 145, 227, 153, 226, 191, 110, 11, 180, 71, 15, 227, 162, 166, 66, 99, 42, 90, 0, 210, 93, 12, 80, 255, 245, 139, 111, 239, 186, 97, 156, 217, 83, 234, 79, 48, 93,
    221, 98, 249, 182, 84, 71, 138, 91, 130, 219, 9, 31, 247, 203, 109, 11, 185, 191, 141, 166, 5, 12, 95, 4, 142, 63, 42, 33, 77, 140, 220, 230, 117, 209, 197, 176, 205, 159, 7, 49,
    112, 195, 176, 124, 19, 220, 90, 229, 183, 36, 106, 16, 248, 106, 206, 137, 184, 143, 149, 211, 37, 250, 95, 197, 103, 213, 234, 93, 85, 237, 11, 226, 143, 223, 93, 226, 49, 150, 98, 144,
    186, 119, 139, 242, 122, 7, 174, 236, 13, 191, 235, 8, 210, 58, 202, 148, 112, 188, 101, 24, 132, 187, 199, 215, 229, 132, 251, 161, 26, 94, 219, 29, 29, 152, 67, 232, 203, 89, 168, 69,
    3, 112, 14, 154, 31, 85, 179, 217, 244, 122, 57, 93, 30, 111, 82, 194, 246, 137, 251, 160, 14, 119, 29, 235, 208, 138, 65, 33, 168, 142, 255, 214, 48, 143, 224, 231, 197, 75, 239, 17,
    37, 155, 243, 223, 142, 32, 165, 29, 251, 23, 226, 224, 22, 178, 18, 185, 114, 239, 114, 185, 224, 203, 217, 162, 150, 13, 78, 123, 205, 151, 82, 233, 217, 249, 249, 125, 178, 103, 28, 190,
    225, 156, 180, 145, 172, 234, 139, 139, 89, 245, 230, 221, 148, 83, 154, 29, 166, 238, 225, 209, 1, 227, 243, 80, 123, 27, 233, 105, 69, 255, 70, 239, 31, 88, 22, 78, 251, 93, 98, 136,
    22, 117, 205, 117, 75, 149, 226, 201, 205, 34, 248, 121, 149, 104, 191, 236, 118, 225, 232, 168, 60, 231, 64, 120, 141, 97, 175, 119, 252, 112, 236, 208, 160, 148, 110, 196, 60, 93, 15, 59,
    246, 143, 126, 215, 236, 238, 32, 9, 159, 126, 0, 41, 179, 108, 143, 133, 209, 151, 8, 130, 16, 101, 50, 30, 206, 249, 207, 153, 181, 88, 248, 93, 11, 179, 151, 101, 71, 205, 196, 201,
    179, 189, 93, 221, 154, 240, 77, 8, 248, 143, 24, 9, 93, 255, 52, 56, 76, 180, 131, 157, 252, 8, 248, 123, 230, 38, 130, 216, 61, 198, 171, 176, 184, 208, 68, 45, 7, 39, 4, 36,
    26, 120, 242, 232, 191, 189, 203, 116, 211, 230, 116, 46, 250, 243, 148, 166, 105, 174, 246, 8, 251, 69, 121, 221, 76, 7, 4, 164, 101, 135, 209, 19, 220, 157, 84, 153, 84, 171, 114, 58,
    147, 210, 59, 106, 221, 53, 96, 173, 166, 14, 180, 212, 204, 86, 135, 144, 250, 203, 223, 168, 217, 141, 109, 108, 15, 248, 219, 115, 170, 255, 163, 13, 245, 32, 163, 244, 67, 12, 15, 151,
    21, 103, 219, 158, 24, 239, 22, 237, 24, 211, 137, 63, 175, 198, 155, 57, 46, 7, 201, 60, 219, 53, 8, 141, 233, 111, 71, 157, 238, 97, 207, 252, 218, 174, 190, 11, 69, 50, 165, 118,
    237, 108, 163, 138, 106, 215, 181, 211, 22, 236, 17, 139, 206, 52, 23, 245, 151, 48, 100, 166, 11, 255, 21, 166, 237, 243, 225, 199, 91, 158, 125, 87, 12, 187, 196, 88, 155, 241, 7, 58,
    229, 38, 185, 161, 41, 111, 23, 62, 93, 222, 94, 172, 3, 150, 205, 180, 74, 128, 185, 177, 6, 13, 228, 198, 205, 133, 41, 44, 157, 216, 125, 80, 35, 54, 183, 215, 140, 196, 32, 194,
    96, 167, 74, 57, 166, 137, 111, 149, 151, 182, 251, 73, 145, 14, 246, 152, 21, 165, 156, 167, 89, 233, 52, 177, 94, 14, 217, 211, 221, 198, 59, 54, 79, 69, 201, 127, 109, 154, 75, 64,
    218, 200, 64, 44, 123, 227, 150, 141, 39, 235, 46, 233, 254, 38, 194, 229, 119, 133, 235, 255, 21, 81, 218, 132, 152, 187, 221, 254, 160, 24, 117, 139, 139, 32, 61, 116, 144, 205, 204, 166,
    57, 44, 90, 15, 37, 203, 236, 71, 37, 250, 61, 64, 252, 16, 198, 211, 15, 7, 216, 177, 206, 155, 169, 182, 157, 186, 191, 78, 200, 118, 26, 249, 79, 16, 179, 182, 63, 8, 17, 132,
    104, 118, 251, 53, 141, 255, 127, 36, 177, 213, 233, 15, 203, 97, 171, 240, 227, 82, 72, 148, 215, 66, 166, 221, 14, 152, 95, 41, 39, 237, 38, 254, 54, 82, 210, 130, 240, 64, 70, 188,
    13, 83, 101, 219, 173, 101, 123, 6, 192, 24, 125, 148, 171, 189, 35, 25, 9, 143, 215, 83, 59, 105, 43, 196, 222, 31, 189, 158, 159, 159, 171, 141, 140, 141, 249, 111, 45, 29, 130, 254,
    238, 180, 72, 27, 173, 134, 139, 235, 249, 10, 127, 126, 94, 149, 59, 37, 26, 6, 52, 69, 252, 120, 156, 158, 165, 247, 191, 15, 69, 246, 143, 236, 101, 178, 208, 108, 38, 250, 57, 35,
    218, 148, 23, 66, 29, 168, 32, 235, 1, 173, 55, 111, 57, 40, 44, 17, 225, 45, 246, 70, 124, 123, 34, 188, 117, 56, 183, 55, 132, 92, 55, 124, 183, 51, 164, 243, 102, 55, 236, 151,
    17, 255, 122, 148, 167, 54, 243, 93, 219, 245, 32, 147, 169, 54, 170, 177, 188, 87, 126, 215, 82, 32, 41, 6, 21, 202, 183, 54, 116, 15, 136, 14, 34, 62, 181, 176, 12, 15, 97, 169,
    45, 28, 25, 29, 255, 6, 129, 97, 211, 9, 9, 236, 118, 54, 185, 222, 221, 78, 151, 211, 179, 233, 140, 234, 30, 134, 197, 199, 59, 235, 141, 108, 118, 67, 19, 251, 96, 105, 113, 59,
    175, 144, 99, 240, 212, 238, 225, 120, 108, 157, 243, 123, 230, 246, 182, 50, 188, 107, 225, 218, 6, 80, 166, 229, 120, 150, 66, 119, 242, 190, 59, 243, 98, 252, 102, 58, 112, 58, 31, 110,
    251, 18, 181, 146, 67, 161, 29, 126, 100, 123, 104, 145, 112, 7, 105, 155, 32, 114, 59, 235, 216, 195, 253, 59, 170, 187, 34, 166, 199, 214, 192, 115, 6, 114, 118, 134, 230, 173, 249, 251,
    147, 231, 97, 181, 248, 228, 121, 56, 60, 150, 43, 195, 167, 39, 147, 233, 109, 36, 155, 142, 71, 205, 2, 235, 233, 201, 246, 160, 213, 195, 231, 172, 70, 205, 34, 248, 8, 214, 180, 57,
    114, 85, 38, 189, 214, 71, 174, 166, 208, 180, 136, 7, 208, 126, 81, 255, 52, 234, 113, 37, 215, 100, 186, 128, 87, 72, 173, 234, 157, 158, 52, 135, 166, 246, 94, 167, 168, 21, 101, 153,
    45, 117, 225, 34, 254, 161, 168, 138, 145, 102, 141, 26, 167, 38, 242, 89, 148, 42, 254, 102, 222, 203, 69, 177, 173, 76, 165, 92, 27, 182, 10, 153, 165, 103, 179, 5, 147, 149, 142, 208,
    136, 242, 118, 28, 107, 235, 35, 57, 34, 17, 69, 178, 152, 199, 158, 226, 82, 40, 180, 31, 231, 138, 71, 56, 90, 92, 77, 148, 231, 233, 109, 102, 213, 204, 216, 200, 249, 14, 14, 68,
    32, 114, 106, 236, 179, 56, 181, 17, 127, 9, 63, 206, 84, 241, 214, 160, 198, 165, 87, 118, 156, 41, 75, 52, 120, 240, 99, 14, 184, 150, 231, 69, 170, 178, 0, 46, 69, 192, 71, 197,
    154, 199, 41, 102, 150, 24, 101, 46, 198, 255, 218, 217, 56, 211, 113, 97, 84, 156, 249, 25, 218, 83, 177, 141, 29, 207, 97, 189, 202, 12, 176, 213, 106, 28, 163, 95, 58, 141, 189, 142,
    44, 192, 18, 243, 89, 204, 99, 90, 29, 123, 7, 6, 140, 109, 164, 65, 182, 24, 23, 131, 244, 204, 68, 218, 25, 13, 204, 129, 167, 182, 81, 97, 178, 40, 119, 121, 84, 160, 25, 103,
    216, 99, 173, 243, 152, 135, 126, 166, 150, 167, 94, 197, 70, 185, 50, 69, 1, 254, 145, 104, 177, 3, 53, 156, 46, 198, 200, 137, 125, 17, 27, 29, 231, 46, 54, 30, 120, 22, 51, 96,
    151, 250, 236, 210, 88, 144, 39, 207, 129, 24, 127, 132, 64, 134, 205, 169, 177, 54, 89, 236, 10, 162, 16, 27, 203, 212, 216, 106, 69, 112, 104, 0, 72, 226, 215, 228, 184, 228, 236, 131,
    141, 237, 109, 108, 157, 25, 43, 30, 152, 133, 166, 109, 161, 226, 148, 199, 103, 186, 152, 167, 134, 42, 161, 82, 202, 90, 248, 83, 87, 218, 33, 223, 18, 47, 208, 37, 6, 186, 150, 185,
    145, 55, 66, 16, 107, 73, 2, 157, 249, 113, 12, 194, 88, 176, 59, 197, 197, 34, 141, 7, 138, 122, 20, 36, 65, 93, 198, 35, 121, 33, 51, 36, 11, 174, 20, 56, 146, 196, 16, 59,
    157, 58, 158, 128, 19, 72, 98, 117, 196, 191, 64, 18, 11, 120, 62, 37, 219, 136, 15, 15, 255, 228, 95, 65, 134, 221, 66, 34, 252, 204, 56, 32, 60, 182, 202, 3, 170, 69, 17, 212,
    228, 5, 12, 103, 243, 222, 196, 36, 79, 110, 208, 81, 72, 64, 110, 95, 106, 111, 51, 69, 114, 218, 212, 141, 201, 115, 77, 60, 108, 145, 146, 216, 14, 164, 65, 21, 203, 250, 184, 104,
    240, 0, 116, 188, 138, 45, 123, 145, 9, 30, 142, 253, 1, 173, 33, 210, 148, 22, 235, 34, 72, 164, 73, 21, 196, 50, 7, 47, 209, 99, 30, 148, 234, 40, 59, 90, 65, 212, 128, 184,
    28, 253, 201, 131, 95, 125, 204, 51, 119, 109, 10, 129, 46, 243, 76, 71, 252, 147, 110, 130, 192, 224, 146, 1, 61, 33, 33, 230, 37, 4, 197, 145, 163, 218, 71, 108, 134, 226, 8, 202,
    106, 75, 153, 128, 198, 197, 25, 104, 156, 105, 15, 237, 202, 82, 57, 129, 142, 235, 72, 249, 21, 144, 134, 234, 89, 72, 174, 163, 132, 0, 125, 170, 166, 55, 54, 46, 172, 161, 98, 176,
    62, 174, 232, 18, 101, 22, 143, 108, 214, 82, 62, 81, 28, 60, 49, 252, 51, 30, 242, 174, 35, 143, 164, 12, 84, 139, 72, 108, 249, 77, 169, 243, 128, 107, 34, 64, 79, 217, 160, 138,
    139, 84, 151, 60, 145, 151, 127, 162, 248, 41, 205, 70, 238, 129, 188, 21, 40, 57, 203, 200, 197, 72, 117, 17, 126, 228, 25, 195, 158, 58, 42, 229, 85, 234, 69, 176, 74, 195, 195, 150,
    241, 23, 52, 214, 164, 164, 32, 250, 2, 58, 65, 44, 105, 99, 160, 123, 164, 71, 86, 204, 28, 209, 83, 129, 79, 145, 205, 81, 140, 148, 241, 42, 195, 21, 37, 29, 100, 1, 184, 56,
    79, 213, 36, 13, 157, 96, 67, 109, 117, 69, 86, 162, 207, 134, 140, 226, 175, 96, 205, 3, 103, 65, 198, 49, 237, 2, 30, 114, 148, 202, 97, 137, 168, 88, 60, 230, 216, 231, 208, 14,
    66, 231, 121, 194, 41, 115, 20, 15, 0, 227, 41, 209, 60, 52, 80, 58, 99, 114, 128, 128, 44, 106, 230, 229, 146, 227, 129, 5, 20, 208, 162, 96, 78, 198, 179, 39, 192, 208, 66, 96,
    114, 74, 42, 200, 154, 91, 214, 160, 89, 200, 227, 204, 26, 138, 45, 13, 18, 155, 21, 251, 27, 243, 156, 99, 42, 8, 229, 7, 60, 200, 211, 43, 144, 151, 234, 147, 210, 64, 65, 250,
    96, 196, 210, 194, 3, 55, 35, 215, 76, 147, 17, 96, 33, 200, 87, 0, 140, 143, 138, 75, 252, 194, 194, 197, 180, 126, 57, 140, 4, 76, 139, 7, 210, 89, 206, 222, 0, 243, 180, 80,
    189, 112, 124, 236, 239, 205, 248, 204, 149, 78, 30, 226, 197, 205, 172, 26, 49, 12, 174, 39, 147, 232, 121, 203, 87, 24, 74, 140, 47, 138, 82, 123, 64, 5, 113, 195, 69, 4, 89, 206,
    171, 37, 245, 77, 206, 51, 168, 229, 55, 40, 114, 145, 69, 38, 135, 5, 5, 179, 32, 99, 138, 26, 13, 251, 76, 83, 205, 19, 130, 243, 152, 71, 3, 123, 63, 243, 222, 137, 201, 7,
    179, 193, 48, 170, 12, 164, 101, 140, 178, 196, 149, 189, 138, 233, 25, 160, 180, 176, 60, 166, 212, 41, 84, 5, 194, 25, 46, 98, 14, 209, 64, 76, 167, 165, 225, 6, 208, 116, 150, 129,
    153, 144, 131, 140, 218, 13, 83, 174, 41, 126, 224, 38, 216, 146, 163, 235, 32, 187, 83, 170, 204, 12, 13, 211, 218, 87, 160, 88, 230, 175, 32, 102, 60, 72, 89, 103, 47, 120, 98, 88,
    22, 21, 138, 86, 87, 208, 79, 169, 221, 5, 130, 28, 176, 193, 102, 227, 28, 166, 191, 224, 249, 218, 22, 21, 60, 28, 164, 201, 32, 239, 41, 229, 85, 129, 165, 6, 63, 62, 79, 105,
    119, 41, 26, 144, 12, 99, 82, 125, 165, 139, 130, 174, 172, 164, 191, 224, 159, 192, 166, 200, 40, 55, 134, 140, 1, 239, 34, 202, 104, 88, 33, 77, 153, 189, 132, 182, 165, 51, 216, 103,
    99, 75, 106, 146, 104, 19, 107, 192, 76, 249, 12, 162, 144, 209, 107, 164, 52, 161, 60, 197, 12, 78, 64, 93, 242, 52, 65, 55, 19, 175, 102, 175, 44, 207, 10, 46, 74, 88, 116, 134,
    69, 77, 79, 105, 160, 21, 207, 32, 119, 134, 102, 45, 92, 26, 245, 51, 180, 7, 57, 37, 217, 203, 159, 80, 87, 83, 63, 66, 72, 64, 147, 226, 61, 183, 39, 144, 254, 144, 37, 170,
    107, 12, 246, 81, 94, 161, 80, 17, 69, 28, 22, 16, 166, 29, 166, 215, 81, 172, 33, 106, 25, 47, 212, 119, 20, 133, 198, 128, 50, 180, 203, 208, 83, 112, 173, 128, 175, 132, 152, 211,
    10, 21, 108, 195, 64, 113, 96, 130, 129, 61, 60, 170, 47, 224, 85, 121, 142, 58, 152, 153, 66, 147, 120, 116, 35, 200, 167, 9, 14, 41, 60, 151, 26, 214, 155, 254, 143, 6, 153, 190,
    143, 61, 45, 72, 8, 128, 22, 231, 97, 232, 16, 49, 106, 196, 157, 3, 255, 149, 215, 49, 67, 9, 208, 212, 241, 120, 106, 100, 226, 154, 66, 195, 224, 206, 89, 57, 207, 33, 165, 134,
    49, 15, 181, 58, 162, 188, 0, 113, 235, 115, 198, 58, 90, 148, 64, 46, 13, 45, 37, 193, 191, 0, 229, 64, 52, 152, 98, 224, 74, 162, 170, 98, 125, 231, 117, 118, 107, 83, 51, 3,
    226, 36, 30, 202, 103, 233, 88, 163, 243, 25, 141, 25, 36, 204, 137, 38, 88, 157, 205, 200, 85, 79, 245, 240, 116, 233, 48, 228, 166, 228, 73, 126, 148, 40, 219, 176, 8, 122, 6, 159,
    142, 82, 153, 73, 51, 113, 172, 114, 9, 108, 130, 114, 208, 245, 140, 225, 122, 192, 17, 180, 227, 242, 56, 215, 20, 109, 122, 48, 4, 98, 33, 244, 98, 3, 48, 129, 144, 117, 186, 104,
    154, 20, 45, 39, 124, 195, 92, 106, 154, 64, 148, 69, 152, 228, 161, 136, 6, 82, 148, 33, 37, 135, 247, 50, 40, 14, 67, 157, 201, 77, 204, 248, 6, 20, 6, 165, 83, 137, 171, 52,
    93, 146, 156, 210, 173, 221, 107, 43, 134, 218, 58, 40, 62, 188, 2, 72, 170, 74, 4, 2, 10, 28, 106, 46, 129, 118, 208, 50, 48, 21, 254, 24, 222, 57, 34, 114, 188, 0, 85, 168,
    182, 207, 103, 38, 231, 65, 225, 233, 152, 140, 54, 150, 1, 7, 132, 16, 90, 225, 53, 5, 18, 58, 14, 213, 6, 231, 97, 174, 89, 144, 220, 82, 234, 115, 244, 15, 125, 137, 154, 139,
    88, 121, 155, 195, 50, 25, 5, 167, 226, 161, 159, 176, 254, 224, 87, 202, 19, 238, 24, 14, 67, 131, 60, 188, 47, 163, 83, 74, 5, 60, 176, 136, 132, 147, 216, 9, 98, 74, 85, 131,
    197, 244, 180, 60, 114, 208, 183, 68, 105, 176, 170, 177, 73, 9, 38, 191, 226, 241, 125, 108, 63, 151, 64, 137, 69, 25, 133, 33, 14, 161, 25, 231, 86, 54, 137, 168, 98, 30, 253, 15,
    249, 154, 81, 181, 45, 59, 132, 254, 140, 41, 233, 20, 27, 122, 90, 202, 24, 207, 65, 135, 20, 48, 36, 125, 107, 114, 147, 142, 41, 190, 168, 73, 190, 81, 161, 196, 137, 34, 86, 201,
    37, 88, 163, 17, 119, 34, 232, 54, 127, 237, 104, 181, 50, 7, 99, 15, 152, 136, 200, 60, 109, 157, 208, 65, 64, 210, 96, 51, 58, 64, 164, 133, 0, 154, 71, 187, 203, 111, 136, 181,
    41, 58, 153, 25, 195, 46, 69, 52, 183, 20, 90, 234, 166, 65, 208, 9, 29, 247, 66, 110, 237, 155, 24, 31, 34, 11, 153, 129, 144, 137, 114, 0, 113, 88, 43, 202, 12, 108, 25, 158,
    12, 143, 219, 71, 227, 80, 38, 70, 245, 184, 0, 83, 136, 6, 53, 5, 206, 135, 234, 205, 18, 105, 105, 210, 148, 95, 56, 144, 223, 224, 42, 96, 148, 49, 238, 30, 35, 56, 135, 61,
    164, 203, 34, 103, 50, 176, 143, 124, 132, 204, 225, 151, 241, 26, 8, 71, 5, 137, 124, 96, 78, 182, 102, 14, 35, 121, 64, 224, 249, 147, 248, 117, 38, 187, 69, 12, 1, 1, 204, 27,
    98, 65, 51, 212, 56, 216, 73, 58, 21, 18, 81, 243, 200, 119, 197, 88, 153, 194, 139, 48, 41, 53, 162, 43, 114, 178, 60, 141, 39, 226, 49, 8, 11, 195, 246, 168, 72, 161, 138, 6,
    129, 84, 248, 13, 102, 155, 95, 151, 16, 243, 104, 56, 24, 105, 46, 146, 197, 147, 218, 225, 98, 96, 148, 24, 29, 241, 39, 12, 173, 44, 63, 213, 224, 199, 18, 43, 240, 91, 6, 32,
    24, 191, 142, 64, 77, 131, 80, 208, 60, 192, 185, 68, 66, 85, 176, 187, 244, 60, 112, 52, 10, 191, 33, 208, 178, 74, 34, 9, 144, 85, 211, 194, 135, 75, 195, 24, 134, 243, 38, 31,
    27, 134, 136, 136, 138, 56, 146, 97, 144, 129, 210, 78, 130, 120, 35, 46, 40, 230, 241, 249, 134, 161, 55, 110, 97, 7, 35, 250, 39, 218, 129, 98, 29, 15, 84, 19, 254, 219, 31, 15,
    112, 248, 25, 198, 173, 211, 201, 168, 189, 127, 169, 25, 199, 182, 147, 78, 79, 56, 157, 183, 41, 189, 222, 66, 211, 148, 92, 63, 34, 198, 216, 73, 225, 20, 200, 233, 151, 139, 242, 34,
    42, 231, 19, 57, 207, 1, 3, 219, 69, 117, 114, 182, 192, 240, 248, 186, 156, 239, 41, 254, 229, 244, 234, 180, 94, 176, 132, 188, 11, 206, 215, 91, 194, 210, 122, 212, 231, 217, 83, 3,
    57, 123, 10, 200, 163, 54, 250, 112, 125, 122, 50, 229, 162, 104, 56, 22, 95, 142, 190, 2, 126, 155, 55, 202, 155, 246, 195, 128, 62, 42, 49, 228, 191, 94, 141, 228, 12, 171, 97, 196,
    223, 228, 226, 231, 30, 15, 198, 10, 111, 115, 182, 95, 217, 151, 151, 248, 7, 128, 48, 225, 80, 254, 121, 232, 126, 120, 104, 136, 208, 61, 59, 172, 129, 212, 107, 47, 169, 70, 205, 105,
    15, 237, 217, 129, 238, 102, 230, 118, 78, 239, 172, 254, 41, 146, 61, 174, 189, 54, 164, 157, 76, 243, 88, 166, 125, 44, 211, 109, 50, 119, 139, 236, 155, 200, 219, 151, 191, 174, 121, 221,
    238, 190, 76, 117, 237, 20, 220, 76, 127, 157, 170, 79, 132, 71, 187, 112, 81, 191, 179, 192, 249, 56, 245, 56, 79, 178, 91, 227, 205, 219, 63, 61, 97, 114, 165, 61, 113, 226, 45, 60,
    142, 205, 122, 205, 52, 75, 218, 158, 101, 225, 125, 107, 38, 166, 9, 150, 131, 14, 169, 243, 113, 97, 207, 162, 176, 249, 111, 196, 201, 160, 61, 250, 196, 184, 154, 113, 78, 162, 232, 37,
    249, 109, 144, 232, 69, 196, 47, 75, 100, 8, 5, 173, 79, 10, 237, 135, 17, 252, 117, 66, 99, 138, 160, 19, 37, 244, 144, 97, 69, 130, 193, 83, 228, 138, 52, 209, 8, 176, 95, 192,
    148, 160, 172, 165, 179, 49, 137, 47, 236, 16, 163, 63, 159, 100, 69, 17, 185, 60, 77, 76, 238, 144, 96, 211, 36, 99, 204, 151, 231, 9, 198, 144, 168, 131, 78, 201, 151, 89, 224, 103,
    146, 44, 20, 201, 146, 148, 120, 100, 184, 22, 158, 9, 121, 162, 249, 109, 25, 36, 56, 149, 74, 157, 34, 177, 140, 2, 50, 193, 96, 40, 9, 176, 37, 28, 43, 73, 121, 222, 52, 109,
    115, 140, 220, 36, 167, 73, 81, 136, 221, 227, 7, 98, 154, 132, 156, 9, 220, 15, 168, 164, 60, 82, 104, 0, 137, 130, 37, 254, 252, 66, 7, 199, 133, 170, 64, 81, 54, 98, 248, 157,
    26, 78, 179, 104, 16, 203, 161, 142, 67, 79, 84, 138, 120, 211, 37, 133, 73, 135, 32, 143, 65, 81, 21, 241, 51, 32, 153, 46, 134, 59, 116, 5, 157, 209, 21, 111, 147, 52, 213, 168,
    157, 169, 4, 180, 193, 184, 41, 129, 53, 5, 141, 249, 85, 17, 79, 242, 248, 4, 94, 99, 72, 199, 153, 56, 58, 113, 157, 202, 183, 103, 64, 99, 80, 195, 51, 252, 112, 160, 96, 170,
    134, 145, 35, 64, 7, 26, 103, 38, 209, 25, 234, 56, 80, 146, 97, 17, 124, 17, 40, 90, 16, 199, 34, 227, 23, 78, 24, 206, 36, 69, 10, 122, 89, 20, 193, 112, 21, 174, 129, 252,
    26, 182, 113, 122, 77, 87, 130, 76, 212, 183, 184, 22, 172, 15, 107, 157, 72, 76, 154, 242, 115, 36, 128, 137, 224, 56, 81, 136, 146, 172, 210, 73, 145, 25, 38, 240, 219, 60, 105, 72,
    0, 77, 95, 112, 150, 34, 41, 16, 63, 74, 74, 193, 34, 236, 10, 67, 160, 28, 25, 14, 141, 104, 200, 141, 145, 241, 10, 240, 196, 245, 21, 194, 44, 16, 145, 67, 53, 176, 211, 43,
    198, 158, 44, 161, 201, 63, 92, 83, 150, 64, 171, 94, 5, 225, 80, 252, 126, 82, 6, 234, 43, 14, 218, 152, 174, 81, 34, 96, 2, 212, 36, 7, 97, 151, 46, 248, 109, 20, 1, 203,
    146, 175, 56, 124, 3, 209, 115, 129, 47, 95, 99, 42, 140, 228, 128, 120, 168, 73, 26, 219, 92, 39, 24, 107, 1, 159, 44, 65, 203, 160, 87, 102, 133, 201, 218, 75, 191, 153, 0, 2,
    50, 0, 68, 2, 135, 72, 47, 56, 107, 129, 254, 250, 144, 146, 147, 198, 236, 4, 131, 22, 136, 10, 34, 170, 225, 3, 186, 190, 142, 84, 34, 62, 52, 205, 37, 253, 133, 60, 51, 12,
    131, 22, 160, 8, 195, 57, 8, 56, 66, 6, 62, 102, 148, 234, 140, 159, 36, 74, 165, 100, 129, 81, 8, 41, 7, 105, 100, 118, 129, 241, 11, 66, 193, 36, 15, 143, 25, 165, 62, 221,
    150, 246, 12, 239, 82, 126, 10, 71, 26, 131, 14, 51, 123, 216, 197, 160, 183, 241, 171, 215, 45, 139, 213, 188, 159, 215, 24, 185, 157, 253, 43, 167, 15, 206, 12, 21, 139, 185, 181, 190,
    135, 119, 130, 236, 183, 140, 237, 23, 240, 58, 78, 103, 179, 225, 124, 107, 23, 13, 227, 15, 78, 21, 121, 206, 38, 63, 196, 124, 207, 91, 134, 77, 147, 7, 54, 194, 156, 110, 78, 132,
    139, 194, 231, 209, 146, 36, 105, 121, 128, 176, 57, 104, 243, 78, 43, 33, 181, 183, 34, 208, 21, 211, 233, 143, 90, 239, 10, 6, 207, 222, 84, 12, 176, 59, 155, 47, 158, 54, 205, 30,
    108, 62, 151, 42, 214, 54, 95, 238, 187, 51, 235, 156, 15, 108, 34, 39, 49, 243, 141, 201, 151, 189, 144, 81, 123, 127, 252, 200, 68, 221, 77, 239, 35, 89, 65, 104, 39, 242, 140, 234,
    144, 186, 157, 121, 185, 210, 70, 102, 227, 98, 12, 73, 227, 172, 215, 158, 147, 209, 80, 85, 243, 210, 111, 228, 231, 79, 117, 196, 62, 158, 60, 63, 107, 122, 217, 241, 157, 173, 195, 18,
    63, 236, 57, 255, 115, 188, 228, 249, 57, 198, 3, 230, 73, 94, 18, 238, 1, 106, 4, 253, 121, 193, 111, 168, 201, 200, 26, 142, 43, 77, 233, 32, 97, 87, 248, 77, 181, 130, 159, 122,
    67, 2, 253, 21, 60, 129, 243, 252, 110, 152, 216, 81, 235, 96, 105, 48, 216, 228, 103, 168, 196, 63, 242, 35, 75, 28, 88, 25, 96, 196, 54, 188, 229, 39, 155, 216, 70, 209, 216, 4,
    250, 36, 103, 97, 19, 139, 198, 55, 58, 14, 108, 114, 151, 24, 218, 80, 250, 70, 126, 226, 140, 246, 16, 170, 47, 229, 97, 227, 77, 176, 213, 58, 184, 185, 156, 246, 86, 204, 1, 12,
    84, 227, 79, 233, 31, 252, 182, 78, 22, 44, 4, 124, 64, 211, 44, 16, 148, 128, 221, 193, 0, 250, 128, 87, 65, 17, 179, 226, 87, 209, 101, 184, 128, 72, 12, 120, 78, 119, 2, 147,
    174, 232, 243, 44, 138, 211, 231, 109, 168, 68, 138, 193, 0, 179, 143, 0, 47, 30, 51, 43, 146, 12, 113, 4, 237, 165, 67, 159, 98, 23, 168, 150, 242, 219, 114, 128, 93, 240, 203, 116,
    70, 70, 45, 47, 56, 147, 193, 143, 87, 69, 48, 164, 128, 64, 231, 6, 164, 61, 167, 249, 64, 1, 79, 87, 70, 111, 231, 188, 35, 125, 16, 46, 144, 202, 160, 27, 156, 54, 236, 57,
    236, 157, 163, 145, 179, 57, 186, 149, 113, 192, 150, 228, 198, 13, 119, 49, 122, 45, 150, 63, 229, 156, 50, 204, 45, 237, 254, 43, 241, 148, 57, 76, 170, 70, 68, 147, 114, 192, 138, 43,
    167, 12, 141, 165, 103, 80, 244, 51, 184, 19, 107, 14, 31, 81, 52, 37, 12, 39, 9, 149, 227, 39, 225, 154, 54, 184, 216, 100, 225, 101, 83, 248, 70, 157, 121, 80, 7, 104, 160, 11,
    116, 158, 16, 32, 116, 194, 114, 202, 49, 133, 39, 42, 10, 186, 68, 250, 114, 52, 146, 57, 86, 97, 2, 168, 3, 137, 177, 168, 91, 120, 193, 12, 190, 92, 101, 193, 191, 33, 68, 144,
    233, 41, 208, 75, 112, 121, 37, 150, 156, 75, 63, 86, 129, 129, 242, 253, 61, 96, 153, 210, 81, 23, 18, 200, 188, 16, 31, 34, 95, 96, 131, 23, 180, 148, 41, 147, 23, 129, 58, 252,
    76, 156, 4, 7, 138, 129, 23, 63, 28, 136, 0, 80, 226, 34, 102, 113, 42, 59, 132, 126, 100, 56, 63, 153, 6, 182, 0, 137, 240, 144, 115, 86, 41, 19, 63, 232, 40, 27, 166, 201,
    2, 219, 114, 8, 175, 133, 48, 166, 116, 107, 22, 145, 4, 253, 182, 245, 244, 202, 25, 48, 182, 16, 7, 78, 206, 144, 74, 156, 147, 180, 142, 50, 232, 132, 142, 153, 163, 191, 38, 62,
    74, 89, 233, 155, 43, 108, 83, 2, 50, 111, 141, 68, 7, 235, 54, 90, 30, 61, 165, 167, 53, 194, 87, 66, 123, 37, 56, 122, 78, 38, 128, 246, 2, 69, 129, 91, 242, 25, 68, 42,
    146, 17, 202, 21, 226, 153, 29, 87, 33, 208, 114, 198, 73, 157, 77, 46, 91, 38, 150, 235, 250, 187, 18, 35, 190, 92, 180, 46, 15, 126, 220, 168, 64, 251, 204, 139, 47, 87, 38, 16,
    158, 196, 83, 34, 254, 204, 13, 81, 167, 10, 49, 39, 72, 36, 228, 95, 63, 82, 3, 183, 165, 211, 53, 47, 154, 198, 24, 244, 133, 210, 1, 44, 196, 196, 248, 237, 99, 190, 227, 203,
    183, 231, 218, 61, 238, 199, 195, 11, 245, 226, 243, 182, 245, 194, 17, 118, 235, 209, 238, 214, 91, 54, 71, 58, 172, 22, 239, 163, 242, 2, 227, 46, 169, 214, 248, 186, 29, 223, 104, 254,
    246, 206, 113, 235, 26, 255, 171, 58, 198, 214, 233, 183, 13, 57, 198, 205, 252, 197, 54, 158, 106, 191, 135, 18, 8, 212, 184, 208, 157, 23, 84, 162, 135, 175, 181, 244, 62, 76, 75, 33,
    210, 248, 102, 177, 168, 230, 171, 240, 226, 211, 195, 21, 126, 238, 190, 95, 211, 90, 238, 59, 212, 46, 184, 24, 195, 159, 246, 250, 190, 207, 10, 29, 229, 112, 66, 165, 248, 195, 245, 218,
    113, 193, 185, 228, 219, 56, 203, 252, 101, 140, 161, 194, 91, 150, 184, 140, 245, 207, 87, 42, 206, 93, 170, 110, 145, 241, 50, 133, 212, 191, 117, 121, 183, 38, 75, 71, 234, 231, 215, 142,
    107, 205, 72, 100, 201, 75, 180, 182, 167, 32, 65, 160, 193, 136, 13, 62, 2, 29, 117, 9, 253, 231, 215, 48, 231, 173, 38, 129, 212, 1, 216, 31, 209, 164, 138, 82, 4, 234, 221, 146,
    205, 195, 37, 138, 222, 178, 197, 151, 120, 248, 188, 83, 34, 212, 250, 249, 138, 109, 196, 46, 43, 46, 217, 236, 91, 146, 227, 229, 67, 74, 10, 86, 132, 228, 50, 253, 40, 164, 84, 189,
    124, 208, 161, 230, 97, 13, 10, 101, 9, 234, 150, 101, 247, 66, 74, 165, 79, 252, 228, 211, 111, 5, 9, 253, 63, 216, 39, 196, 48, 41, 87, 199, 92, 73, 15, 231, 155, 133, 167, 168,
    121, 184, 116, 24, 150, 63, 200, 225, 148, 236, 91, 131, 216, 161, 147, 19, 55, 57, 47, 247, 230, 240, 225, 150, 173, 181, 45, 231, 67, 157, 19, 195, 247, 5, 21, 149, 239, 128, 214, 173,
    209, 193, 174, 142, 54, 175, 26, 29, 204, 144, 119, 159, 0, 228, 244, 101, 115, 116, 89, 244, 231, 47, 63, 220, 220, 166, 214, 31, 215, 7, 157, 52, 26, 250, 17, 85, 191, 224, 193, 92,
    17, 237, 253, 71, 87, 226, 57, 95, 31, 81, 105, 115, 244, 249, 117, 115, 238, 215, 131, 249, 180, 238, 172, 90, 231, 112, 240, 223, 220, 6, 242, 165, 189, 95, 101, 4, 159, 98, 248, 12,
    3, 86, 254, 180, 13, 159, 225, 39, 130, 139, 44, 191, 140, 83, 89, 196, 144, 5, 163, 176, 231, 130, 235, 130, 238, 45, 162, 102, 164, 203, 2, 73, 179, 23, 128, 83, 254, 233, 204, 165,
    177, 75, 219, 57, 178, 123, 193, 231, 175, 52, 163, 79, 167, 93, 39, 143, 91, 47, 34, 53, 139, 17, 55, 116, 107, 241, 91, 194, 97, 62, 191, 13, 155, 11, 101, 80, 16, 68, 128, 159,
    107, 249, 34, 180, 110, 214, 237, 228, 51, 205, 80, 42, 174, 142, 148, 237, 172, 56, 60, 168, 219, 221, 110, 112, 181, 7, 26, 181, 219, 13, 130, 5, 82, 192, 232, 65, 63, 216, 139, 72,
    189, 66, 23, 184, 126, 186, 211, 69, 89, 112, 67, 104, 231, 210, 207, 59, 84, 65, 144, 31, 5, 24, 93, 18, 70, 153, 131, 9, 81, 187, 184, 114, 41, 196, 223, 238, 118, 34, 10, 25,
    250, 50, 117, 157, 134, 162, 208, 80, 212, 233, 0, 105, 102, 164, 3, 209, 3, 70, 8, 150, 154, 209, 35, 23, 208, 219, 89, 210, 183, 135, 204, 227, 194, 191, 146, 165, 143, 54, 216, 140,
    203, 92, 32, 105, 186, 195, 5, 202, 140, 33, 27, 246, 116, 128, 155, 214, 244, 237, 174, 52, 69, 129, 163, 81, 23, 36, 231, 67, 205, 108, 79, 7, 2, 150, 154, 235, 140, 187, 29, 16,
    246, 236, 97, 155, 150, 21, 43, 187, 211, 3, 17, 98, 115, 185, 219, 3, 34, 47, 194, 116, 187, 79, 144, 68, 152, 254, 233, 181, 150, 66, 41, 152, 74, 197, 113, 129, 174, 92, 214, 226,
    198, 147, 144, 16, 18, 185, 38, 23, 30, 254, 233, 9, 166, 249, 77, 99, 66, 126, 11, 195, 204, 239, 35, 241, 139, 78, 210, 86, 179, 140, 3, 43, 213, 124, 231, 233, 244, 164, 190, 150,
    195, 158, 100, 87, 238, 232, 124, 209, 172, 244, 84, 147, 141, 109, 62, 121, 30, 138, 236, 22, 93, 158, 114, 169, 38, 90, 190, 95, 174, 170, 171, 109, 161, 231, 161, 129, 39, 27, 215, 48,
    73, 38, 111, 238, 53, 223, 113, 218, 93, 82, 90, 31, 124, 68, 180, 247, 188, 140, 215, 52, 191, 55, 39, 188, 166, 247, 136, 177, 110, 191, 42, 215, 52, 212, 78, 218, 59, 93, 214, 125,
    225, 33, 226, 199, 91, 118, 211, 30, 142, 9, 118, 94, 51, 57, 217, 6, 253, 166, 53, 191, 35, 247, 29, 139, 172, 21, 191, 220, 174, 24, 252, 183, 163, 216, 167, 217, 255, 246, 232, 32,
    60, 180, 227, 89, 78, 193, 40, 155, 240, 131, 246, 69, 98, 185, 131, 143, 67, 195, 36, 227, 213, 194, 242, 112, 220, 56, 230, 74, 103, 226, 249, 173, 123, 142, 65, 116, 150, 112, 216, 153,
    216, 87, 169, 231, 82, 44, 70, 152, 99, 207, 164, 132, 214, 57, 73, 249, 89, 249, 80, 72, 110, 76, 66, 133, 49, 54, 201, 227, 52, 177, 82, 49, 150, 220, 2, 80, 52, 219, 116, 49,
    231, 113, 228, 123, 226, 136, 15, 19, 104, 173, 150, 4, 196, 174, 177, 201, 220, 88, 49, 179, 96, 53, 159, 164, 64, 44, 182, 46, 41, 112, 253, 121, 171, 69, 235, 9, 216, 205, 91, 53,
    255, 151, 233, 90, 96, 208, 107, 34, 103, 242, 132, 91, 101, 53, 112, 79, 249, 3, 196, 45, 183, 175, 162, 27, 105, 46, 116, 80, 137, 225, 199, 211, 139, 216, 21, 248, 225, 100, 73, 92,
    152, 132, 91, 107, 44, 158, 185, 48, 229, 152, 5, 18, 209, 48, 186, 152, 51, 93, 220, 172, 135, 202, 92, 108, 136, 57, 51, 196, 201, 42, 214, 48, 164, 147, 227, 109, 206, 4, 112, 21,
    193, 107, 194, 173, 28, 137, 44, 205, 39, 57, 184, 133, 68, 12, 214, 19, 110, 45, 245, 137, 125, 91, 200, 150, 136, 134, 184, 153, 16, 151, 255, 47, 119, 228, 128, 51, 62, 158, 114, 64,
    33, 97, 122, 36, 233, 248, 255, 146, 19, 8, 122, 28, 164, 39, 146, 109, 120, 146, 43, 141, 116, 218, 188, 140, 243, 52, 73, 199, 222, 163, 99, 62, 77, 114, 89, 2, 201, 99, 206, 71,
    65, 6, 51, 74, 3, 23, 167, 200, 16, 118, 189, 144, 68, 13, 177, 178, 50, 17, 105, 49, 140, 0, 218, 92, 127, 139, 56, 231, 194, 125, 74, 9, 183, 45, 229, 148, 178, 212, 178, 21,
    175, 121, 191, 110, 66, 106, 178, 141, 88, 106, 74, 35, 177, 39, 162, 104, 132, 59, 115, 164, 38, 90, 49, 49, 107, 166, 210, 138, 145, 189, 201, 164, 58, 168, 149, 112, 127, 40, 80, 146,
    27, 112, 77, 188, 10, 200, 22, 131, 59, 220, 145, 161, 81, 46, 45, 80, 71, 26, 36, 86, 113, 104, 143, 109, 147, 79, 182, 105, 155, 95, 167, 231, 142, 69, 180, 67, 190, 103, 172, 78,
    94, 107, 174, 224, 68, 90, 250, 203, 106, 100, 33, 167, 73, 99, 43, 226, 34, 50, 34, 25, 236, 78, 202, 162, 82, 34, 167, 34, 177, 4, 228, 41, 114, 2, 4, 10, 149, 103, 145, 103,
    17, 168, 24, 253, 20, 41, 198, 31, 10, 93, 36, 66, 23, 81, 232, 34, 17, 186, 136, 66, 23, 81, 232, 34, 10, 93, 68, 161, 139, 68, 232, 100, 53, 212, 49, 139, 19, 126, 220, 224,
    18, 81, 232, 34, 17, 58, 46, 243, 101, 172, 155, 69, 89, 194, 29, 98, 194, 47, 252, 20, 5, 97, 242, 14, 50, 79, 133, 7, 135, 137, 21, 24, 70, 153, 103, 3, 162, 1, 130, 86,
    208, 128, 128, 151, 104, 128, 224, 37, 26, 32, 104, 137, 6, 8, 90, 65, 1, 2, 94, 54, 104, 66, 20, 84, 0, 104, 137, 2, 4, 180, 160, 1, 94, 116, 1, 252, 76, 124, 208, 5,
    26, 164, 160, 10, 109, 67, 177, 221, 237, 240, 240, 157, 181, 109, 148, 191, 245, 123, 205, 6, 135, 245, 52, 199, 118, 82, 168, 253, 50, 83, 99, 255, 219, 41, 123, 172, 127, 251, 229, 174,
    143, 153, 17, 50, 173, 229, 18, 243, 96, 185, 164, 101, 196, 214, 75, 0, 246, 204, 158, 69, 235, 195, 26, 214, 187, 46, 4, 216, 209, 173, 128, 91, 2, 222, 45, 28, 116, 153, 76, 235,
    231, 243, 114, 94, 183, 76, 151, 5, 45, 83, 110, 194, 247, 160, 169, 45, 74, 206, 102, 166, 69, 212, 92, 4, 34, 231, 159, 51, 171, 57, 241, 141, 136, 73, 86, 44, 57, 53, 218, 92,
    85, 40, 68, 190, 67, 83, 181, 184, 143, 92, 201, 98, 42, 151, 65, 211, 34, 151, 162, 233, 206, 229, 77, 142, 86, 241, 148, 114, 230, 24, 101, 155, 71, 105, 128, 187, 181, 128, 148, 167,
    21, 229, 222, 77, 176, 55, 229, 54, 34, 104, 92, 198, 205, 119, 57, 87, 117, 179, 128, 106, 192, 84, 208, 68, 16, 198, 85, 111, 79, 83, 105, 85, 254, 185, 131, 125, 225, 44, 245, 250,
    26, 58, 83, 24, 234, 126, 64, 212, 64, 222, 100, 67, 21, 196, 134, 179, 192, 44, 137, 8, 146, 191, 225, 254, 13, 77, 11, 68, 15, 42, 200, 185, 225, 240, 132, 186, 37, 115, 157, 13,
    165, 120, 13, 109, 27, 200, 59, 55, 63, 89, 159, 39, 46, 213, 63, 195, 225, 54, 149, 46, 213, 191, 173, 17, 109, 161, 125, 43, 64, 254, 173, 73, 139, 91, 57, 40, 223, 60, 170, 184,
    149, 121, 27, 55, 53, 218, 101, 195, 253, 1, 169, 223, 121, 7, 175, 9, 190, 30, 8, 122, 39, 66, 218, 121, 105, 167, 105, 106, 39, 245, 208, 182, 150, 112, 10, 35, 35, 221, 112, 50,
    244, 131, 247, 153, 78, 55, 103, 77, 70, 113, 212, 156, 50, 30, 80, 6, 232, 206, 105, 150, 167, 114, 224, 103, 131, 107, 28, 253, 239, 255, 5, 251, 110, 252, 206, 108, 109, 251, 77, 188,
    160, 152, 157, 148, 135, 138, 217, 57, 207, 254, 193, 118, 151, 205, 91, 123, 123, 134, 211, 107, 165, 228, 81, 22, 141, 174, 154, 238, 226, 220, 71, 46, 251, 185, 66, 137, 37, 196, 47, 48,
    184, 216, 168, 229, 107, 53, 212, 16, 83, 133, 136, 12, 158, 5, 146, 58, 132, 245, 52, 67, 238, 76, 24, 194, 0, 234, 237, 207, 37, 26, 134, 151, 149, 108, 37, 41, 241, 166, 20, 253,
    160, 166, 196, 176, 5, 120, 164, 60, 246, 98, 44, 105, 151, 215, 63, 75, 249, 29, 174, 51, 134, 252, 185, 13, 53, 134, 38, 24, 92, 180, 198, 109, 37, 49, 127, 228, 238, 37, 219, 229,
    86, 192, 36, 27, 42, 73, 150, 82, 241, 166, 20, 226, 184, 128, 118, 40, 179, 201, 220, 182, 211, 160, 29, 154, 144, 228, 225, 6, 144, 252, 172, 113, 0, 214, 68, 110, 184, 65, 78, 126,
    150, 130, 255, 58, 93, 48, 223, 244, 211, 138, 131, 7, 13, 226, 13, 13, 228, 71, 176, 126, 33, 196, 225, 250, 150, 7, 92, 184, 241, 140, 215, 64, 235, 159, 91, 219, 245, 95, 91, 110,
    100, 25, 90, 162, 226, 199, 208, 223, 33, 255, 8, 16, 214, 114, 136, 64, 130, 215, 165, 132, 21, 32, 124, 78, 103, 159, 164, 179, 156, 65, 28, 127, 198, 142, 177, 45, 80, 231, 149, 193,
    244, 144, 175, 38, 36, 118, 22, 111, 139, 196, 77, 25, 201, 15, 55, 40, 49, 84, 75, 169, 24, 42, 13, 165, 82, 106, 135, 169, 125, 105, 232, 69, 199, 100, 35, 27, 123, 192, 180, 131,
    180, 186, 228, 158, 23, 4, 217, 210, 202, 11, 11, 211, 12, 10, 27, 68, 97, 232, 75, 120, 160, 19, 230, 195, 182, 199, 66, 138, 231, 23, 29, 123, 178, 209, 13, 49, 35, 205, 199, 185,
    14, 216, 145, 231, 225, 237, 188, 231, 60, 218, 245, 244, 255, 0, 215, 193, 152, 93, 11, 142, 0, 0
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
