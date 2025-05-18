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
    It provides a beautiful web interface for firmware updates.

    The main source file.

*/

#include "PrettyOTA.h"

// Static variables
Stream* PrettyOTA::m_SerialMonitorStream = nullptr;
bool    PrettyOTA::m_DefaultCallbackPrintWithColor = false;

std::string PrettyOTA::m_AppBuildTime = "";
std::string PrettyOTA::m_AppBuildDate = "";
std::string PrettyOTA::m_AppVersion = "";
std::string PrettyOTA::m_HardwareID = ARDUINO_BOARD;

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

#if (DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING == 1)
    // Initialize firmware pulling backend
    m_FirmwarePullManager.Begin(m_SerialMonitorStream, m_OnStartUpdate, m_OnProgressUpdate, m_OnEndUpdate);

    m_FirmwarePullManager.SetCurrentAppVersion("1.0.0");
    m_FirmwarePullManager.SetHardwareID("Board2");
    m_FirmwarePullManager.SetCustomFilter("custom1");

    std::string fwUrl = "";
    m_FirmwarePullManager.CheckForNewFirmwareAvailable("https://pastebin.com/raw/K0yi7htv", fwUrl);

    m_SerialMonitorStream->println(("Received firmware URL: " + fwUrl).c_str());
#endif

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
        if(deserializeJson(loginData, data))
        {
            P_LOG_E("Could not deserialize Json");
            return request->send(400, "text/plain", "Could not deserialize Json");
        }

        // Check login credentials
        if(loginData["userId"].as<std::string>() == m_Username && loginData["password"].as<std::string>() == m_Password)
        {
            // Generate session ID
            UUID_t id = {0};
            GenerateUUID(&id);
            const std::string sessionIDstr = "sessionID=" + UUIDToString(id);

            // If max number of clients is logged in, log out oldest client (first entry in vector) by removing it's sessionID
            if(m_AuthenticatedSessionIDs.size() >= MAX_NUM_LOGGED_IN_CLIENTS)
                m_AuthenticatedSessionIDs.erase(m_AuthenticatedSessionIDs.begin());

            // Add session ID to known (authenticated) session IDs
            m_AuthenticatedSessionIDs.push_back(sessionIDstr);

            // Save sessionIDs to NVS
            if(!SaveSessionIDsToNVS())
                P_LOG_W("Could not save this session to NVS storage. Client must log in again after reboot or update");

            // Send response and set session ID cookie
            AsyncWebServerResponse* response = request->beginResponse(200);
            response->addHeader("Set-Cookie", sessionIDstr.c_str());
            return request->send(response);
        }
        else
        {
            P_LOG_W("Log in attempt with wrong credentials");
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
                if(!SaveSessionIDsToNVS())
                    P_LOG_W("Could not delete this session from NVS storage. Client could still be logged in");

                return request->send(200);
            }
            else
            {
                return request->send(400, "text/plain", "No client with given sessionID is logged in");
            }
        }
        else
        {
            return request->send(400, "text/plain", "No cookie with sessionID found. Reload the page");
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

        // Is an update already running? (web interface or pulling in background)
        if(m_IsUpdateRunning)
        {
            P_LOG_E("An update is already running");
            return request->send(400, "text/plain", "An update is already running");
        }

        m_IsUpdateRunning = true;

        // Get OTA update mode (filesystem / firmware)
        NSPrettyOTA::UPDATE_MODE updateMode = NSPrettyOTA::UPDATE_MODE::FIRMWARE;
        if(request->hasParam("mode"))
        {
            const std::string value = request->getParam("mode")->value().c_str();
            updateMode = (value == "fs" ? NSPrettyOTA::UPDATE_MODE::FILESYSTEM : NSPrettyOTA::UPDATE_MODE::FIRMWARE);
        }
        else
        {
            m_IsUpdateRunning = false;
            P_LOG_E("Missing parameter in URL: mode");
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
            m_IsUpdateRunning = false;
            P_LOG_E("Missing parameter in URL: reboot");
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
            m_IsUpdateRunning = false;
            P_LOG_E("Missing parameter in URL: hash");
            return request->send(400, "text/plain", "Missing parameter in URL: hash");
        }

        // Call OnStart callback
        if(m_OnStartUpdate)
            m_OnStartUpdate(updateMode);

        // Start update
        if(!m_UpdateManager.Begin(updateMode, md5Hash.c_str()))
        {
            m_IsUpdateRunning = false;
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

        //response->addHeader("Connection", "close"); // Testing
        response->addHeader("Access-Control-Allow-Origin", "*");
        request->send(response);

        m_IsUpdateRunning = false;

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

        if(size != 0)
        {
            if(m_UpdateManager.Write(data, size) != size)
            {
                P_LOG_E("UpdateManager: Error while writing");
                P_LOG_E(m_UpdateManager.GetLastErrorAsString() + "\n");
                return request->send(400, "text/plain", m_UpdateManager.GetLastErrorAsString().c_str());
            }

            // Call OnProgress callback
            if(m_OnProgressUpdate)
                m_OnProgressUpdate(index + size, request->contentLength());
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

        // Is an update already running? (web interface or pulling in background)
        if(m_IsUpdateRunning)
        {
            P_LOG_E("Rollback is not possible while an update is running");
            return request->send(400, "text/plain", "Rollback is not possible while an update is running");
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
    // Page "/prettyota/rebootCheck": For checking if server is online
    server->on("/prettyota/rebootCheck", HTTP_GET | HTTP_HEAD, [&](AsyncWebServerRequest* request)
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

        // Is an update already running? (web interface or pulling in background)
        if(m_IsUpdateRunning)
        {
            P_LOG_E("Reboot is not possible while an update is running");
            return request->send(400, "text/plain", "Reboot is not possible while an update is running");
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
#if (PRETTY_OTA_ENABLE_ARDUINO_OTA == 1)
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
            {"board", "esp32"}, // ToDo: Board identifier
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
                P_LOG_E("Could not set mDNS txt item");
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
#else
    P_LOG_W("ArduinoOTA is disabled in code. Set #define PRETTY_OTA_ENABLE_ARDUINO_OTA 1 to enable ArduinoOTA functionality.");
#endif
}

// Handle reboot request background task
void PrettyOTA::BackgroundTask(void* parameter)
{
    PrettyOTA* const me = reinterpret_cast<PrettyOTA*>(parameter);

    while (true)
    {
#if (PRETTY_OTA_ENABLE_ARDUINO_OTA == 1)
        ArduinoOTA.handle();
#endif

        // Check if specified time has passed since reboot request was made
        if(me->m_RequestReboot && (millis() - me->m_RebootRequestTime >= 2000))
        {
            me->P_LOG_I("Rebooting...");
            m_SerialMonitorStream->flush();

            yield();
            delay(200);

            me->m_RequestReboot = false;
            ESP.restart();
        }

        yield();
        delay(1000);
    }
}

#if (DEV_PRETTY_OTA_ENABLE_FIRMWARE_PULLING == 1)
bool PrettyOTA::DoFirmwarePull(const char* const customFilter)
{
    if(m_IsUpdateRunning)
        return false;

    m_IsUpdateRunning = true;


    m_IsUpdateRunning = false;

    return false;
}
#endif

void PrettyOTA::UseDefaultCallbacks(bool printWithColor)
{
    m_DefaultCallbackPrintWithColor = printWithColor;

    m_OnStartUpdate = OnOTAStart;
    m_OnProgressUpdate = OnOTAProgress;
    m_OnEndUpdate = OnOTAEnd;
}

void PrettyOTA::SetAppBuildTimeAndDate(const char *const appBuildTime, const char *const appBuildDate)
{
    m_AppBuildTime = appBuildTime;
    m_AppBuildDate = appBuildDate;
}

void PrettyOTA::SetAppVersion(const char* const appVersion)
{
    m_AppVersion = appVersion;
}
