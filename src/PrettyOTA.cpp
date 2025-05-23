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
                if(!SaveSessionIDsToNVS())
                    return request->send(400, "text/plain", "Could not delete this session from NVS storage");

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
            m_IsUpdateRunning = false;
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
            m_IsUpdateRunning = false;
            P_LOG_E("Missing parameter: hash");
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

        response->addHeader("Connection", "close");
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
            delay(1000);

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

const uint8_t PrettyOTA::PRETTY_OTA_WEBSITE_DATA[12706] = {
    31, 139, 8, 8, 2, 203, 241, 103, 0, 3, 112, 114, 101, 116, 116, 121, 79, 84, 65, 95, 109, 105, 110, 105, 102, 121, 46, 104, 116, 109, 108, 0, 229, 125, 11, 119, 219, 70, 150, 230, 95,
    65, 216, 27, 71, 28, 19, 48, 234, 133, 135, 36, 42, 147, 56, 233, 118, 239, 177, 167, 251, 196, 137, 119, 118, 114, 50, 25, 136, 4, 37, 78, 40, 66, 77, 66, 114, 28, 69, 243, 127,
    246, 111, 236, 47, 219, 239, 187, 5, 146, 0, 31, 178, 236, 73, 122, 119, 206, 198, 17, 1, 212, 227, 222, 91, 183, 238, 171, 30, 40, 156, 126, 50, 174, 70, 245, 187, 235, 50, 184, 172,
    175, 102, 103, 167, 252, 13, 102, 197, 252, 98, 88, 206, 241, 84, 22, 227, 179, 211, 171, 178, 46, 130, 209, 101, 177, 88, 150, 245, 240, 187, 111, 255, 24, 102, 77, 218, 188, 184, 42, 135,
    183, 211, 242, 237, 117, 181, 168, 131, 81, 53, 175, 203, 121, 61, 236, 189, 157, 142, 235, 203, 225, 184, 188, 157, 142, 202, 80, 30, 6, 211, 249, 180, 158, 22, 179, 112, 57, 42, 102, 229,
    80, 245, 218, 0, 198, 229, 114, 180, 152, 94, 215, 211, 106, 190, 129, 241, 69, 112, 94, 214, 117, 185, 8, 102, 85, 245, 211, 116, 126, 17, 252, 229, 219, 47, 130, 183, 229, 121, 112, 115,
    61, 46, 144, 30, 1, 68, 61, 173, 103, 229, 217, 95, 23, 40, 248, 14, 217, 167, 207, 124, 194, 233, 108, 58, 255, 41, 88, 148, 179, 225, 20, 224, 2, 54, 110, 56, 189, 42, 46, 202,
    103, 203, 219, 139, 167, 63, 163, 125, 151, 139, 114, 50, 236, 1, 78, 113, 220, 201, 24, 124, 106, 158, 227, 54, 192, 237, 124, 57, 252, 236, 178, 174, 175, 143, 159, 61, 123, 251, 246, 109,
    244, 214, 68, 213, 226, 226, 153, 142, 227, 152, 133, 63, 11, 124, 27, 63, 115, 74, 127, 22, 92, 150, 211, 139, 203, 186, 121, 144, 186, 199, 183, 190, 246, 18, 213, 111, 203, 81, 93, 68,
    211, 234, 217, 188, 152, 87, 159, 125, 106, 190, 6, 146, 235, 162, 190, 12, 198, 195, 207, 94, 197, 65, 124, 137, 106, 183, 248, 123, 17, 191, 137, 127, 249, 44, 152, 76, 103, 179, 225, 103,
    159, 106, 99, 29, 255, 125, 246, 108, 171, 134, 114, 46, 50, 46, 11, 178, 60, 202, 156, 153, 153, 200, 164, 42, 140, 98, 173, 3, 19, 165, 177, 198, 109, 156, 225, 54, 203, 115, 166, 6,
    74, 71, 153, 78, 112, 107, 85, 96, 35, 107, 12, 110, 149, 14, 116, 28, 101, 41, 83, 113, 107, 162, 60, 97, 137, 52, 13, 84, 22, 185, 140, 21, 109, 22, 40, 21, 197, 146, 110, 146,
    231, 58, 215, 81, 170, 19, 34, 53, 64, 132, 218, 58, 77, 130, 220, 69, 86, 167, 129, 177, 9, 208, 196, 35, 84, 112, 74, 177, 94, 230, 0, 10, 69, 1, 69, 39, 145, 202, 108, 160,
    109, 96, 245, 12, 136, 28, 104, 83, 177, 27, 185, 200, 37, 192, 13, 28, 214, 4, 58, 74, 80, 198, 218, 72, 135, 78, 202, 36, 108, 128, 155, 133, 42, 50, 49, 107, 196, 250, 185, 113,
    38, 114, 168, 129, 75, 142, 171, 49, 6, 149, 80, 53, 213, 17, 176, 25, 32, 214, 153, 26, 133, 104, 65, 130, 134, 36, 81, 154, 187, 208, 36, 81, 162, 243, 32, 141, 116, 30, 186, 36,
    50, 104, 120, 26, 41, 2, 78, 162, 92, 179, 253, 113, 206, 26, 177, 176, 66, 110, 93, 76, 14, 217, 151, 42, 117, 0, 152, 205, 132, 157, 108, 145, 142, 148, 77, 73, 99, 2, 140, 113,
    170, 72, 123, 18, 131, 52, 151, 144, 109, 25, 112, 197, 198, 5, 57, 232, 79, 65, 175, 33, 31, 148, 101, 162, 65, 3, 140, 50, 35, 246, 7, 137, 137, 19, 27, 70, 14, 156, 87, 38,
    210, 10, 45, 6, 115, 8, 193, 25, 220, 103, 9, 24, 17, 165, 9, 136, 137, 163, 56, 243, 196, 155, 80, 165, 104, 80, 42, 149, 13, 136, 87, 160, 155, 9, 82, 8, 132, 131, 53, 78,
    135, 128, 151, 166, 38, 204, 34, 147, 164, 72, 138, 141, 14, 45, 24, 104, 67, 178, 42, 15, 211, 200, 177, 36, 196, 69, 132, 2, 92, 160, 216, 48, 69, 4, 36, 206, 80, 58, 6, 215,
    144, 42, 245, 132, 41, 40, 108, 35, 229, 188, 216, 32, 57, 75, 69, 152, 116, 168, 117, 148, 43, 45, 98, 19, 162, 147, 173, 176, 211, 102, 33, 100, 195, 154, 92, 196, 134, 120, 116, 76,
    233, 84, 160, 84, 69, 86, 68, 142, 80, 116, 108, 71, 190, 42, 136, 181, 44, 193, 182, 64, 176, 209, 163, 144, 0, 148, 1, 119, 217, 96, 176, 91, 179, 130, 50, 16, 190, 40, 55, 20,
    144, 20, 236, 114, 224, 187, 147, 123, 13, 21, 208, 185, 32, 73, 192, 104, 151, 41, 17, 112, 180, 42, 39, 165, 144, 139, 44, 82, 137, 243, 122, 1, 130, 114, 151, 248, 142, 64, 135, 101,
    214, 55, 128, 234, 96, 36, 221, 185, 0, 44, 77, 173, 84, 77, 71, 154, 96, 50, 73, 182, 134, 212, 133, 108, 116, 144, 64, 210, 29, 165, 69, 65, 11, 80, 62, 1, 3, 217, 221, 57,
    48, 36, 144, 82, 112, 1, 173, 0, 14, 60, 105, 240, 209, 162, 237, 232, 31, 224, 67, 183, 50, 41, 65, 31, 166, 41, 122, 3, 221, 135, 210, 232, 221, 220, 73, 177, 92, 229, 210, 141,
    228, 59, 0, 154, 80, 163, 255, 83, 45, 188, 81, 33, 164, 47, 83, 242, 160, 83, 53, 67, 207, 101, 162, 240, 42, 1, 27, 149, 33, 115, 85, 38, 157, 235, 117, 88, 133, 6, 162, 74,
    129, 86, 232, 5, 109, 193, 88, 242, 9, 173, 64, 153, 84, 236, 67, 22, 210, 140, 104, 223, 165, 224, 30, 90, 25, 43, 244, 77, 138, 14, 37, 15, 96, 0, 208, 255, 9, 59, 218, 130,
    159, 224, 83, 34, 18, 155, 177, 83, 146, 140, 2, 155, 169, 144, 74, 101, 41, 139, 138, 194, 9, 5, 110, 228, 85, 68, 84, 164, 53, 104, 36, 84, 196, 53, 240, 18, 234, 197, 21, 93,
    172, 148, 11, 53, 45, 22, 133, 61, 75, 68, 92, 165, 175, 116, 158, 136, 192, 182, 205, 162, 30, 157, 155, 34, 89, 153, 69, 26, 99, 220, 193, 25, 120, 31, 226, 173, 253, 85, 53, 190,
    153, 149, 193, 104, 81, 45, 151, 213, 98, 122, 49, 157, 159, 193, 19, 44, 235, 96, 57, 43, 203, 235, 97, 57, 60, 155, 151, 111, 131, 191, 46, 170, 171, 233, 178, 60, 58, 170, 135, 103,
    240, 108, 223, 78, 175, 202, 234, 166, 62, 170, 7, 101, 191, 223, 31, 92, 141, 221, 112, 114, 51, 31, 209, 45, 29, 245, 239, 110, 139, 69, 80, 110, 18, 202, 254, 29, 220, 206, 205, 98,
    30, 180, 147, 38, 213, 226, 136, 5, 235, 193, 124, 216, 131, 20, 194, 134, 39, 105, 150, 23, 231, 163, 113, 57, 233, 13, 170, 97, 175, 55, 88, 12, 227, 147, 197, 105, 25, 205, 202, 249,
    69, 125, 121, 178, 120, 250, 180, 95, 15, 203, 136, 238, 245, 121, 53, 46, 191, 168, 143, 22, 253, 65, 245, 116, 56, 151, 36, 60, 214, 103, 103, 103, 246, 137, 114, 253, 167, 235, 36, 229,
    158, 212, 253, 147, 134, 128, 234, 254, 104, 47, 13, 68, 54, 7, 178, 249, 169, 209, 255, 176, 198, 55, 127, 58, 204, 250, 245, 211, 225, 235, 122, 1, 175, 26, 77, 192, 131, 231, 13, 234,
    163, 242, 251, 249, 217, 153, 251, 1, 248, 230, 159, 26, 253, 68, 59, 183, 70, 82, 183, 145, 12, 234, 254, 93, 249, 125, 205, 178, 191, 14, 149, 206, 78, 79, 107, 148, 31, 148, 223, 43,
    251, 244, 168, 126, 154, 88, 64, 200, 79, 79, 109, 255, 135, 97, 125, 178, 162, 103, 54, 84, 169, 209, 46, 179, 42, 55, 131, 233, 16, 130, 141, 103, 147, 165, 249, 96, 60, 12, 215, 89,
    118, 112, 51, 92, 229, 100, 131, 17, 200, 31, 109, 120, 53, 122, 58, 84, 137, 239, 138, 171, 225, 108, 112, 49, 156, 14, 16, 102, 12, 38, 195, 155, 147, 233, 112, 121, 212, 253, 91, 108,
    253, 85, 91, 127, 243, 238, 31, 168, 152, 31, 141, 129, 125, 126, 116, 51, 152, 225, 119, 54, 64, 218, 224, 6, 173, 26, 61, 141, 127, 24, 164, 131, 48, 201, 98, 88, 191, 220, 36, 125,
    201, 98, 134, 250, 97, 160, 244, 32, 52, 112, 86, 137, 117, 25, 114, 88, 141, 57, 26, 57, 233, 32, 137, 19, 56, 187, 76, 229, 125, 64, 154, 73, 134, 249, 97, 160, 81, 69, 197, 22,
    38, 193, 25, 19, 247, 31, 68, 109, 5, 53, 236, 140, 85, 208, 234, 116, 131, 218, 9, 106, 197, 136, 36, 131, 242, 182, 80, 39, 130, 26, 122, 11, 166, 194, 239, 88, 181, 65, 158, 122,
    228, 214, 165, 177, 203, 51, 243, 48, 234, 140, 168, 85, 154, 194, 130, 56, 171, 90, 173, 206, 125, 171, 225, 72, 209, 101, 214, 170, 116, 131, 91, 197, 30, 185, 133, 141, 51, 27, 188, 74,
    53, 173, 206, 243, 216, 194, 48, 37, 250, 97, 212, 74, 11, 110, 52, 12, 46, 54, 201, 116, 139, 227, 198, 35, 183, 49, 26, 6, 179, 214, 66, 109, 155, 118, 187, 24, 76, 209, 58, 143,
    91, 248, 157, 224, 135, 70, 38, 14, 129, 132, 206, 137, 190, 18, 244, 149, 160, 175, 186, 232, 127, 24, 56, 0, 74, 28, 124, 136, 83, 241, 6, 59, 88, 155, 179, 239, 146, 220, 193, 234,
    26, 221, 194, 78, 81, 176, 131, 196, 34, 28, 75, 83, 213, 106, 59, 56, 162, 99, 200, 72, 10, 41, 73, 77, 172, 31, 70, 237, 4, 117, 26, 35, 204, 203, 146, 92, 181, 26, 30, 19,
    183, 201, 128, 55, 102, 207, 173, 17, 59, 65, 28, 38, 73, 108, 211, 204, 24, 183, 193, 108, 61, 102, 11, 247, 101, 210, 204, 102, 15, 99, 206, 137, 217, 33, 16, 179, 104, 68, 214, 66,
    108, 155, 70, 195, 189, 161, 51, 200, 214, 21, 110, 227, 81, 171, 44, 53, 137, 201, 147, 150, 160, 101, 130, 90, 129, 71, 206, 160, 67, 212, 123, 248, 109, 60, 195, 45, 112, 103, 8, 154,
    90, 98, 174, 5, 185, 83, 232, 111, 52, 97, 131, 58, 21, 212, 48, 20, 232, 205, 12, 146, 222, 234, 107, 237, 155, 173, 114, 13, 158, 192, 195, 88, 34, 95, 8, 242, 133, 32, 95, 108,
    115, 220, 178, 123, 50, 112, 124, 131, 23, 13, 80, 106, 0, 135, 167, 181, 75, 65, 150, 217, 234, 234, 4, 210, 105, 242, 24, 225, 41, 101, 121, 141, 155, 44, 55, 128, 230, 12, 34, 41,
    151, 60, 140, 89, 9, 102, 197, 178, 57, 244, 165, 37, 103, 86, 176, 43, 120, 254, 44, 71, 151, 154, 110, 187, 19, 86, 114, 54, 79, 69, 2, 215, 184, 99, 143, 27, 222, 22, 252, 64,
    144, 25, 191, 7, 187, 33, 122, 240, 91, 167, 185, 74, 237, 6, 121, 236, 155, 142, 65, 6, 196, 70, 107, 221, 237, 111, 32, 71, 162, 211, 42, 79, 91, 86, 45, 17, 220, 105, 130, 192,
    74, 101, 249, 195, 136, 115, 105, 54, 232, 51, 137, 69, 72, 216, 146, 52, 237, 49, 91, 173, 50, 229, 50, 138, 114, 71, 202, 147, 1, 88, 133, 136, 207, 233, 150, 106, 107, 223, 234, 60,
    135, 45, 205, 160, 173, 196, 189, 20, 220, 75, 193, 189, 220, 182, 228, 228, 94, 158, 37, 38, 134, 164, 111, 112, 147, 175, 20, 88, 141, 72, 89, 89, 229, 182, 236, 138, 72, 39, 165, 217,
    230, 113, 75, 195, 104, 86, 64, 48, 36, 196, 80, 203, 30, 198, 205, 230, 65, 108, 96, 79, 45, 100, 45, 109, 233, 182, 17, 228, 208, 163, 220, 130, 50, 56, 141, 45, 131, 74, 236, 177,
    83, 78, 183, 197, 220, 163, 214, 49, 72, 210, 232, 194, 252, 97, 228, 153, 224, 134, 162, 194, 35, 24, 151, 183, 152, 238, 60, 114, 72, 140, 130, 24, 216, 174, 31, 33, 102, 151, 80, 245,
    97, 121, 90, 200, 141, 96, 87, 144, 92, 229, 84, 98, 223, 131, 220, 122, 174, 91, 132, 128, 232, 192, 150, 156, 139, 42, 177, 229, 240, 99, 90, 65, 197, 243, 174, 7, 117, 131, 20, 52,
    103, 169, 118, 45, 89, 203, 125, 203, 13, 120, 14, 62, 178, 199, 103, 195, 2, 248, 174, 0, 23, 55, 211, 193, 5, 169, 41, 64, 205, 37, 42, 225, 230, 102, 48, 233, 223, 251, 64, 230,
    251, 134, 172, 31, 14, 5, 77, 95, 44, 22, 197, 187, 163, 85, 200, 113, 118, 6, 233, 247, 65, 84, 189, 137, 160, 16, 177, 125, 63, 255, 1, 169, 172, 230, 115, 179, 237, 8, 203, 135,
    82, 191, 14, 143, 16, 69, 61, 233, 132, 119, 243, 103, 89, 191, 127, 122, 202, 16, 171, 21, 93, 149, 253, 193, 6, 6, 226, 207, 251, 147, 21, 125, 65, 205, 136, 107, 48, 31, 84, 131,
    197, 96, 185, 142, 59, 139, 173, 128, 172, 73, 46, 17, 140, 253, 90, 34, 0, 195, 80, 9, 96, 11, 252, 99, 64, 59, 40, 142, 42, 84, 238, 15, 16, 92, 206, 251, 247, 107, 216, 172,
    220, 64, 30, 20, 131, 217, 26, 12, 200, 124, 82, 253, 250, 31, 243, 39, 139, 1, 11, 248, 204, 77, 181, 234, 129, 106, 139, 95, 171, 39, 255, 177, 191, 218, 226, 112, 181, 127, 173, 254,
    117, 127, 157, 229, 193, 58, 213, 191, 30, 205, 127, 253, 15, 52, 104, 95, 181, 194, 115, 133, 157, 58, 31, 30, 37, 240, 128, 232, 134, 254, 211, 230, 110, 29, 61, 31, 129, 85, 8, 109,
    158, 50, 202, 150, 235, 92, 174, 167, 167, 42, 249, 213, 23, 157, 223, 111, 7, 250, 0, 91, 7, 83, 12, 39, 138, 249, 168, 172, 38, 193, 119, 211, 121, 157, 137, 220, 252, 250, 43, 198,
    18, 71, 28, 91, 124, 91, 254, 92, 127, 61, 31, 161, 199, 23, 253, 168, 148, 155, 163, 222, 82, 98, 238, 222, 112, 200, 65, 10, 42, 214, 159, 215, 199, 255, 253, 245, 95, 254, 41, 242,
    25, 211, 201, 59, 192, 238, 247, 215, 33, 243, 124, 248, 253, 15, 24, 52, 16, 222, 6, 7, 138, 112, 12, 49, 88, 14, 171, 232, 252, 93, 93, 190, 108, 198, 17, 167, 75, 25, 75, 204,
    163, 235, 155, 229, 229, 209, 190, 240, 190, 250, 126, 241, 67, 127, 29, 209, 151, 71, 243, 232, 223, 171, 233, 252, 168, 215, 131, 180, 221, 31, 245, 7, 151, 197, 242, 242, 143, 168, 240, 199,
    233, 172, 28, 22, 203, 119, 243, 81, 176, 61, 82, 130, 44, 205, 251, 195, 179, 187, 89, 89, 7, 158, 48, 22, 254, 166, 44, 208, 206, 147, 42, 170, 230, 179, 170, 24, 119, 70, 73, 126,
    220, 53, 223, 110, 68, 25, 213, 197, 226, 162, 172, 163, 69, 185, 188, 153, 161, 59, 234, 35, 12, 184, 142, 230, 32, 101, 80, 33, 177, 24, 127, 177, 148, 146, 95, 222, 76, 38, 37, 228,
    166, 127, 15, 210, 61, 81, 27, 113, 186, 153, 127, 39, 179, 129, 68, 116, 57, 29, 151, 95, 207, 202, 171, 114, 94, 31, 245, 110, 174, 73, 200, 243, 106, 118, 115, 53, 239, 161, 101, 237,
    60, 12, 245, 106, 240, 102, 185, 63, 247, 188, 42, 22, 7, 42, 158, 223, 212, 117, 53, 95, 231, 21, 111, 139, 105, 51, 162, 60, 210, 52, 106, 203, 203, 234, 237, 186, 240, 245, 162, 186,
    64, 219, 54, 88, 128, 246, 175, 77, 218, 183, 156, 166, 60, 234, 189, 6, 11, 234, 213, 212, 166, 159, 214, 236, 129, 17, 139, 119, 13, 211, 234, 161, 71, 209, 238, 23, 218, 137, 249, 112,
    92, 141, 110, 136, 38, 2, 7, 27, 140, 95, 190, 251, 243, 248, 168, 87, 213, 197, 43, 116, 117, 175, 31, 221, 22, 179, 155, 18, 194, 115, 176, 232, 162, 60, 175, 170, 250, 249, 101, 57,
    250, 233, 188, 250, 249, 207, 243, 235, 155, 26, 213, 70, 124, 46, 199, 39, 211, 201, 209, 39, 71, 30, 253, 164, 172, 71, 151, 71, 255, 246, 236, 90, 230, 89, 129, 225, 217, 146, 132, 127,
    142, 65, 118, 57, 252, 111, 119, 243, 251, 39, 36, 16, 119, 245, 253, 19, 15, 20, 247, 213, 253, 191, 245, 251, 81, 245, 83, 191, 190, 92, 84, 111, 3, 246, 254, 215, 139, 5, 228, 186,
    247, 188, 186, 153, 141, 131, 121, 5, 214, 17, 76, 183, 241, 148, 171, 133, 200, 202, 63, 191, 122, 249, 162, 174, 175, 191, 41, 255, 118, 83, 46, 235, 147, 69, 228, 187, 20, 34, 182, 226,
    108, 71, 204, 64, 239, 202, 120, 62, 175, 174, 208, 150, 226, 124, 182, 150, 190, 122, 248, 170, 168, 47, 163, 69, 117, 51, 31, 179, 24, 224, 148, 227, 103, 16, 65, 52, 102, 246, 15, 42,
    142, 251, 39, 7, 217, 180, 194, 246, 101, 177, 0, 123, 150, 245, 187, 89, 25, 249, 185, 223, 250, 105, 239, 211, 222, 224, 189, 21, 223, 176, 35, 80, 117, 58, 159, 151, 139, 23, 223, 190,
    122, 233, 43, 222, 223, 15, 22, 104, 12, 37, 253, 29, 24, 81, 151, 240, 16, 243, 139, 149, 222, 181, 38, 30, 236, 112, 184, 16, 133, 120, 247, 154, 197, 158, 60, 57, 250, 8, 90, 123,
    104, 228, 99, 136, 245, 53, 55, 164, 54, 245, 58, 106, 176, 35, 217, 59, 138, 128, 225, 23, 137, 102, 179, 110, 150, 159, 31, 117, 244, 98, 121, 51, 26, 109, 169, 197, 107, 159, 244, 10,
    127, 197, 5, 244, 194, 235, 116, 208, 36, 79, 110, 102, 107, 28, 252, 249, 99, 181, 120, 93, 46, 110, 203, 197, 55, 34, 107, 175, 1, 252, 27, 177, 33, 71, 253, 254, 177, 125, 0, 115,
    73, 249, 107, 227, 21, 129, 108, 116, 241, 59, 145, 174, 96, 82, 64, 199, 198, 173, 108, 152, 182, 37, 186, 129, 61, 176, 188, 134, 48, 149, 52, 236, 64, 244, 219, 129, 238, 249, 214, 4,
    222, 44, 151, 227, 192, 19, 31, 208, 101, 4, 189, 167, 171, 198, 72, 72, 208, 76, 98, 121, 195, 91, 45, 174, 190, 42, 234, 226, 100, 25, 21, 215, 215, 37, 36, 187, 55, 1, 134, 30,
    188, 97, 25, 113, 93, 165, 79, 1, 67, 198, 81, 239, 175, 127, 121, 253, 109, 111, 208, 107, 105, 176, 87, 166, 30, 139, 44, 89, 117, 185, 207, 62, 121, 194, 105, 160, 122, 79, 27, 144,
    247, 163, 130, 198, 96, 219, 220, 190, 95, 36, 126, 51, 118, 149, 209, 149, 151, 19, 248, 172, 77, 56, 50, 167, 109, 20, 27, 214, 154, 153, 35, 137, 207, 111, 150, 117, 117, 245, 197, 172,
    92, 64, 62, 6, 235, 176, 78, 121, 217, 104, 231, 246, 254, 50, 159, 189, 11, 138, 96, 137, 6, 207, 74, 206, 55, 150, 193, 168, 152, 7, 231, 101, 224, 185, 133, 174, 41, 224, 245, 224,
    243, 35, 144, 245, 137, 234, 31, 247, 206, 167, 243, 222, 39, 195, 242, 251, 248, 7, 97, 79, 180, 188, 158, 77, 1, 9, 249, 209, 117, 117, 125, 212, 223, 197, 242, 153, 96, 233, 69, 172,
    41, 56, 150, 219, 72, 162, 207, 60, 240, 163, 150, 119, 3, 2, 36, 198, 253, 251, 195, 214, 188, 154, 205, 206, 139, 209, 79, 95, 138, 143, 2, 254, 98, 60, 254, 250, 22, 217, 47, 167,
    203, 186, 132, 58, 31, 245, 70, 179, 233, 232, 167, 222, 224, 104, 203, 194, 52, 125, 217, 101, 212, 223, 219, 153, 138, 225, 175, 247, 25, 254, 250, 177, 70, 178, 238, 26, 73, 177, 65, 245,
    71, 219, 160, 111, 26, 126, 126, 184, 21, 66, 55, 53, 118, 232, 0, 246, 7, 165, 127, 141, 247, 144, 252, 215, 255, 9, 75, 244, 94, 224, 239, 177, 69, 117, 203, 22, 13, 234, 131, 198,
    101, 92, 173, 16, 1, 67, 237, 13, 12, 195, 183, 195, 238, 199, 135, 13, 255, 69, 101, 119, 215, 216, 117, 177, 180, 133, 237, 245, 155, 63, 29, 144, 55, 225, 0, 71, 7, 91, 182, 114,
    75, 86, 127, 111, 69, 121, 164, 132, 31, 31, 29, 110, 227, 75, 154, 177, 166, 86, 239, 129, 78, 239, 84, 242, 197, 27, 118, 116, 67, 144, 215, 144, 31, 58, 33, 47, 36, 184, 72, 123,
    27, 25, 142, 130, 7, 68, 246, 184, 37, 179, 135, 233, 184, 168, 190, 108, 27, 206, 241, 116, 201, 216, 113, 60, 252, 68, 61, 174, 142, 238, 86, 122, 159, 110, 188, 42, 230, 55, 197, 108,
    205, 158, 71, 233, 199, 172, 186, 168, 110, 62, 78, 63, 126, 103, 121, 129, 49, 42, 235, 55, 211, 242, 237, 81, 35, 19, 93, 93, 220, 113, 178, 47, 171, 139, 0, 77, 89, 91, 160, 135,
    185, 229, 219, 253, 97, 86, 100, 123, 68, 115, 152, 89, 29, 54, 85, 163, 98, 246, 186, 174, 22, 16, 63, 224, 170, 255, 92, 151, 87, 43, 136, 63, 142, 26, 144, 15, 4, 208, 15, 142,
    166, 100, 236, 202, 142, 32, 59, 154, 101, 198, 193, 120, 81, 93, 127, 1, 206, 30, 30, 161, 177, 196, 47, 213, 156, 227, 162, 117, 164, 195, 180, 23, 211, 139, 203, 25, 119, 156, 144, 240,
    21, 152, 104, 52, 43, 150, 75, 54, 146, 45, 222, 84, 14, 47, 87, 165, 123, 173, 217, 17, 230, 126, 55, 191, 124, 15, 160, 69, 121, 85, 221, 150, 239, 131, 213, 54, 87, 132, 115, 160,
    57, 101, 127, 15, 100, 72, 204, 184, 156, 183, 161, 181, 237, 202, 99, 161, 73, 131, 119, 65, 237, 68, 180, 15, 192, 91, 135, 176, 82, 178, 99, 128, 202, 14, 196, 45, 195, 253, 16, 200,
    101, 167, 232, 3, 48, 91, 62, 250, 33, 120, 229, 186, 216, 251, 96, 173, 98, 229, 247, 1, 243, 229, 14, 66, 219, 82, 222, 114, 80, 211, 190, 29, 134, 137, 65, 253, 116, 50, 197, 16,
    1, 181, 183, 90, 205, 96, 101, 8, 0, 159, 63, 170, 178, 31, 134, 110, 117, 240, 86, 129, 166, 35, 122, 253, 227, 143, 2, 185, 146, 192, 67, 80, 15, 171, 250, 123, 9, 37, 223, 0,
    96, 52, 43, 139, 197, 106, 83, 65, 75, 243, 189, 85, 108, 30, 134, 173, 141, 7, 71, 45, 187, 251, 159, 106, 147, 39, 224, 190, 63, 72, 75, 179, 165, 90, 29, 243, 124, 119, 152, 196,
    223, 2, 255, 214, 108, 29, 220, 206, 226, 221, 122, 179, 222, 159, 231, 147, 234, 200, 187, 167, 114, 159, 123, 42, 247, 185, 167, 22, 131, 166, 147, 35, 248, 166, 178, 227, 155, 196, 53, 149,
    171, 32, 181, 129, 45, 19, 172, 215, 220, 187, 120, 84, 95, 78, 151, 221, 240, 249, 240, 188, 15, 98, 138, 37, 48, 249, 121, 212, 174, 20, 71, 107, 7, 245, 198, 23, 26, 236, 247, 30,
    13, 136, 31, 155, 105, 223, 193, 110, 197, 254, 129, 154, 87, 197, 116, 254, 227, 205, 98, 198, 58, 188, 255, 238, 155, 151, 135, 138, 194, 69, 110, 202, 202, 131, 20, 46, 163, 226, 166, 190,
    68, 107, 154, 174, 250, 122, 46, 241, 201, 231, 157, 216, 178, 27, 86, 28, 119, 66, 186, 110, 222, 253, 61, 32, 122, 47, 253, 167, 175, 183, 156, 244, 110, 191, 246, 136, 191, 113, 216, 251,
    132, 224, 183, 239, 251, 62, 146, 126, 203, 222, 191, 68, 236, 255, 182, 88, 148, 63, 78, 199, 63, 214, 40, 186, 37, 0, 171, 236, 63, 127, 117, 88, 81, 246, 128, 144, 237, 169, 143, 172,
    62, 153, 46, 174, 164, 250, 74, 138, 246, 144, 177, 42, 179, 18, 195, 15, 6, 182, 34, 232, 209, 128, 206, 111, 166, 179, 241, 143, 156, 148, 216, 71, 143, 228, 126, 133, 204, 15, 1, 176,
    162, 225, 209, 149, 107, 216, 168, 131, 216, 105, 192, 62, 4, 64, 7, 187, 84, 134, 88, 53, 163, 215, 191, 86, 203, 229, 20, 90, 243, 249, 225, 25, 215, 157, 105, 151, 71, 141, 30, 86,
    181, 86, 68, 200, 76, 237, 176, 55, 170, 102, 213, 226, 248, 15, 113, 60, 153, 196, 241, 201, 67, 193, 230, 86, 253, 13, 23, 122, 255, 179, 164, 71, 252, 40, 130, 227, 143, 37, 120, 50,
    113, 248, 247, 145, 4, 255, 19, 172, 197, 125, 57, 91, 150, 129, 109, 235, 239, 231, 156, 234, 172, 102, 98, 210, 142, 122, 107, 171, 113, 188, 51, 220, 227, 212, 100, 71, 169, 143, 31, 91,
    179, 59, 183, 177, 54, 28, 239, 179, 116, 239, 49, 112, 123, 134, 206, 107, 83, 167, 36, 128, 146, 229, 189, 246, 156, 129, 145, 21, 136, 242, 84, 197, 39, 253, 187, 118, 134, 114, 204, 216,
    44, 8, 205, 247, 25, 203, 121, 179, 234, 6, 106, 218, 54, 18, 216, 98, 162, 139, 239, 7, 44, 33, 225, 94, 39, 255, 233, 83, 201, 217, 223, 210, 214, 112, 6, 109, 157, 175, 218, 42,
    179, 191, 82, 245, 126, 189, 114, 253, 254, 246, 183, 166, 14, 74, 9, 32, 185, 184, 244, 113, 35, 169, 39, 79, 62, 41, 251, 13, 234, 255, 244, 196, 194, 23, 55, 117, 181, 154, 85, 152,
    46, 131, 149, 38, 68, 193, 95, 17, 22, 65, 32, 155, 172, 43, 25, 176, 207, 222, 5, 40, 125, 131, 100, 184, 85, 89, 207, 90, 25, 205, 168, 55, 184, 173, 166, 227, 224, 177, 51, 34,
    135, 189, 206, 193, 153, 136, 7, 84, 243, 240, 76, 68, 124, 210, 93, 70, 220, 43, 153, 31, 65, 204, 199, 77, 139, 32, 244, 63, 108, 149, 30, 219, 99, 62, 139, 11, 162, 224, 254, 124,
    186, 188, 44, 199, 3, 12, 122, 68, 175, 209, 131, 139, 155, 249, 156, 171, 222, 189, 7, 102, 224, 186, 125, 241, 144, 169, 124, 44, 81, 155, 5, 205, 69, 9, 142, 207, 203, 81, 29, 5,
    13, 165, 35, 201, 187, 44, 110, 203, 102, 198, 35, 168, 22, 59, 2, 4, 73, 46, 151, 2, 224, 188, 148, 162, 163, 106, 1, 80, 245, 236, 221, 135, 180, 164, 181, 203, 98, 51, 39, 115,
    247, 118, 58, 31, 87, 111, 35, 198, 142, 204, 131, 169, 164, 173, 56, 106, 111, 229, 16, 64, 40, 186, 51, 219, 49, 157, 7, 237, 152, 243, 215, 95, 31, 57, 73, 242, 73, 220, 31, 108,
    7, 191, 143, 132, 181, 29, 50, 247, 84, 20, 71, 49, 76, 208, 38, 36, 126, 36, 164, 77, 8, 221, 123, 182, 90, 94, 30, 180, 162, 229, 71, 130, 105, 133, 215, 189, 103, 242, 240, 208,
    208, 240, 65, 219, 53, 236, 213, 139, 155, 178, 55, 28, 118, 48, 93, 28, 98, 227, 3, 104, 14, 143, 77, 246, 131, 222, 226, 106, 127, 176, 111, 40, 54, 104, 133, 230, 247, 235, 201, 160,
    221, 217, 179, 49, 96, 99, 148, 183, 216, 154, 64, 147, 193, 13, 75, 126, 85, 78, 10, 89, 141, 149, 185, 186, 135, 224, 84, 215, 239, 133, 113, 210, 89, 217, 139, 248, 198, 214, 183, 139,
    98, 190, 156, 148, 139, 72, 86, 207, 222, 143, 5, 156, 152, 215, 36, 183, 51, 117, 246, 222, 74, 190, 137, 31, 86, 7, 110, 227, 182, 244, 149, 90, 147, 107, 143, 224, 194, 135, 212, 216,
    55, 123, 249, 64, 224, 223, 48, 79, 198, 233, 168, 232, 187, 165, 177, 10, 45, 230, 14, 91, 247, 171, 236, 181, 29, 25, 174, 239, 54, 53, 101, 163, 143, 183, 29, 39, 167, 207, 252, 203,
    23, 103, 167, 18, 24, 158, 241, 29, 194, 187, 73, 53, 175, 195, 73, 113, 53, 157, 189, 59, 94, 162, 203, 66, 216, 233, 233, 228, 254, 188, 26, 191, 187, 99, 44, 120, 33, 219, 49, 194,
    38, 134, 84, 57, 255, 157, 52, 79, 101, 194, 127, 247, 209, 4, 26, 81, 46, 238, 174, 171, 229, 148, 77, 61, 158, 76, 127, 46, 199, 39, 179, 114, 82, 31, 199, 39, 231, 21, 220, 204,
    21, 110, 100, 139, 195, 49, 119, 42, 156, 248, 55, 241, 142, 117, 118, 253, 243, 201, 108, 202, 25, 75, 159, 96, 240, 188, 139, 212, 40, 254, 91, 33, 205, 114, 254, 59, 17, 186, 151, 211,
    95, 202, 99, 37, 181, 170, 159, 195, 229, 101, 129, 70, 31, 199, 65, 28, 0, 112, 128, 8, 61, 190, 151, 113, 249, 87, 211, 219, 59, 248, 184, 235, 89, 241, 238, 120, 50, 43, 127, 62,
    185, 42, 22, 48, 17, 97, 93, 93, 31, 155, 69, 121, 181, 122, 110, 72, 181, 76, 98, 185, 112, 60, 165, 129, 103, 147, 70, 98, 203, 79, 10, 116, 252, 60, 156, 66, 93, 151, 199, 35,
    17, 216, 251, 232, 82, 182, 85, 125, 83, 189, 189, 59, 175, 22, 184, 91, 129, 81, 160, 1, 17, 46, 66, 142, 134, 81, 106, 180, 66, 36, 172, 81, 238, 122, 77, 201, 66, 154, 207, 148,
    123, 191, 239, 101, 241, 101, 245, 51, 134, 204, 163, 159, 238, 228, 85, 204, 99, 29, 105, 183, 98, 155, 139, 81, 209, 115, 211, 198, 27, 24, 13, 90, 215, 2, 203, 6, 218, 148, 64, 193,
    159, 77, 255, 192, 187, 192, 205, 220, 150, 39, 213, 117, 49, 154, 214, 239, 208, 57, 158, 162, 152, 69, 151, 112, 101, 66, 225, 166, 66, 113, 142, 134, 220, 212, 229, 110, 231, 92, 46, 103,
    71, 42, 53, 65, 18, 127, 26, 104, 253, 105, 127, 213, 203, 57, 136, 88, 145, 139, 219, 90, 172, 65, 181, 184, 58, 94, 254, 4, 135, 23, 143, 203, 139, 65, 168, 29, 46, 8, 156, 65,
    164, 178, 148, 132, 45, 26, 132, 41, 31, 74, 132, 53, 31, 68, 196, 94, 26, 194, 124, 77, 3, 50, 62, 148, 2, 227, 214, 20, 232, 120, 67, 129, 220, 47, 42, 78, 131, 28, 91, 98,
    221, 166, 39, 212, 13, 91, 120, 233, 75, 151, 133, 234, 174, 152, 79, 175, 10, 175, 85, 139, 234, 74, 250, 37, 176, 203, 96, 58, 103, 100, 85, 151, 190, 152, 222, 46, 38, 172, 107, 151,
    59, 89, 23, 8, 199, 37, 245, 64, 45, 125, 85, 243, 62, 12, 59, 53, 117, 83, 211, 126, 56, 82, 179, 188, 255, 199, 159, 202, 119, 147, 69, 113, 133, 80, 106, 141, 238, 46, 254, 244,
    238, 151, 16, 38, 171, 252, 25, 108, 106, 73, 165, 112, 104, 70, 142, 133, 100, 95, 16, 38, 232, 24, 221, 42, 173, 54, 165, 85, 171, 52, 76, 192, 189, 109, 21, 203, 59, 121, 232, 231,
    251, 164, 149, 155, 117, 114, 97, 58, 238, 179, 86, 110, 122, 0, 131, 210, 40, 72, 107, 182, 46, 233, 58, 249, 134, 253, 189, 110, 202, 253, 78, 195, 189, 116, 191, 191, 229, 255, 229, 27,
    222, 24, 180, 102, 144, 249, 230, 79, 119, 141, 110, 152, 182, 74, 134, 254, 253, 191, 198, 168, 110, 4, 231, 216, 107, 140, 13, 244, 50, 160, 167, 40, 22, 27, 233, 106, 25, 185, 80, 109,
    44, 167, 71, 244, 124, 186, 24, 205, 202, 59, 190, 143, 120, 60, 199, 192, 250, 4, 81, 85, 245, 83, 121, 252, 7, 237, 206, 227, 252, 188, 121, 244, 175, 189, 163, 169, 205, 227, 184, 128,
    19, 225, 126, 214, 99, 197, 237, 113, 237, 228, 106, 50, 129, 119, 61, 94, 167, 145, 154, 81, 113, 125, 44, 102, 160, 69, 48, 203, 218, 64, 69, 110, 25, 112, 120, 10, 22, 133, 92, 73,
    93, 43, 108, 75, 14, 154, 182, 221, 9, 51, 55, 214, 192, 39, 31, 153, 196, 27, 130, 118, 13, 1, 78, 161, 121, 60, 189, 247, 110, 95, 241, 60, 62, 80, 62, 52, 110, 213, 189, 123,
    50, 149, 102, 238, 125, 212, 222, 175, 113, 215, 118, 54, 187, 254, 136, 53, 182, 37, 201, 155, 211, 38, 49, 136, 225, 219, 214, 204, 26, 52, 142, 186, 155, 26, 96, 100, 95, 189, 133, 63,
    70, 4, 83, 210, 234, 173, 214, 58, 27, 97, 50, 182, 101, 105, 149, 60, 120, 103, 44, 94, 152, 45, 40, 215, 110, 216, 152, 38, 47, 92, 20, 227, 233, 205, 82, 92, 78, 43, 158, 136,
    178, 212, 49, 2, 104, 7, 38, 10, 196, 48, 141, 19, 99, 161, 4, 1, 43, 73, 109, 181, 167, 129, 42, 30, 33, 208, 105, 124, 213, 144, 143, 238, 63, 25, 221, 44, 150, 240, 19, 215,
    213, 212, 7, 13, 43, 250, 143, 47, 25, 193, 222, 181, 171, 174, 226, 170, 243, 108, 83, 108, 179, 164, 187, 85, 212, 196, 231, 182, 72, 54, 5, 57, 188, 104, 58, 68, 58, 163, 155, 243,
    213, 244, 234, 174, 169, 152, 150, 252, 119, 31, 249, 192, 230, 133, 196, 48, 221, 32, 105, 43, 2, 90, 84, 111, 79, 254, 253, 102, 89, 79, 39, 239, 194, 230, 248, 135, 181, 182, 238, 68,
    69, 237, 240, 76, 111, 5, 121, 42, 161, 226, 147, 145, 27, 145, 191, 185, 190, 46, 23, 35, 48, 235, 228, 6, 241, 39, 98, 208, 25, 176, 122, 189, 109, 73, 151, 40, 121, 155, 224, 86,
    107, 125, 1, 183, 35, 126, 136, 126, 86, 145, 227, 121, 204, 127, 93, 8, 180, 71, 187, 113, 81, 83, 161, 49, 21, 45, 4, 201, 54, 5, 168, 255, 234, 249, 119, 119, 221, 48, 78, 239,
    41, 245, 39, 152, 174, 110, 177, 108, 83, 170, 35, 197, 45, 193, 237, 132, 143, 251, 229, 182, 69, 220, 239, 163, 105, 158, 194, 231, 190, 199, 31, 148, 144, 38, 70, 110, 247, 117, 222, 165,
    176, 221, 63, 59, 49, 112, 211, 97, 217, 58, 184, 53, 177, 219, 176, 168, 33, 224, 235, 57, 231, 89, 63, 84, 78, 151, 104, 127, 25, 158, 151, 245, 219, 178, 220, 23, 196, 159, 188, 189,
    196, 99, 40, 197, 32, 117, 111, 23, 197, 245, 22, 94, 217, 30, 126, 215, 17, 164, 85, 148, 41, 225, 120, 203, 48, 72, 239, 158, 92, 99, 72, 136, 81, 124, 211, 215, 102, 75, 7, 230,
    16, 250, 98, 230, 107, 209, 0, 76, 192, 243, 227, 114, 54, 155, 94, 47, 167, 203, 147, 117, 138, 223, 44, 113, 239, 213, 225, 174, 99, 29, 90, 49, 40, 4, 213, 242, 223, 10, 231, 49,
    252, 188, 120, 233, 61, 162, 100, 50, 254, 219, 18, 164, 164, 99, 255, 124, 28, 220, 34, 86, 34, 87, 110, 94, 46, 22, 124, 149, 70, 212, 178, 161, 105, 175, 249, 138, 227, 228, 124, 50,
    185, 143, 246, 76, 179, 172, 123, 78, 96, 68, 117, 117, 129, 209, 248, 235, 183, 83, 206, 87, 119, 58, 117, 79, 31, 29, 48, 62, 187, 218, 219, 72, 79, 43, 250, 215, 106, 255, 192, 50,
    183, 202, 109, 51, 67, 180, 168, 107, 174, 91, 170, 20, 142, 111, 22, 222, 207, 199, 145, 114, 203, 110, 19, 142, 143, 139, 9, 7, 194, 43, 10, 123, 189, 147, 221, 177, 67, 67, 82, 178,
    22, 243, 100, 53, 236, 216, 63, 250, 93, 117, 119, 135, 72, 248, 244, 3, 68, 233, 101, 123, 44, 140, 182, 4, 16, 132, 32, 149, 241, 112, 198, 127, 86, 175, 196, 194, 109, 91, 152, 189,
    93, 118, 220, 204, 139, 61, 221, 219, 212, 141, 9, 95, 135, 128, 255, 140, 145, 208, 245, 207, 253, 195, 76, 59, 216, 200, 15, 192, 191, 103, 110, 194, 139, 221, 67, 125, 229, 151, 142, 154,
    168, 229, 224, 132, 128, 68, 3, 143, 30, 253, 183, 55, 153, 174, 97, 78, 231, 162, 63, 143, 1, 77, 115, 181, 71, 216, 47, 138, 235, 102, 58, 192, 19, 45, 251, 137, 30, 225, 238, 164,
    202, 184, 172, 139, 233, 76, 74, 111, 169, 117, 215, 128, 181, 64, 29, 128, 212, 44, 70, 248, 144, 250, 171, 223, 8, 236, 218, 54, 182, 7, 252, 237, 41, 243, 255, 209, 198, 122, 176, 163,
    212, 46, 133, 135, 203, 138, 179, 109, 175, 123, 116, 139, 118, 140, 233, 216, 77, 202, 209, 122, 142, 203, 66, 50, 207, 183, 13, 66, 99, 250, 219, 81, 167, 221, 109, 153, 91, 217, 213, 183,
    190, 72, 26, 199, 219, 118, 182, 81, 197, 120, 219, 181, 211, 22, 236, 17, 139, 206, 52, 23, 245, 151, 56, 100, 166, 11, 255, 229, 186, 237, 243, 225, 199, 91, 158, 125, 91, 12, 187, 204,
    88, 153, 241, 29, 157, 178, 227, 76, 211, 148, 183, 11, 159, 45, 111, 47, 86, 1, 203, 122, 90, 197, 227, 92, 91, 131, 6, 115, 227, 230, 252, 20, 150, 138, 204, 62, 172, 1, 193, 237,
    53, 35, 33, 152, 208, 223, 170, 82, 140, 104, 226, 91, 229, 5, 246, 81, 148, 39, 253, 61, 102, 37, 142, 173, 163, 89, 233, 128, 88, 173, 118, 237, 105, 110, 227, 29, 155, 167, 188, 224,
    191, 54, 207, 37, 32, 109, 100, 32, 148, 41, 240, 101, 227, 201, 186, 11, 246, 191, 137, 112, 185, 109, 225, 250, 127, 69, 148, 214, 33, 230, 118, 179, 223, 43, 70, 221, 226, 34, 72, 187,
    14, 178, 153, 217, 212, 135, 69, 107, 87, 178, 244, 126, 82, 130, 63, 0, 197, 143, 126, 60, 189, 59, 192, 14, 85, 214, 76, 181, 109, 213, 253, 56, 33, 219, 2, 242, 119, 16, 179, 182,
    63, 240, 17, 132, 104, 118, 251, 53, 141, 255, 127, 36, 177, 213, 232, 247, 203, 97, 171, 240, 195, 82, 72, 146, 87, 66, 166, 236, 22, 154, 143, 148, 147, 54, 136, 223, 71, 74, 90, 24,
    118, 100, 196, 25, 63, 85, 182, 217, 55, 184, 103, 0, 140, 209, 71, 81, 239, 29, 201, 72, 120, 188, 154, 218, 73, 90, 33, 246, 254, 232, 117, 50, 153, 196, 107, 25, 27, 241, 223, 74,
    58, 132, 252, 237, 105, 145, 54, 89, 77, 47, 174, 230, 43, 220, 100, 82, 22, 91, 37, 154, 14, 104, 138, 184, 209, 40, 57, 79, 238, 255, 224, 139, 236, 31, 217, 203, 100, 161, 94, 79,
    244, 115, 70, 180, 41, 47, 140, 58, 80, 65, 214, 3, 90, 47, 223, 114, 80, 88, 32, 194, 91, 236, 141, 248, 246, 68, 120, 171, 112, 110, 111, 8, 185, 2, 124, 183, 53, 164, 115, 122,
    59, 236, 151, 17, 255, 106, 148, 23, 175, 231, 187, 54, 235, 65, 58, 141, 219, 164, 134, 242, 122, 249, 93, 75, 129, 164, 24, 84, 40, 219, 216, 208, 61, 40, 58, 132, 184, 196, 192, 50,
    236, 226, 138, 55, 120, 100, 116, 252, 27, 4, 134, 77, 35, 36, 176, 219, 218, 193, 124, 119, 59, 93, 78, 207, 167, 51, 170, 187, 31, 22, 159, 108, 173, 55, 18, 236, 154, 39, 102, 103,
    105, 113, 51, 175, 144, 97, 240, 212, 110, 225, 104, 100, 172, 117, 123, 230, 246, 54, 50, 188, 109, 225, 218, 6, 80, 166, 229, 120, 174, 66, 119, 242, 190, 59, 243, 162, 221, 122, 58, 112,
    58, 31, 108, 218, 18, 180, 146, 125, 161, 173, 254, 72, 247, 240, 34, 226, 246, 224, 54, 67, 228, 118, 214, 177, 135, 251, 55, 204, 119, 69, 76, 141, 140, 134, 231, 244, 236, 236, 12, 205,
    91, 243, 247, 167, 207, 252, 106, 241, 233, 51, 127, 202, 44, 87, 134, 207, 78, 199, 211, 219, 64, 118, 148, 15, 155, 5, 214, 179, 211, 205, 137, 172, 135, 15, 100, 13, 154, 61, 14, 67,
    88, 211, 230, 108, 86, 153, 244, 90, 157, 205, 154, 64, 211, 2, 158, 84, 251, 101, 245, 243, 176, 199, 149, 92, 157, 170, 28, 94, 33, 49, 113, 239, 236, 180, 57, 93, 181, 247, 42, 65,
    173, 32, 77, 77, 161, 114, 27, 240, 15, 69, 227, 16, 105, 70, 199, 163, 68, 7, 46, 13, 146, 152, 191, 169, 115, 114, 137, 9, 43, 141, 19, 174, 13, 155, 24, 153, 133, 35, 216, 156,
    201, 177, 10, 0, 36, 118, 102, 20, 42, 227, 2, 57, 75, 17, 69, 210, 144, 231, 163, 226, 146, 199, 128, 31, 102, 49, 207, 122, 52, 184, 234, 32, 203, 146, 219, 212, 196, 51, 109, 2,
    235, 58, 52, 144, 128, 192, 198, 35, 151, 134, 137, 9, 248, 75, 252, 97, 26, 231, 111, 52, 106, 92, 186, 216, 140, 210, 216, 144, 12, 158, 16, 153, 1, 175, 225, 193, 146, 113, 145, 131,
    150, 220, 211, 19, 135, 138, 231, 46, 166, 134, 20, 165, 54, 196, 255, 202, 154, 48, 85, 97, 174, 227, 48, 117, 51, 192, 139, 67, 19, 90, 30, 216, 122, 149, 106, 80, 171, 226, 81, 136,
    118, 169, 36, 116, 42, 48, 64, 75, 202, 103, 33, 207, 115, 181, 108, 29, 58, 96, 100, 2, 5, 182, 133, 184, 104, 164, 167, 58, 80, 86, 43, 80, 14, 58, 149, 9, 114, 157, 6, 153,
    205, 130, 28, 96, 172, 102, 139, 149, 202, 66, 158, 14, 154, 24, 158, 177, 22, 234, 216, 22, 9, 10, 240, 143, 76, 11, 45, 184, 97, 85, 62, 66, 78, 232, 242, 80, 171, 48, 179, 161,
    118, 160, 51, 159, 129, 186, 196, 165, 151, 218, 128, 61, 89, 6, 194, 248, 35, 12, 210, 4, 23, 143, 148, 78, 67, 155, 147, 132, 80, 27, 166, 134, 70, 197, 68, 7, 0, 32, 18, 191,
    58, 195, 37, 99, 27, 76, 104, 110, 67, 99, 245, 40, 230, 241, 108, 0, 109, 242, 56, 76, 120, 206, 166, 13, 121, 188, 104, 44, 92, 74, 88, 11, 127, 241, 149, 178, 200, 55, 164, 11,
    124, 9, 65, 174, 97, 110, 224, 180, 48, 196, 24, 178, 64, 165, 110, 20, 130, 49, 6, 221, 157, 224, 98, 144, 198, 147, 71, 29, 10, 146, 161, 54, 229, 217, 189, 144, 25, 178, 5, 87,
    10, 28, 89, 162, 73, 157, 74, 44, 207, 91, 242, 44, 49, 42, 224, 159, 103, 137, 1, 62, 151, 176, 219, 72, 15, 79, 9, 229, 95, 206, 14, 187, 133, 68, 184, 153, 182, 32, 120, 100,
    98, 7, 172, 6, 69, 80, 147, 23, 116, 56, 193, 59, 29, 146, 61, 153, 70, 67, 33, 1, 153, 121, 161, 156, 73, 99, 178, 211, 36, 118, 196, 62, 87, 164, 195, 228, 9, 153, 109, 193,
    26, 84, 49, 172, 143, 139, 66, 31, 128, 143, 87, 161, 97, 43, 82, 161, 195, 178, 61, 224, 53, 68, 154, 210, 98, 108, 0, 137, 212, 73, 12, 177, 204, 208, 151, 104, 49, 79, 84, 181,
    148, 29, 21, 67, 212, 64, 184, 156, 17, 202, 19, 98, 93, 200, 195, 121, 77, 2, 129, 46, 178, 84, 5, 252, 147, 102, 130, 193, 232, 37, 13, 126, 66, 66, 244, 11, 8, 138, 101, 143,
    42, 23, 16, 12, 197, 17, 156, 85, 134, 50, 1, 141, 11, 83, 240, 56, 85, 14, 218, 149, 38, 114, 222, 33, 215, 145, 178, 43, 16, 13, 213, 51, 144, 92, 75, 9, 1, 249, 84, 77,
    167, 77, 152, 27, 77, 197, 96, 125, 92, 209, 36, 202, 44, 30, 9, 214, 80, 62, 81, 28, 125, 162, 249, 167, 29, 228, 93, 5, 14, 73, 41, 184, 22, 144, 217, 242, 155, 80, 231, 129,
    87, 7, 192, 158, 16, 96, 28, 230, 137, 42, 120, 116, 47, 255, 68, 241, 19, 154, 141, 204, 129, 120, 35, 88, 50, 150, 145, 139, 150, 234, 34, 252, 200, 211, 154, 45, 181, 84, 202, 171,
    196, 137, 96, 21, 154, 167, 50, 227, 207, 107, 172, 78, 200, 65, 180, 5, 124, 130, 88, 210, 198, 64, 247, 200, 143, 52, 159, 89, 146, 23, 251, 126, 10, 76, 134, 98, 228, 140, 139, 83,
    92, 81, 210, 66, 22, 64, 139, 117, 84, 77, 242, 208, 10, 53, 212, 86, 155, 167, 5, 218, 172, 217, 81, 252, 21, 170, 121, 50, 45, 216, 56, 162, 93, 192, 67, 134, 82, 25, 44, 17,
    21, 139, 231, 33, 187, 12, 218, 65, 236, 60, 120, 56, 97, 78, 204, 227, 230, 120, 156, 52, 143, 168, 148, 198, 232, 12, 40, 32, 139, 138, 121, 153, 228, 56, 80, 1, 5, 52, 40, 152,
    177, 227, 217, 18, 80, 104, 32, 48, 25, 37, 21, 108, 205, 12, 107, 208, 44, 100, 97, 106, 52, 197, 150, 6, 137, 96, 197, 254, 134, 60, 16, 153, 10, 66, 249, 65, 31, 100, 201, 21,
    216, 75, 245, 73, 104, 160, 32, 125, 48, 98, 73, 238, 64, 155, 150, 107, 170, 216, 17, 232, 66, 176, 47, 7, 26, 23, 228, 151, 248, 133, 133, 11, 105, 253, 50, 24, 9, 152, 22, 7,
    162, 211, 140, 173, 1, 229, 73, 30, 247, 252, 57, 179, 127, 208, 163, 115, 91, 88, 121, 8, 23, 55, 124, 67, 0, 97, 112, 53, 30, 7, 207, 90, 190, 66, 83, 98, 92, 158, 23, 202,
    1, 43, 152, 235, 47, 34, 200, 114, 176, 45, 185, 175, 51, 30, 86, 45, 191, 94, 145, 243, 52, 208, 25, 44, 40, 58, 11, 50, 22, 83, 163, 97, 159, 105, 170, 121, 148, 112, 22, 242,
    12, 97, 231, 102, 206, 89, 49, 249, 232, 108, 116, 24, 85, 6, 210, 50, 66, 89, 210, 202, 86, 133, 244, 12, 80, 90, 88, 30, 93, 168, 4, 170, 2, 225, 244, 23, 49, 135, 0, 16,
    210, 105, 41, 184, 1, 128, 78, 83, 116, 38, 228, 32, 165, 118, 195, 148, 43, 138, 31, 122, 19, 221, 146, 161, 233, 96, 187, 141, 227, 34, 213, 52, 76, 43, 95, 129, 98, 169, 187, 130,
    152, 241, 196, 101, 149, 62, 231, 249, 116, 105, 144, 199, 180, 186, 66, 126, 66, 237, 206, 17, 228, 160, 27, 76, 58, 202, 96, 250, 115, 30, 196, 109, 80, 193, 193, 65, 234, 20, 242, 158,
    80, 94, 99, 116, 169, 198, 143, 203, 18, 218, 93, 138, 6, 36, 67, 235, 68, 93, 169, 60, 167, 43, 43, 232, 47, 248, 39, 184, 41, 50, 177, 29, 65, 198, 64, 119, 30, 164, 52, 172,
    144, 166, 212, 92, 66, 219, 146, 25, 236, 179, 54, 5, 53, 73, 180, 137, 53, 96, 166, 92, 10, 81, 72, 233, 53, 18, 154, 80, 158, 153, 7, 39, 16, 95, 242, 236, 74, 59, 19, 175,
    102, 174, 12, 15, 21, 206, 11, 88, 116, 134, 69, 77, 75, 105, 160, 99, 30, 86, 110, 53, 205, 154, 191, 52, 234, 167, 105, 15, 50, 74, 178, 147, 63, 225, 174, 162, 126, 248, 144, 128,
    38, 197, 57, 110, 79, 32, 255, 33, 75, 84, 215, 16, 221, 71, 121, 133, 66, 5, 20, 113, 88, 64, 152, 118, 152, 94, 75, 177, 134, 168, 165, 188, 80, 223, 81, 20, 26, 3, 206, 208,
    46, 67, 79, 209, 107, 57, 124, 37, 196, 156, 86, 40, 39, 12, 13, 197, 129, 9, 6, 245, 240, 168, 46, 135, 87, 229, 129, 235, 232, 204, 4, 154, 196, 131, 66, 193, 62, 69, 116, 72,
    225, 1, 214, 176, 222, 244, 127, 52, 200, 244, 125, 108, 105, 78, 70, 0, 181, 56, 15, 77, 135, 136, 81, 35, 238, 44, 250, 63, 118, 42, 100, 40, 1, 158, 90, 158, 99, 141, 76, 92,
    19, 104, 24, 220, 57, 43, 103, 25, 164, 84, 51, 230, 161, 86, 7, 148, 23, 16, 110, 92, 198, 88, 71, 137, 18, 200, 165, 225, 165, 36, 184, 231, 224, 28, 152, 6, 83, 12, 90, 201,
    212, 56, 95, 221, 57, 149, 222, 154, 68, 207, 64, 56, 153, 135, 242, 105, 50, 82, 104, 124, 74, 99, 6, 9, 179, 162, 9, 70, 165, 51, 246, 170, 163, 122, 56, 186, 116, 24, 114, 93,
    240, 220, 72, 74, 148, 105, 186, 8, 122, 6, 159, 142, 82, 169, 78, 82, 113, 172, 114, 241, 221, 4, 229, 160, 235, 25, 193, 245, 160, 71, 0, 199, 102, 97, 166, 40, 218, 244, 96, 8,
    196, 124, 232, 69, 0, 48, 129, 144, 117, 186, 104, 154, 20, 37, 71, 129, 195, 92, 42, 154, 64, 148, 69, 152, 228, 160, 136, 26, 82, 148, 34, 37, 131, 247, 210, 40, 14, 67, 157, 202,
    77, 200, 248, 6, 28, 6, 167, 19, 137, 171, 20, 93, 146, 28, 231, 173, 236, 43, 35, 134, 218, 88, 40, 62, 188, 2, 88, 26, 23, 8, 4, 98, 244, 80, 115, 241, 188, 131, 150, 161,
    83, 225, 143, 225, 157, 3, 18, 199, 11, 72, 133, 106, 187, 108, 166, 51, 158, 40, 158, 140, 216, 209, 218, 48, 224, 128, 16, 66, 43, 156, 162, 64, 66, 199, 161, 218, 232, 121, 152, 107,
    22, 100, 111, 197, 241, 23, 104, 31, 218, 18, 52, 23, 177, 242, 38, 131, 101, 210, 49, 156, 138, 131, 126, 194, 250, 163, 191, 18, 158, 167, 200, 112, 24, 26, 228, 224, 125, 25, 157, 82,
    42, 224, 129, 69, 36, 172, 196, 78, 16, 83, 170, 26, 44, 166, 163, 229, 145, 19, 193, 37, 74, 131, 85, 13, 117, 66, 52, 217, 21, 15, 139, 36, 252, 76, 2, 37, 22, 101, 20, 134,
    56, 132, 102, 156, 91, 217, 36, 162, 10, 249, 141, 0, 200, 215, 140, 170, 109, 216, 32, 180, 103, 68, 73, 167, 216, 208, 211, 82, 198, 120, 96, 58, 164, 128, 33, 233, 27, 157, 233, 100,
    68, 241, 69, 77, 246, 27, 21, 74, 156, 40, 98, 149, 76, 130, 53, 26, 113, 43, 130, 110, 178, 87, 150, 86, 43, 181, 48, 246, 192, 137, 136, 204, 209, 214, 9, 31, 4, 37, 13, 54,
    163, 3, 68, 90, 8, 160, 121, 6, 188, 252, 250, 88, 155, 162, 147, 234, 17, 236, 82, 64, 115, 75, 161, 165, 110, 106, 4, 157, 208, 113, 39, 236, 86, 174, 137, 241, 33, 178, 144, 25,
    8, 153, 40, 7, 8, 135, 181, 162, 204, 192, 150, 225, 73, 243, 92, 126, 0, 135, 50, 49, 170, 199, 5, 148, 66, 52, 168, 41, 112, 62, 84, 111, 150, 72, 10, 157, 36, 252, 20, 130,
    252, 122, 87, 1, 163, 140, 113, 247, 8, 193, 57, 236, 33, 93, 22, 123, 38, 69, 247, 177, 31, 33, 115, 248, 101, 188, 6, 198, 81, 65, 2, 231, 59, 39, 93, 117, 14, 35, 121, 96,
    224, 105, 167, 248, 181, 58, 189, 69, 12, 1, 1, 204, 26, 102, 65, 51, 226, 145, 183, 147, 116, 42, 100, 162, 226, 217, 240, 49, 99, 101, 10, 47, 194, 164, 68, 139, 174, 200, 17, 244,
    52, 158, 136, 199, 32, 44, 12, 219, 131, 60, 129, 42, 106, 4, 82, 254, 215, 155, 109, 126, 134, 66, 204, 163, 230, 96, 164, 185, 72, 22, 143, 116, 135, 139, 129, 81, 98, 116, 196, 31,
    63, 180, 50, 252, 166, 131, 27, 73, 172, 192, 143, 30, 128, 97, 252, 140, 2, 53, 13, 66, 65, 243, 0, 231, 18, 8, 87, 209, 221, 133, 227, 241, 182, 129, 255, 245, 129, 150, 137, 37,
    146, 0, 91, 21, 45, 188, 191, 52, 29, 195, 112, 94, 103, 35, 205, 16, 17, 81, 17, 71, 50, 12, 50, 80, 218, 74, 16, 175, 197, 5, 133, 60, 103, 95, 51, 244, 198, 45, 236, 96,
    64, 255, 68, 59, 144, 175, 226, 129, 114, 204, 127, 251, 227, 1, 14, 63, 253, 184, 117, 58, 30, 182, 247, 47, 53, 227, 216, 118, 210, 217, 41, 167, 243, 214, 165, 87, 91, 104, 154, 146,
    171, 71, 196, 24, 91, 41, 156, 2, 57, 251, 106, 81, 92, 4, 197, 124, 44, 167, 55, 96, 96, 187, 40, 79, 207, 23, 24, 30, 95, 23, 243, 61, 197, 191, 154, 94, 157, 85, 11, 150,
    144, 141, 223, 124, 123, 201, 47, 173, 7, 71, 60, 125, 170, 47, 167, 79, 129, 120, 212, 70, 27, 174, 207, 78, 167, 92, 20, 245, 231, 231, 203, 225, 87, 160, 111, 189, 125, 188, 129, 239,
    7, 244, 65, 129, 33, 255, 117, 61, 148, 83, 172, 6, 1, 127, 163, 139, 95, 122, 60, 26, 203, 191, 170, 219, 222, 180, 239, 119, 233, 3, 195, 152, 67, 249, 103, 190, 249, 254, 161, 97,
    66, 247, 240, 176, 6, 83, 175, 189, 164, 26, 52, 103, 59, 180, 103, 7, 186, 155, 153, 219, 57, 189, 243, 234, 231, 64, 246, 184, 118, 42, 172, 119, 31, 183, 209, 183, 178, 100, 22, 242,
    64, 94, 93, 93, 175, 91, 176, 149, 191, 198, 166, 255, 174, 216, 204, 223, 21, 155, 253, 253, 176, 249, 223, 235, 182, 32, 200, 146, 244, 74, 162, 215, 75, 195, 94, 72, 55, 224, 246, 205,
    154, 238, 203, 223, 145, 51, 84, 216, 42, 226, 103, 51, 3, 255, 86, 107, 51, 7, 249, 233, 3, 4, 202, 172, 228, 22, 140, 245, 76, 229, 89, 252, 169, 80, 186, 205, 82, 212, 239, 172,
    69, 63, 44, 232, 156, 210, 218, 174, 241, 250, 205, 159, 30, 49, 15, 214, 158, 227, 114, 6, 193, 129, 73, 123, 205, 140, 88, 210, 158, 16, 227, 125, 107, 210, 172, 25, 215, 120, 115, 23,
    79, 70, 185, 57, 15, 252, 62, 205, 33, 231, 237, 246, 152, 62, 14, 129, 24, 146, 70, 49, 3, 26, 126, 239, 37, 120, 30, 240, 107, 33, 41, 162, 118, 227, 162, 92, 185, 65, 128, 208,
    42, 162, 223, 195, 248, 0, 37, 212, 128, 17, 96, 132, 113, 110, 96, 243, 36, 82, 24, 11, 61, 135, 213, 71, 89, 195, 184, 64, 71, 46, 55, 3, 12, 212, 93, 148, 230, 121, 96, 179,
    36, 210, 153, 69, 130, 73, 162, 148, 225, 121, 150, 69, 24, 238, 163, 14, 26, 37, 95, 219, 65, 72, 16, 165, 190, 72, 26, 37, 164, 35, 197, 53, 119, 76, 200, 34, 197, 239, 5, 33,
    193, 198, 137, 212, 201, 35, 195, 128, 45, 21, 10, 6, 146, 0, 179, 207, 97, 173, 148, 231, 77, 3, 155, 211, 25, 77, 114, 18, 229, 185, 184, 40, 126, 244, 167, 73, 200, 152, 192, 173,
    155, 177, 148, 71, 10, 125, 21, 73, 48, 164, 159, 95, 93, 225, 16, 62, 206, 81, 148, 64, 52, 191, 61, 196, 25, 49, 5, 102, 89, 212, 177, 104, 73, 156, 96, 104, 96, 163, 92, 39,
    3, 176, 71, 163, 104, 28, 240, 211, 46, 169, 202, 7, 91, 124, 5, 159, 209, 20, 103, 162, 36, 81, 168, 157, 198, 17, 120, 131, 33, 110, 4, 199, 7, 30, 243, 75, 49, 142, 236, 113,
    17, 28, 252, 128, 49, 78, 100, 25, 111, 169, 68, 190, 39, 4, 30, 131, 27, 142, 145, 162, 5, 7, 147, 120, 16, 88, 34, 180, 224, 113, 170, 35, 149, 162, 142, 5, 39, 25, 193, 34,
    108, 0, 71, 115, 210, 152, 167, 252, 106, 13, 35, 207, 40, 79, 192, 47, 131, 34, 46, 102, 24, 199, 254, 26, 180, 105, 122, 69, 175, 143, 76, 212, 55, 184, 230, 172, 15, 199, 26, 201,
    240, 33, 225, 39, 102, 128, 19, 227, 152, 40, 70, 64, 107, 98, 21, 229, 169, 102, 2, 191, 183, 148, 248, 4, 240, 244, 57, 39, 148, 162, 28, 161, 190, 164, 228, 44, 194, 166, 48, 90,
    205, 144, 97, 1, 68, 65, 110, 180, 12, 45, 65, 39, 174, 47, 17, 17, 131, 137, 28, 85, 163, 59, 93, 204, 97, 2, 75, 40, 246, 31, 174, 9, 75, 0, 170, 139, 189, 112, 196, 252,
    38, 86, 10, 238, 199, 28, 95, 51, 93, 161, 132, 167, 4, 164, 73, 14, 34, 100, 149, 243, 123, 55, 130, 150, 37, 95, 114, 164, 13, 166, 103, 130, 95, 190, 176, 149, 107, 201, 1, 243,
    80, 147, 60, 54, 153, 138, 48, 44, 6, 61, 105, 4, 200, 224, 87, 106, 164, 147, 149, 147, 118, 51, 1, 12, 100, 172, 142, 4, 142, 102, 159, 115, 130, 9, 237, 117, 62, 37, 35, 143,
    217, 8, 198, 151, 16, 21, 4, 191, 131, 29, 190, 190, 10, 226, 72, 194, 157, 36, 147, 244, 231, 242, 204, 136, 25, 90, 128, 34, 140, 188, 33, 224, 136, 238, 248, 152, 82, 170, 83, 126,
    102, 42, 145, 146, 57, 6, 140, 228, 28, 164, 145, 217, 57, 134, 154, 136, 218, 163, 204, 63, 166, 148, 250, 100, 83, 218, 49, 18, 79, 248, 121, 35, 1, 6, 29, 102, 246, 160, 75, 65,
    111, 29, 2, 93, 183, 44, 86, 243, 166, 236, 202, 244, 119, 183, 26, 157, 237, 156, 240, 186, 101, 219, 15, 111, 218, 217, 111, 25, 219, 175, 194, 118, 226, 131, 245, 187, 1, 27, 187, 168,
    25, 42, 114, 86, 207, 113, 226, 127, 36, 187, 249, 247, 212, 241, 219, 252, 131, 197, 16, 97, 226, 232, 221, 16, 229, 71, 63, 227, 23, 109, 245, 85, 246, 53, 122, 207, 171, 194, 13, 228,
    3, 219, 157, 206, 214, 199, 254, 5, 254, 107, 121, 81, 20, 181, 156, 135, 223, 2, 182, 126, 49, 157, 152, 218, 27, 78, 24, 112, 49, 180, 27, 182, 94, 248, 245, 241, 91, 83, 209, 227,
    238, 108, 177, 121, 220, 98, 138, 119, 23, 92, 144, 90, 185, 11, 185, 239, 174, 159, 112, 214, 183, 137, 143, 197, 67, 52, 222, 66, 118, 188, 6, 237, 183, 32, 134, 58, 232, 190, 218, 48,
    148, 117, 162, 118, 34, 15, 34, 247, 169, 155, 249, 181, 43, 165, 101, 206, 53, 76, 49, 134, 76, 123, 237, 153, 55, 5, 45, 215, 47, 220, 90, 244, 130, 63, 85, 1, 27, 121, 250, 236,
    188, 105, 102, 199, 239, 182, 14, 197, 124, 191, 215, 253, 251, 120, 216, 201, 4, 195, 62, 253, 40, 15, 11, 215, 2, 21, 132, 238, 61, 231, 55, 245, 100, 2, 5, 78, 47, 73, 232, 92,
    97, 147, 248, 141, 189, 156, 159, 254, 67, 2, 125, 29, 188, 136, 117, 252, 142, 156, 216, 96, 99, 97, 165, 82, 140, 78, 147, 198, 183, 242, 163, 91, 28, 63, 107, 80, 68, 24, 206, 240,
    19, 94, 132, 145, 55, 246, 132, 254, 204, 26, 216, 211, 188, 241, 171, 150, 227, 215, 204, 70, 154, 246, 151, 126, 149, 159, 188, 163, 45, 133, 217, 144, 242, 240, 15, 218, 219, 121, 229, 93,
    100, 70, 91, 45, 166, 4, 198, 173, 241, 197, 244, 45, 110, 83, 39, 245, 214, 5, 254, 163, 1, 11, 2, 101, 92, 102, 97, 60, 157, 167, 43, 167, 140, 25, 241, 201, 104, 50, 220, 71,
    32, 198, 63, 163, 43, 130, 59, 136, 233, 47, 13, 138, 211, 95, 174, 185, 68, 142, 193, 120, 179, 141, 64, 47, 222, 54, 205, 163, 20, 49, 8, 109, 173, 69, 155, 66, 235, 185, 150, 240,
    91, 131, 192, 157, 243, 75, 133, 90, 6, 167, 207, 57, 97, 197, 143, 153, 5, 48, 194, 192, 64, 199, 8, 162, 29, 103, 115, 193, 1, 71, 55, 72, 79, 105, 157, 37, 127, 16, 106, 144,
    203, 224, 27, 28, 62, 124, 1, 108, 165, 165, 129, 52, 25, 154, 149, 114, 92, 30, 101, 218, 14, 182, 41, 122, 37, 94, 35, 225, 210, 1, 76, 53, 125, 198, 75, 241, 178, 25, 204, 177,
    66, 52, 148, 112, 94, 2, 87, 206, 12, 107, 67, 175, 18, 211, 71, 225, 78, 60, 1, 252, 75, 222, 148, 208, 156, 11, 142, 45, 63, 17, 216, 192, 224, 154, 162, 129, 135, 78, 224, 87,
    85, 234, 192, 29, 144, 129, 38, 208, 241, 66, 128, 208, 8, 195, 153, 229, 4, 94, 44, 207, 233, 78, 25, 7, 0, 72, 106, 89, 133, 9, 224, 14, 36, 198, 160, 110, 238, 132, 50, 196,
    1, 113, 234, 125, 35, 194, 11, 153, 133, 4, 191, 132, 150, 151, 226, 5, 184, 194, 103, 98, 116, 160, 124, 143, 17, 84, 38, 116, 242, 185, 4, 65, 207, 197, 255, 200, 23, 249, 224, 65,
    13, 101, 74, 103, 185, 231, 14, 63, 27, 40, 129, 69, 204, 160, 141, 31, 146, 68, 240, 40, 49, 21, 179, 184, 98, 225, 195, 70, 118, 56, 63, 161, 135, 110, 1, 17, 254, 33, 227, 228,
    97, 42, 62, 212, 82, 54, 116, 147, 133, 110, 203, 32, 188, 6, 194, 152, 208, 37, 26, 68, 33, 244, 249, 198, 209, 163, 167, 160, 216, 64, 28, 56, 7, 71, 46, 113, 234, 217, 88, 202,
    160, 21, 62, 166, 150, 190, 158, 244, 196, 177, 145, 182, 217, 220, 52, 37, 32, 243, 70, 75, 100, 177, 130, 209, 138, 6, 18, 122, 105, 45, 253, 74, 108, 47, 133, 70, 199, 57, 35, 240,
    94, 176, 196, 232, 45, 249, 44, 38, 21, 73, 11, 231, 114, 241, 234, 150, 139, 77, 128, 156, 114, 238, 110, 157, 75, 200, 164, 114, 85, 127, 91, 98, 36, 14, 16, 173, 203, 124, 12, 160,
    99, 207, 251, 212, 73, 28, 16, 107, 207, 120, 50, 47, 22, 241, 103, 174, 143, 88, 99, 31, 175, 130, 69, 194, 254, 213, 35, 53, 112, 83, 58, 89, 245, 69, 3, 140, 1, 163, 47, 237,
    209, 66, 76, 180, 219, 60, 102, 91, 113, 192, 230, 176, 194, 135, 99, 0, 127, 44, 134, 56, 189, 77, 61, 127, 46, 225, 238, 16, 176, 57, 152, 165, 94, 188, 11, 138, 11, 140, 248, 164,
    90, 227, 236, 182, 156, 163, 254, 253, 189, 227, 198, 55, 254, 151, 245, 140, 173, 67, 142, 27, 126, 140, 154, 121, 170, 77, 48, 214, 126, 223, 200, 115, 168, 241, 161, 91, 47, 34, 5, 187,
    175, 47, 245, 222, 207, 76, 225, 210, 232, 102, 177, 40, 231, 181, 127, 193, 109, 119, 39, 7, 223, 178, 88, 49, 91, 238, 59, 236, 206, 185, 232, 198, 159, 246, 62, 14, 151, 230, 42, 200,
    224, 133, 10, 113, 136, 171, 61, 2, 57, 215, 12, 110, 195, 52, 117, 151, 33, 198, 25, 111, 88, 226, 50, 84, 191, 92, 197, 97, 102, 147, 248, 22, 25, 47, 18, 136, 253, 27, 155, 117,
    107, 178, 116, 16, 255, 242, 202, 114, 79, 1, 18, 89, 242, 18, 208, 246, 20, 36, 10, 0, 12, 8, 240, 1, 236, 168, 75, 236, 191, 188, 130, 61, 111, 129, 4, 81, 7, 112, 127, 0,
    200, 56, 72, 16, 229, 119, 75, 54, 15, 151, 40, 122, 75, 136, 47, 240, 240, 69, 167, 132, 175, 245, 203, 21, 97, 132, 54, 205, 47, 9, 246, 13, 217, 241, 98, 151, 147, 66, 21, 49,
    217, 84, 61, 136, 41, 137, 95, 236, 52, 168, 121, 88, 161, 66, 89, 162, 186, 101, 217, 189, 152, 18, 105, 19, 63, 36, 247, 91, 97, 66, 251, 15, 182, 9, 65, 76, 194, 85, 80, 91,
    208, 197, 185, 102, 129, 49, 104, 30, 46, 45, 198, 244, 59, 57, 156, 122, 127, 163, 17, 60, 116, 114, 194, 38, 231, 197, 222, 28, 62, 220, 18, 90, 219, 116, 238, 234, 156, 88, 190, 47,
    169, 168, 124, 215, 183, 106, 141, 15, 54, 58, 186, 62, 42, 98, 55, 171, 243, 182, 217, 193, 12, 121, 253, 13, 248, 207, 94, 52, 103, 19, 6, 127, 254, 74, 48, 201, 236, 50, 44, 197,
    246, 113, 134, 129, 63, 57, 175, 215, 219, 7, 77, 38, 195, 206, 214, 147, 203, 15, 81, 180, 70, 252, 199, 213, 105, 72, 141, 254, 119, 176, 239, 61, 192, 240, 55, 39, 225, 75, 30, 2,
    24, 208, 45, 117, 144, 111, 157, 89, 248, 59, 161, 229, 169, 132, 123, 208, 174, 15, 43, 252, 205, 209, 174, 191, 6, 112, 221, 156, 115, 216, 193, 222, 57, 178, 239, 177, 40, 247, 205, 121,
    118, 14, 217, 255, 205, 157, 12, 223, 126, 253, 40, 47, 243, 24, 207, 162, 57, 36, 224, 79, 219, 179, 104, 126, 148, 59, 79, 179, 203, 48, 145, 213, 64, 89, 121, 245, 155, 151, 184, 192,
    110, 223, 96, 92, 130, 116, 89, 105, 108, 54, 213, 112, 237, 44, 153, 217, 36, 180, 73, 59, 71, 182, 1, 185, 236, 165, 98, 124, 111, 149, 237, 228, 113, 15, 83, 16, 207, 66, 68, 102,
    221, 90, 252, 122, 183, 95, 24, 107, 227, 230, 138, 51, 44, 16, 98, 236, 47, 148, 124, 131, 93, 53, 11, 224, 242, 97, 116, 88, 45, 46, 51, 22, 237, 172, 208, 63, 196, 183, 219, 205,
    224, 178, 41, 76, 214, 118, 51, 136, 22, 68, 129, 162, 157, 118, 176, 21, 65, 252, 18, 77, 224, 70, 132, 173, 38, 202, 202, 53, 130, 103, 155, 124, 209, 225, 10, 134, 81, 129, 199, 209,
    101, 97, 144, 90, 216, 232, 120, 155, 86, 174, 41, 186, 219, 237, 70, 4, 62, 67, 93, 38, 182, 3, 40, 240, 128, 130, 78, 3, 200, 51, 45, 13, 8, 118, 58, 66, 168, 84, 140, 207,
    185, 19, 165, 157, 37, 109, 219, 237, 60, 238, 160, 137, 101, 13, 177, 141, 54, 229, 122, 49, 88, 154, 108, 245, 2, 101, 70, 179, 27, 246, 52, 128, 187, 63, 213, 237, 182, 52, 5, 190,
    71, 131, 46, 74, 206, 86, 235, 217, 158, 6, 120, 42, 21, 23, 236, 183, 27, 32, 221, 179, 167, 219, 148, 44, 253, 154, 173, 22, 136, 16, 235, 203, 237, 22, 144, 120, 17, 166, 219, 125,
    130, 36, 194, 244, 47, 175, 148, 20, 74, 208, 169, 84, 28, 235, 249, 202, 245, 97, 238, 224, 242, 9, 62, 145, 139, 219, 254, 225, 95, 30, 225, 251, 94, 55, 38, 228, 119, 246, 124, 252,
    16, 25, 63, 158, 230, 205, 160, 95, 42, 133, 1, 107, 62, 169, 118, 118, 90, 93, 203, 121, 121, 178, 86, 52, 156, 44, 154, 213, 212, 114, 188, 246, 92, 167, 207, 124, 145, 237, 162, 203,
    51, 46, 135, 6, 203, 119, 203, 186, 188, 218, 20, 122, 230, 1, 60, 218, 92, 251, 217, 77, 121, 59, 182, 249, 96, 218, 246, 178, 237, 234, 236, 56, 177, 223, 187, 47, 188, 54, 224, 247,
    230, 248, 87, 97, 207, 130, 211, 89, 113, 94, 206, 130, 73, 181, 120, 0, 66, 251, 125, 89, 144, 47, 85, 30, 112, 1, 237, 55, 89, 27, 8, 237, 164, 189, 243, 156, 221, 247, 145, 2,
    126, 93, 105, 59, 109, 119, 44, 183, 245, 22, 216, 233, 102, 176, 166, 91, 243, 114, 114, 223, 177, 243, 42, 214, 86, 126, 122, 157, 193, 199, 227, 188, 74, 123, 84, 231, 31, 218, 195, 16,
    78, 157, 197, 38, 82, 163, 80, 229, 145, 225, 6, 91, 14, 233, 163, 148, 87, 3, 123, 198, 241, 254, 136, 27, 17, 34, 23, 36, 81, 202, 177, 163, 74, 35, 78, 23, 68, 230, 101, 226,
    184, 83, 66, 71, 233, 200, 49, 41, 162, 205, 143, 160, 251, 81, 234, 11, 201, 141, 142, 168, 134, 218, 68, 89, 152, 68, 70, 42, 134, 146, 155, 3, 139, 34, 76, 27, 114, 254, 13, 246,
    27, 69, 108, 26, 193, 22, 40, 73, 192, 144, 35, 212, 169, 29, 197, 204, 204, 89, 205, 69, 9, 8, 11, 141, 141, 114, 92, 127, 217, 140, 34, 215, 179, 238, 235, 183, 222, 254, 47, 51,
    54, 79, 18, 176, 195, 234, 44, 226, 86, 118, 5, 226, 19, 254, 128, 114, 195, 237, 229, 104, 71, 146, 9, 35, 226, 72, 135, 70, 163, 61, 54, 199, 15, 103, 185, 194, 92, 71, 220, 250,
    102, 240, 204, 213, 72, 203, 44, 240, 136, 246, 214, 134, 156, 162, 228, 102, 90, 84, 230, 10, 83, 200, 41, 61, 206, 50, 178, 134, 38, 163, 44, 111, 51, 38, 160, 91, 49, 232, 136, 184,
    213, 42, 146, 173, 51, 81, 134, 238, 66, 162, 118, 113, 196, 173, 223, 46, 50, 111, 114, 217, 178, 212, 112, 55, 21, 238, 242, 255, 229, 150, 32, 112, 170, 206, 81, 16, 40, 37, 76, 15,
    36, 29, 255, 95, 114, 230, 71, 141, 188, 248, 4, 178, 77, 86, 114, 5, 72, 7, 230, 101, 152, 37, 81, 50, 114, 14, 13, 115, 9, 136, 225, 186, 87, 22, 114, 34, 17, 66, 152, 82,
    28, 184, 34, 201, 14, 97, 211, 115, 73, 84, 144, 43, 35, 51, 200, 6, 195, 63, 144, 205, 69, 215, 128, 147, 101, 220, 71, 24, 113, 91, 97, 70, 49, 75, 12, 161, 56, 197, 251, 21,
    8, 169, 73, 24, 161, 212, 20, 32, 161, 35, 161, 0, 194, 157, 115, 82, 19, 80, 116, 200, 154, 137, 64, 209, 242, 238, 0, 185, 14, 110, 69, 220, 191, 13, 146, 228, 6, 189, 38, 206,
    10, 108, 11, 209, 59, 220, 49, 165, 80, 46, 201, 81, 71, 0, 146, 170, 208, 195, 35, 108, 246, 147, 105, 96, 163, 163, 200, 9, 194, 97, 191, 167, 172, 206, 190, 86, 92, 182, 11, 148,
    180, 151, 213, 216, 133, 156, 223, 14, 141, 136, 139, 200, 136, 100, 176, 57, 9, 139, 74, 137, 140, 154, 196, 18, 144, 167, 192, 10, 18, 104, 84, 150, 6, 142, 69, 160, 99, 116, 127, 228,
    24, 127, 40, 116, 129, 8, 93, 64, 161, 11, 68, 232, 2, 10, 93, 64, 161, 11, 40, 116, 1, 133, 46, 16, 161, 147, 37, 112, 203, 44, 206, 212, 114, 3, 90, 64, 161, 11, 68, 232,
    184, 182, 155, 178, 110, 26, 164, 17, 119, 112, 74, 127, 225, 39, 207, 137, 147, 119, 144, 121, 106, 60, 122, 152, 84, 161, 195, 40, 243, 4, 32, 26, 32, 100, 121, 13, 240, 116, 137, 6,
    8, 93, 162, 1, 66, 150, 104, 128, 144, 229, 21, 192, 211, 101, 188, 38, 4, 94, 5, 64, 150, 40, 128, 39, 11, 26, 224, 68, 23, 208, 159, 145, 243, 186, 64, 139, 228, 85, 161, 99,
    41, 54, 219, 145, 118, 95, 42, 221, 12, 58, 54, 78, 179, 25, 64, 52, 243, 83, 65, 107, 62, 175, 253, 186, 97, 227, 2, 218, 41, 123, 28, 64, 251, 245, 203, 15, 153, 204, 211, 173,
    165, 46, 189, 179, 212, 213, 50, 99, 171, 213, 27, 115, 110, 206, 131, 213, 113, 42, 171, 125, 81, 130, 236, 248, 86, 208, 45, 129, 239, 22, 238, 189, 136, 166, 213, 179, 121, 49, 175, 90,
    198, 203, 128, 155, 9, 95, 147, 113, 224, 170, 201, 11, 78, 68, 39, 121, 208, 92, 4, 35, 151, 14, 82, 163, 184, 102, 129, 80, 76, 22, 170, 57, 171, 221, 92, 99, 95, 136, 61, 15,
    93, 85, 226, 65, 178, 88, 214, 208, 185, 250, 157, 228, 153, 20, 77, 182, 46, 175, 51, 64, 197, 83, 194, 73, 127, 148, 109, 30, 5, 0, 247, 83, 130, 40, 71, 59, 202, 221, 213, 232,
    224, 132, 27, 253, 160, 115, 41, 183, 199, 102, 92, 204, 79, 61, 169, 158, 82, 33, 19, 209, 29, 55, 59, 56, 26, 75, 19, 103, 95, 88, 88, 24, 46, 48, 172, 174, 190, 49, 185, 166,
    246, 123, 66, 53, 36, 78, 182, 60, 66, 112, 56, 129, 207, 146, 8, 77, 249, 235, 239, 95, 211, 184, 64, 248, 160, 132, 156, 214, 247, 79, 168, 91, 48, 215, 26, 95, 138, 87, 15, 91,
    67, 226, 185, 61, 209, 184, 44, 178, 137, 250, 5, 62, 183, 169, 116, 25, 255, 109, 69, 104, 139, 236, 91, 65, 242, 183, 38, 45, 108, 229, 160, 124, 243, 24, 135, 173, 204, 219, 176, 169,
    209, 46, 235, 239, 15, 201, 253, 214, 107, 178, 77, 236, 182, 45, 234, 221, 40, 105, 235, 189, 186, 6, 212, 86, 234, 102, 124, 190, 231, 91, 59, 123, 7, 227, 155, 176, 210, 31, 166, 202,
    56, 219, 111, 116, 218, 121, 45, 241, 108, 125, 34, 112, 16, 6, 205, 167, 32, 130, 53, 194, 206, 161, 195, 103, 114, 46, 115, 131, 15, 165, 255, 247, 255, 130, 35, 208, 110, 107, 62, 190,
    253, 74, 173, 215, 223, 78, 202, 174, 254, 118, 190, 58, 178, 179, 25, 106, 253, 250, 237, 158, 225, 252, 74, 119, 121, 38, 77, 163, 210, 186, 187, 252, 250, 129, 11, 187, 54, 143, 197, 100,
    226, 23, 20, 92, 172, 181, 247, 85, 60, 80, 144, 230, 24, 177, 27, 92, 16, 4, 122, 0, 51, 171, 7, 220, 183, 50, 128, 165, 84, 155, 159, 75, 0, 134, 59, 150, 236, 88, 82, 194,
    117, 41, 58, 76, 69, 193, 34, 4, 184, 174, 44, 116, 98, 85, 105, 192, 87, 63, 75, 249, 29, 172, 50, 6, 252, 185, 245, 53, 6, 218, 91, 102, 64, 227, 166, 163, 144, 63, 114, 247,
    130, 112, 185, 167, 55, 74, 7, 177, 36, 75, 169, 112, 93, 10, 17, 159, 39, 219, 151, 89, 103, 110, 224, 52, 100, 123, 16, 146, 60, 88, 35, 146, 159, 21, 13, 160, 154, 196, 13, 214,
    196, 201, 207, 82, 232, 95, 165, 11, 229, 235, 118, 26, 137, 4, 192, 131, 112, 205, 3, 249, 17, 170, 159, 11, 115, 184, 130, 233, 128, 23, 254, 62, 229, 213, 243, 250, 151, 214, 123, 55,
    175, 12, 183, 57, 13, 12, 73, 113, 35, 168, 249, 128, 127, 68, 8, 163, 58, 64, 196, 193, 235, 82, 226, 15, 48, 62, 99, 84, 16, 37, 179, 140, 209, 30, 127, 70, 150, 81, 48, 72,
    231, 149, 97, 247, 128, 239, 24, 69, 102, 22, 110, 138, 132, 77, 25, 201, 247, 55, 40, 49, 136, 151, 82, 209, 87, 26, 72, 165, 196, 12, 18, 243, 66, 211, 221, 142, 216, 141, 4, 182,
    211, 105, 7, 121, 117, 201, 29, 81, 8, 199, 5, 202, 115, 3, 11, 14, 14, 107, 132, 107, 104, 139, 127, 160, 183, 230, 195, 166, 197, 194, 138, 103, 23, 93, 179, 179, 86, 14, 177, 54,
    205, 55, 246, 14, 152, 155, 103, 254, 61, 219, 103, 60, 164, 249, 236, 255, 0, 54, 101, 11, 183, 254, 145, 0, 0
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
