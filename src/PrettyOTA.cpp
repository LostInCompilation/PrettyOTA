/*

******************************************************
*                    PRETTY OTA                      *
*                                                    *
* A better looking Web-OTA.                          *
******************************************************

Description:
    The main source file.

Author:     Marc Schöndorf
License:    See LICENSE.md

*/

#include "PrettyOTA.hpp"

Stream* PrettyOTA::m_SerialMonitorStream = nullptr;

// ********************************************************
// SHA256 helpers
const char* const SHA256StringLookup = "0123456789abcdef";

String SHA256ToString(const uint8_t hash[32])
{
    String result = "";
    for(uint32_t i = 0; i < 32; i++)
    {
        result += SHA256StringLookup[hash[i] >> 4];
        result += SHA256StringLookup[hash[i] & 0x0F];
    }
    return result;
}

// ********************************************************
// Log functions
void PrettyOTA::LOG_I(String message)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println("\033[92mInfo: " + String(message) + "\033[0m");
}

void PrettyOTA::LOG_W(String message)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println("\033[93mWarning: " + String(message) + "\033[0m");
}

void PrettyOTA::LOG_E(String message)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println("\033[97;41m Error: " + String(message) + " \033[0m");
}

// ********************************************************
// OTA default callbacks
void PrettyOTA::OnOTAStart(UPDATE_MODE updateMode)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println("\n\n************************************************");
    m_SerialMonitorStream->println("*                 \033[1;7m OTA UPDATE \033[0m                 *");

    if(updateMode == UPDATE_MODE::FIRMWARE)
        m_SerialMonitorStream->println("*                   \033[1mFirmware\033[0m                   *");
    else
        m_SerialMonitorStream->println("*                  \033[1mFilesystem\033[0m                  *");

    m_SerialMonitorStream->println("************************************************\n");
    m_SerialMonitorStream->println("Starting OTA update...\n");
}

void PrettyOTA::OnOTAProgress(uint32_t currentSize, uint32_t totalSize)
{
    if (!m_SerialMonitorStream)
        return;

    static float lastPercentage = 0.0f;
    const float percentage = 100.0f * static_cast<float>(currentSize) / static_cast<float>(totalSize);
    const uint8_t numBarsToShow = static_cast<uint8_t>(percentage / 3.3333f);

    if(percentage - lastPercentage >= 1.0f)
    {
        m_SerialMonitorStream->print("Updating... [");
        for(uint8_t i = 0; i < 30; i++)
        {
            if (i < numBarsToShow)
                m_SerialMonitorStream->print("=");
            else
                m_SerialMonitorStream->print(" ");
        }
        m_SerialMonitorStream->printf("] %02u%%\n", static_cast<uint8_t>(percentage));

        m_SerialMonitorStream->print("\033[1F"); // Move cursor to begining of previous line
        lastPercentage = percentage;
    }
}

void PrettyOTA::OnOTAEnd(bool successful)
{
    if (!m_SerialMonitorStream)
        return;

    if (successful)
        m_SerialMonitorStream->println("Updating... [==============================] 100%");

    m_SerialMonitorStream->println("\n************************************************");

    if (successful)
        m_SerialMonitorStream->println("*           \033[1;92;7m OTA UPDATE SUCCESSFUL \033[0m            *");
    else
        m_SerialMonitorStream->println("*             \033[1;91;7m OTA UPDATE FAILED \033[0m              *");

    m_SerialMonitorStream->println("************************************************\n\n");
}

// ********************************************************
// UUID helpers
void PrettyOTA::GenerateUUID(UUID_t out_uuid) const
{
    esp_fill_random(out_uuid, sizeof(UUID_t));

    out_uuid[6] = 0x40 | (out_uuid[6] & 0xF);   // UUID version
    out_uuid[8] = (0x80 | out_uuid[8]) & ~0x40; // UUID variant
}

String PrettyOTA::UUIDToString(const UUID_t uuid) const
{
    char out[37] = {};

    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);

    return String(out);
}

// ********************************************************
// Check if client is authenticated
bool PrettyOTA::IsAuthenticated(const AsyncWebServerRequest* const request) const
{
    if(request->hasHeader("Cookie"))
    {
        const AsyncWebHeader* const cookie = request->getHeader("Cookie");

        for(uint32_t i = 0; i < MAX_NUM_LOGGED_IN_CLIENTS; i++)
        {
            if(strncmp(m_AuthenticatedSessionIDs[i], cookie->value().c_str(), 47) == 0)
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

    if(!passwordIsMD5Hash)
    {
        // Convert password to MD5 hash
        MD5Builder md5;
        md5.begin();
        md5.add(m_Password);
        md5.calculate();

        m_Password = md5.toString();
    }
}

// ********************************************************
// Begin
bool PrettyOTA::Begin(AsyncWebServer* const server, const char* const username, const char* const password, bool passwordIsMD5Hash, uint16_t OTAport)
{
    SetAuthenticationDetails(username, password, passwordIsMD5Hash);

    // ********************************************************
    // Login page "/login"
    server->on("/login", HTTP_GET | HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(request->method() != HTTP_GET)
            return;

        // Redirect to "/update" if already logged in
        if(!m_AuthenticationEnabled || IsAuthenticated(request))
            return request->redirect("/update", 302);

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
        if(loginData["userId"].as<String>() == m_Username && loginData["password"].as<String>() == m_Password)
        {
            // Generate session ID
            UUID_t id = {};
            GenerateUUID(id);
            const String idStr = "sessionID=" + UUIDToString(id);

            // Add session ID to known (authenticated) session IDs
            strncpy(m_AuthenticatedSessionIDs[m_NumLoggedInClients], idStr.c_str(), 46);
            m_AuthenticatedSessionIDs[m_NumLoggedInClients][46] = '\0';
            m_NumLoggedInClients++;

            // If max number of clients is logged in, start logging out the oldest client (remove its sessionID)
            if(m_NumLoggedInClients >= MAX_NUM_LOGGED_IN_CLIENTS)
                m_NumLoggedInClients = 0;

            // Send response and set session ID cookie
            AsyncWebServerResponse* response = request->beginResponse(200);
            response->addHeader("Location", "/update");
            response->addHeader("Set-Cookie", idStr);
            return request->send(response);
        }
        else
        {
            return request->send(401, "text/plain", "Wrong username or password");
        }
    });

    // ********************************************************
    // Site "/update"
    server->on("/update", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", "/login");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        AsyncWebServerResponse* response = request->beginResponse(200, "text/html", PRETTY_OTA_WEBSITE_DATA, sizeof(PRETTY_OTA_WEBSITE_DATA));
        response->addHeader("Content-Encoding", "gzip");
        request->send(response);
    });

    // ********************************************************
    // Site "/ota/start"
    server->on("/ota/start", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", "/login");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Get OTA update mode (filesystem / firmware)
        UPDATE_MODE updateMode = UPDATE_MODE::FIRMWARE;
        if (request->hasParam("mode"))
        {
            const String value = request->getParam("mode")->value();
            updateMode = (value == "fs" ? UPDATE_MODE::FILESYSTEM : UPDATE_MODE::FIRMWARE);
        }

        // Get reboot switch
        if (request->hasParam("reboot"))
        {
            const String value = request->getParam("reboot")->value();
            m_AutoRebootEnabled = (value == "true" ? true : false);
        }

        // Get MD5 hash from OTA update file
        if (request->hasParam("hash"))
        {
            const String md5Hash = request->getParam("hash")->value();
            if (!Update.setMD5(md5Hash.c_str()))
            {
                this->LOG_E("OTA: Not a valid MD5 hash for update file");
                return request->send(400, "text/plain", "Not a valid MD5 hash");
            }
        }
        else
        {
            this->LOG_E("OTA: No MD5 hash has been transmitted");
            return request->send(400, "text/plain", "No MD5 hash has been transmitted");
        }

        // Call OnStart callback
        if (m_OnStartUpdate)
            m_OnStartUpdate(updateMode);

        // Start update
        String errorMessage = "";
        if (!Update.begin(UPDATE_SIZE_UNKNOWN, (updateMode == UPDATE_MODE::FIRMWARE ? U_FLASH : U_SPIFFS)))
        {
            errorMessage = String(Update.errorString()) + "\n";

            this->LOG_E("OTA: Could not start update");
            this->LOG_E(errorMessage);
        }

        request->send((Update.hasError()) ? 400 : 200, "text/plain", (Update.hasError()) ? errorMessage.c_str() : "OK");
    });

    // ********************************************************
    // Site "/ota/upload"
    server->on("/ota/upload", HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", "/login");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Call OnEnd callback
        if (m_OnEndUpdate)
            m_OnEndUpdate(!Update.hasError());

        // Response
        String errorMessage = String(Update.errorString()) + "\n";

        AsyncWebServerResponse* response = request->beginResponse((Update.hasError()) ? 400 : 200, "text/plain", (Update.hasError()) ? errorMessage.c_str() : "OK");
        response->addHeader("Connection", "close");
        response->addHeader("Access-Control-Allow-Origin", "*");
        request->send(response);

        // Set reboot flag
        if (!Update.hasError() && m_AutoRebootEnabled)
        {
            m_RebootRequestTime = millis();
            m_RequestReboot = true;
        }
    },
    [&](AsyncWebServerRequest* request, String filename, uint64_t index, uint8_t* data, uint64_t size, bool isLastFrame)
    {
        /*if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", "/login");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }*/

        if (index == 0)
            m_WrittenBytes = 0;

        if (size != 0)
        {
            if (Update.write(data, size) != size)
                return request->send(400, "text/plain", "Failed to write chunked data to free space");

            m_WrittenBytes += size;

            // Call OnProgress callback
            if (m_OnProgressUpdate)
                m_OnProgressUpdate(m_WrittenBytes, request->contentLength());
        }

        // Is this the last frame of data?
        if (isLastFrame)
        {
            if (!Update.end(true))
            {
                // ToDo send error reply?
                this->LOG_E(Update.errorString());
            }
        }
    });

    // ********************************************************
    // Site "/ota/rollback": Firmware rollback
    server->on("/ota/rollback", HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", "/login");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Is a rollback possible?
        if(!Update.canRollBack())
        {
            this->LOG_E("No previous firmware for rollback has been found");

            return request->send(400, "text/plain", "No previous firmware for roll back has been found");
        }

        this->LOG_I("Rolling back to previous firmware...");

        // Do rollback
        if(!Update.rollBack())
        {
            this->LOG_E("Could not roll back to previous firmware");
            return request->send(400, "text/plain", "Could not roll back to previous firmware");
        }
        else
        {
            this->LOG_I("Rollback successful");

            request->send(200);

            // Request reboot
            m_RebootRequestTime = millis();
            m_RequestReboot = true;
        }
    });

    // ********************************************************
    // Site "/ota/queryInfo": Firmware rollback
    server->on("/ota/queryInfo", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", "/login");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        const esp_app_desc_t* const appDesc = esp_ota_get_app_description();

        JsonDocument jsonInfo;
        jsonInfo["rollbackPossible"] = Update.canRollBack();
        jsonInfo["firmwareVersion"] = appDesc->version;
        jsonInfo["sdkVersion"] = appDesc->idf_ver;
        jsonInfo["buildTime"] = appDesc->time;
        jsonInfo["buildDate"] = appDesc->date;
        jsonInfo["projectName"] = appDesc->project_name;
        jsonInfo["firmwareSHA256"] = SHA256ToString(appDesc->app_elf_sha256);

        // Send Json
        String jsonString = "";
        serializeJson(jsonInfo, jsonString);
        request->send(200, "application/json", jsonString);
    });

    // ********************************************************
    // Site "/ota/rebootCheck": For checking if server rebooted
    server->on("/ota/rebootCheck", HTTP_GET, [&](AsyncWebServerRequest* request)
    {
        request->send(200);
    });

    // ********************************************************
    // Site "/ota/doManualReboot": For requesting a reboot
    server->on("/ota/doManualReboot", HTTP_POST, [&](AsyncWebServerRequest* request)
    {
        if(m_AuthenticationEnabled && !IsAuthenticated(request))
        {
            AsyncWebServerResponse* response = request->beginResponse(302);
            response->addHeader("Location", "/login");
            response->addHeader("Cache-Control", "no-cache");

            return request->send(response);
        }

        // Request reboot
        m_RebootRequestTime = millis();
        m_RequestReboot = true;

        request->send(200);
    });

    // Enable ArduinoOTA support
    EnableArduinoOTA(password, passwordIsMD5Hash, OTAport);

    // Create background task with low priority for handling reboot request and ArduinoOTA
    const BaseType_t xReturn = xTaskCreate(BackgroundTask, "PrettyOTABackgroundTask",
        BACKGROUND_TASK_STACK_SIZE, this, BACKGROUND_TASK_PRIORITY, nullptr);

    if (xReturn != pdPASS)
    {
        this->LOG_E("PrettyOTA: Could not create background task for handling reboots");

        return false;
    }

    return true;
}

void PrettyOTA::EnableArduinoOTA(const char* const password, bool passwordIsMD5Hash, uint16_t OTAport)
{
    ArduinoOTA.setMdnsEnabled(false);
    ArduinoOTA.setRebootOnSuccess(true); // ToDo

    // Port
    ArduinoOTA.setPort(OTAport);

    // Password
    if (strcmp(password, "") != 0)
    {
        if (passwordIsMD5Hash)
            ArduinoOTA.setPasswordHash(password);
        else
            ArduinoOTA.setPassword(password);
    }

    // Configure ArduinoOTA
    ArduinoOTA.onStart([&]() {
        const UPDATE_MODE mode = (ArduinoOTA.getCommand() == U_FLASH) ? UPDATE_MODE::FIRMWARE : UPDATE_MODE::FILESYSTEM;
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

        if (m_SerialMonitorStream)
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

        // Check if 1 seconds have passed since reboot request
        if (me->m_RequestReboot && millis() - me->m_RebootRequestTime >= 2000)
        {
            me->LOG_I("Rebooting...");

            yield();
            delay(2000);

            me->m_RequestReboot = false;
            ESP.restart();
        }

        yield();
        delay(350);
    }
}

void PrettyOTA::UseDefaultCallbacks()
{
    if (!m_SerialMonitorStream)
    {
        // Use default Serial
        m_SerialMonitorStream = &Serial;
    }

    m_OnStartUpdate = OnOTAStart;
    m_OnProgressUpdate = OnOTAProgress;
    m_OnEndUpdate = OnOTAEnd;
}

const uint8_t PrettyOTA::PRETTY_OTA_WEBSITE_DATA[11823] = {
    31, 139, 8, 8, 111, 224, 213, 103, 0, 3, 80, 114, 101, 116, 116, 121, 79, 84, 65, 95, 109, 105, 110, 105, 102, 121, 46, 104, 116, 109, 108, 0, 237, 125, 237, 122, 219, 70, 150, 230, 255,
    185, 10, 132, 61, 113, 168, 49, 1, 163, 190, 240, 97, 137, 234, 73, 156, 244, 164, 119, 237, 238, 60, 237, 116, 118, 246, 201, 147, 201, 64, 36, 36, 113, 76, 17, 26, 18, 146, 227, 56,
    234, 251, 217, 219, 216, 43, 219, 247, 61, 5, 144, 0, 69, 82, 114, 58, 211, 211, 51, 189, 150, 73, 16, 133, 170, 58, 167, 206, 247, 169, 2, 10, 39, 31, 77, 171, 73, 253, 238, 186,
    12, 46, 235, 171, 249, 233, 223, 157, 240, 16, 204, 139, 197, 197, 120, 80, 46, 6, 167, 127, 23, 224, 223, 201, 101, 89, 76, 253, 79, 57, 189, 42, 235, 34, 152, 92, 22, 203, 85, 89,
    143, 7, 127, 252, 250, 55, 97, 54, 8, 158, 109, 87, 88, 20, 87, 229, 120, 112, 59, 43, 223, 94, 87, 203, 122, 16, 76, 170, 69, 93, 46, 208, 224, 237, 108, 90, 95, 142, 167, 229,
    237, 108, 82, 134, 114, 50, 10, 102, 139, 89, 61, 43, 230, 225, 106, 82, 204, 203, 177, 138, 226, 189, 29, 78, 203, 213, 100, 57, 187, 174, 103, 213, 162, 211, 231, 167, 193, 89, 89, 215,
    229, 50, 152, 87, 213, 155, 217, 226, 34, 248, 253, 215, 159, 6, 111, 203, 179, 224, 230, 122, 90, 160, 60, 234, 247, 87, 207, 234, 121, 121, 250, 213, 18, 109, 222, 161, 230, 201, 51, 95,
    176, 169, 48, 159, 45, 222, 4, 203, 114, 62, 30, 204, 38, 4, 68, 18, 225, 247, 85, 113, 81, 62, 91, 221, 94, 60, 253, 225, 106, 62, 8, 46, 151, 229, 57, 16, 42, 234, 226, 121,
    239, 202, 232, 99, 243, 2, 63, 3, 252, 92, 172, 198, 159, 92, 214, 245, 245, 243, 103, 207, 222, 190, 125, 27, 189, 53, 81, 181, 188, 120, 166, 227, 56, 102, 229, 79, 2, 79, 139, 79,
    156, 210, 159, 4, 151, 229, 236, 226, 178, 110, 78, 164, 237, 243, 91, 223, 122, 133, 230, 183, 229, 164, 46, 162, 89, 245, 108, 81, 44, 170, 79, 62, 54, 95, 0, 200, 117, 81, 95, 6,
    211, 241, 39, 175, 226, 32, 190, 68, 179, 91, 124, 190, 140, 191, 137, 127, 252, 36, 56, 159, 205, 231, 227, 79, 62, 214, 198, 58, 254, 125, 242, 108, 171, 133, 114, 46, 50, 46, 11, 178,
    60, 202, 156, 153, 155, 200, 164, 42, 140, 98, 173, 3, 19, 165, 177, 198, 207, 56, 195, 207, 44, 207, 89, 26, 40, 29, 101, 58, 193, 79, 171, 2, 27, 89, 99, 240, 83, 233, 64, 199,
    81, 150, 178, 20, 63, 77, 148, 39, 172, 145, 166, 129, 202, 34, 151, 177, 161, 205, 2, 5, 102, 74, 185, 73, 94, 232, 92, 71, 169, 78, 8, 212, 0, 16, 90, 235, 52, 9, 114, 23,
    89, 157, 6, 198, 38, 0, 19, 79, 208, 192, 41, 197, 118, 153, 67, 87, 168, 138, 94, 116, 18, 169, 204, 6, 218, 6, 86, 207, 1, 200, 1, 55, 21, 187, 137, 139, 92, 2, 216, 128,
    97, 77, 160, 163, 4, 117, 172, 141, 116, 232, 164, 78, 194, 1, 184, 121, 168, 34, 19, 179, 69, 172, 95, 24, 103, 34, 135, 22, 56, 228, 56, 26, 99, 208, 8, 77, 83, 29, 1, 154,
    1, 96, 157, 169, 73, 136, 17, 36, 24, 72, 18, 165, 185, 11, 77, 18, 37, 58, 15, 210, 72, 231, 161, 75, 34, 131, 129, 167, 145, 98, 199, 73, 148, 107, 142, 63, 206, 217, 34, 22,
    82, 200, 79, 23, 147, 66, 246, 165, 74, 29, 58, 204, 230, 66, 78, 142, 72, 71, 202, 166, 196, 49, 1, 196, 56, 85, 196, 61, 137, 129, 154, 75, 72, 182, 12, 176, 98, 227, 130, 28,
    248, 167, 192, 215, 144, 14, 202, 178, 208, 96, 0, 70, 153, 9, 249, 65, 100, 226, 196, 134, 145, 3, 229, 149, 137, 180, 194, 136, 65, 28, 246, 224, 12, 126, 103, 9, 8, 17, 165, 9,
    144, 137, 163, 56, 243, 200, 155, 80, 165, 24, 80, 42, 141, 13, 144, 87, 192, 155, 5, 82, 9, 136, 131, 52, 78, 135, 232, 47, 77, 77, 152, 69, 38, 73, 81, 20, 27, 29, 90, 16,
    208, 134, 36, 85, 30, 166, 145, 99, 77, 136, 139, 8, 5, 168, 64, 177, 97, 137, 8, 72, 156, 161, 118, 12, 170, 161, 84, 218, 9, 81, 80, 217, 70, 202, 121, 177, 65, 113, 150, 138,
    48, 233, 80, 235, 40, 87, 90, 196, 38, 4, 147, 173, 144, 211, 102, 33, 100, 195, 154, 92, 196, 134, 112, 116, 76, 233, 84, 192, 84, 69, 86, 68, 142, 189, 232, 216, 78, 124, 83, 32,
    107, 89, 131, 99, 129, 96, 131, 163, 144, 0, 212, 1, 117, 57, 96, 144, 91, 179, 129, 50, 16, 190, 40, 55, 20, 144, 20, 228, 114, 160, 187, 147, 223, 26, 42, 160, 115, 1, 146, 128,
    208, 46, 83, 34, 224, 24, 85, 78, 76, 33, 23, 89, 164, 18, 231, 245, 2, 8, 229, 46, 241, 140, 0, 195, 50, 235, 7, 64, 117, 48, 82, 238, 92, 0, 146, 166, 86, 154, 166, 19,
    205, 110, 50, 41, 182, 134, 216, 133, 28, 116, 144, 64, 210, 29, 165, 69, 65, 11, 80, 63, 1, 1, 201, 238, 28, 16, 18, 72, 41, 168, 128, 81, 0, 6, 206, 52, 232, 104, 49, 118,
    240, 7, 240, 192, 86, 22, 37, 224, 97, 154, 130, 27, 96, 31, 106, 131, 187, 185, 147, 106, 185, 202, 133, 141, 164, 59, 58, 52, 161, 6, 255, 83, 45, 180, 81, 33, 164, 47, 83, 114,
    162, 83, 53, 7, 231, 50, 81, 120, 149, 128, 140, 202, 144, 184, 42, 19, 230, 122, 29, 86, 161, 129, 168, 82, 160, 21, 184, 160, 45, 8, 75, 58, 97, 20, 168, 147, 138, 125, 200, 66,
    154, 17, 237, 89, 10, 234, 97, 148, 177, 2, 111, 82, 48, 148, 52, 128, 1, 0, 255, 19, 50, 218, 130, 158, 160, 83, 34, 18, 155, 145, 41, 73, 70, 129, 205, 84, 72, 165, 178, 148,
    69, 69, 225, 132, 2, 55, 242, 42, 34, 42, 210, 26, 52, 18, 42, 226, 26, 120, 9, 245, 226, 10, 22, 43, 229, 66, 77, 139, 69, 97, 207, 18, 17, 87, 225, 149, 206, 19, 17, 216,
    174, 89, 212, 147, 51, 83, 36, 173, 89, 164, 49, 198, 175, 190, 147, 240, 126, 166, 49, 253, 87, 213, 244, 102, 94, 194, 227, 44, 171, 213, 170, 90, 206, 46, 102, 139, 77, 85, 254, 131,
    155, 88, 213, 193, 106, 94, 150, 215, 227, 114, 124, 186, 40, 223, 6, 95, 45, 171, 171, 217, 170, 28, 214, 227, 83, 120, 202, 175, 103, 87, 101, 117, 83, 15, 235, 81, 121, 116, 116, 124,
    91, 44, 131, 213, 101, 245, 182, 41, 29, 93, 77, 221, 248, 252, 102, 49, 161, 95, 27, 30, 189, 111, 127, 6, 229, 176, 28, 213, 163, 197, 168, 26, 45, 71, 243, 163, 247, 108, 86, 140,
    102, 199, 240, 92, 55, 203, 69, 176, 26, 14, 139, 241, 106, 184, 146, 78, 71, 171, 97, 133, 58, 71, 163, 217, 120, 57, 42, 78, 78, 102, 63, 21, 167, 167, 167, 144, 245, 217, 209, 104,
    113, 116, 183, 238, 146, 40, 248, 14, 87, 163, 249, 168, 56, 122, 223, 116, 86, 14, 23, 79, 170, 159, 254, 180, 120, 178, 20, 136, 254, 226, 166, 217, 226, 64, 179, 229, 79, 213, 147, 63,
    237, 110, 86, 237, 111, 246, 47, 213, 191, 236, 110, 179, 220, 219, 166, 250, 151, 225, 226, 167, 63, 45, 143, 118, 54, 91, 145, 86, 158, 70, 139, 241, 48, 113, 206, 184, 39, 229, 209, 211,
    230, 87, 125, 212, 80, 109, 88, 158, 158, 170, 4, 229, 117, 115, 92, 200, 241, 228, 68, 37, 63, 249, 170, 139, 187, 6, 96, 135, 13, 32, 254, 28, 97, 202, 170, 46, 22, 147, 178, 58,
    15, 254, 56, 91, 212, 217, 167, 203, 101, 241, 238, 167, 159, 134, 243, 49, 249, 253, 117, 249, 67, 253, 197, 98, 82, 77, 203, 229, 240, 40, 42, 229, 215, 112, 176, 170, 151, 8, 72, 6,
    227, 49, 5, 9, 13, 231, 191, 158, 63, 255, 31, 175, 127, 255, 187, 200, 95, 152, 157, 191, 67, 223, 144, 136, 243, 106, 57, 108, 216, 59, 254, 246, 187, 209, 84, 186, 220, 64, 65, 165,
    209, 205, 56, 30, 125, 63, 158, 70, 103, 239, 234, 242, 101, 185, 184, 168, 47, 143, 111, 78, 190, 63, 190, 121, 250, 244, 104, 22, 93, 223, 172, 46, 135, 175, 165, 207, 232, 28, 146, 247,
    2, 1, 218, 11, 98, 48, 253, 246, 230, 187, 163, 118, 240, 221, 33, 129, 86, 45, 80, 80, 123, 60, 128, 193, 67, 184, 144, 164, 89, 94, 156, 77, 166, 229, 249, 96, 180, 28, 15, 6,
    163, 213, 56, 62, 94, 157, 212, 209, 220, 67, 92, 1, 218, 242, 233, 184, 138, 24, 1, 126, 90, 15, 135, 139, 113, 45, 191, 9, 12, 231, 171, 163, 35, 136, 157, 125, 162, 220, 209, 211,
    117, 37, 5, 162, 174, 81, 88, 222, 13, 247, 96, 65, 112, 21, 192, 85, 39, 70, 255, 195, 26, 98, 245, 116, 156, 29, 45, 158, 142, 119, 13, 174, 254, 182, 58, 61, 117, 223, 1, 98,
    245, 177, 209, 79, 180, 115, 107, 48, 139, 30, 24, 145, 163, 249, 183, 5, 107, 255, 52, 86, 58, 59, 57, 41, 208, 98, 52, 255, 86, 217, 167, 195, 226, 105, 98, 209, 71, 126, 114, 98,
    143, 190, 27, 23, 107, 102, 204, 198, 42, 53, 218, 101, 86, 229, 6, 44, 129, 29, 197, 185, 201, 210, 28, 188, 8, 215, 151, 44, 184, 210, 94, 201, 70, 19, 12, 96, 114, 50, 111, 177,
    159, 60, 29, 67, 186, 68, 42, 175, 198, 179, 209, 223, 143, 167, 163, 139, 241, 205, 232, 114, 252, 253, 241, 116, 188, 28, 246, 63, 213, 214, 103, 177, 245, 169, 251, 31, 96, 81, 15, 111,
    0, 189, 30, 126, 15, 177, 169, 135, 179, 17, 202, 70, 223, 99, 84, 147, 167, 241, 119, 163, 116, 20, 38, 89, 12, 103, 155, 155, 228, 72, 46, 241, 130, 250, 110, 164, 244, 40, 52, 136,
    141, 18, 235, 50, 92, 97, 51, 94, 209, 184, 146, 142, 146, 56, 65, 108, 149, 169, 252, 8, 61, 205, 228, 130, 249, 110, 164, 209, 68, 197, 22, 30, 200, 25, 19, 31, 29, 4, 109, 5,
    52, 220, 154, 85, 112, 34, 233, 6, 180, 19, 208, 138, 1, 112, 6, 95, 209, 1, 157, 8, 104, 184, 9, 16, 21, 97, 142, 85, 27, 224, 169, 7, 110, 93, 26, 187, 60, 51, 135, 65,
    103, 4, 173, 210, 20, 14, 203, 89, 213, 25, 117, 238, 71, 141, 184, 13, 44, 179, 86, 165, 27, 216, 42, 246, 192, 45, 92, 170, 217, 192, 85, 170, 25, 117, 158, 199, 22, 126, 48, 209,
    135, 65, 43, 45, 176, 49, 48, 68, 116, 73, 166, 59, 20, 55, 30, 184, 141, 49, 48, 120, 209, 14, 104, 219, 140, 219, 197, 32, 138, 214, 121, 220, 129, 239, 4, 62, 180, 50, 129, 85,
    50, 58, 39, 248, 133, 128, 95, 8, 248, 69, 31, 252, 119, 35, 135, 142, 18, 135, 144, 197, 169, 120, 3, 29, 164, 205, 201, 187, 36, 119, 112, 242, 70, 119, 160, 83, 20, 236, 40, 177,
    136, 254, 211, 84, 117, 198, 14, 138, 232, 24, 50, 146, 66, 74, 82, 19, 235, 195, 160, 157, 128, 78, 99, 100, 21, 89, 146, 171, 206, 192, 99, 194, 54, 25, 224, 198, 228, 220, 26, 176,
    19, 192, 97, 146, 196, 54, 205, 140, 113, 27, 200, 214, 67, 182, 136, 150, 76, 154, 217, 236, 48, 228, 156, 144, 29, 226, 126, 139, 65, 100, 29, 192, 182, 25, 52, 162, 41, 48, 131, 100,
    109, 97, 27, 15, 90, 101, 169, 73, 76, 158, 116, 4, 45, 19, 208, 10, 52, 114, 6, 12, 81, 15, 208, 219, 120, 130, 91, 192, 206, 16, 163, 119, 196, 92, 11, 112, 167, 192, 111, 12,
    97, 3, 58, 21, 208, 48, 20, 224, 102, 6, 73, 239, 240, 90, 251, 97, 171, 92, 131, 38, 8, 104, 44, 129, 87, 2, 188, 18, 224, 213, 54, 197, 45, 217, 147, 129, 226, 27, 184, 24,
    128, 82, 35, 196, 87, 90, 187, 20, 104, 153, 45, 86, 39, 144, 78, 147, 199, 200, 134, 40, 203, 107, 216, 36, 185, 65, 111, 206, 32, 112, 119, 201, 97, 200, 74, 32, 43, 214, 205, 161,
    47, 29, 57, 179, 2, 93, 33, 208, 204, 114, 176, 212, 244, 199, 157, 176, 145, 179, 121, 42, 18, 184, 134, 29, 123, 216, 8, 238, 64, 15, 228, 52, 241, 3, 208, 13, 193, 131, 222, 58,
    205, 85, 106, 55, 192, 99, 63, 116, 228, 180, 16, 27, 173, 117, 159, 223, 0, 142, 66, 167, 85, 158, 118, 172, 90, 34, 176, 211, 4, 113, 188, 202, 242, 195, 128, 115, 25, 54, 240, 51,
    137, 69, 6, 210, 145, 52, 237, 33, 91, 173, 50, 229, 50, 138, 114, 79, 202, 147, 17, 72, 133, 4, 195, 233, 142, 106, 107, 63, 234, 60, 135, 45, 205, 160, 173, 132, 189, 20, 216, 75,
    129, 189, 220, 182, 228, 164, 94, 158, 37, 38, 134, 164, 111, 96, 147, 174, 20, 88, 141, 196, 76, 89, 229, 182, 236, 138, 72, 39, 165, 217, 230, 113, 71, 195, 104, 86, 128, 48, 36, 196,
    80, 203, 14, 195, 230, 240, 32, 54, 176, 167, 22, 178, 150, 118, 116, 219, 8, 112, 232, 81, 110, 129, 25, 156, 198, 150, 65, 37, 244, 216, 41, 167, 187, 98, 238, 65, 235, 24, 40, 105,
    176, 48, 63, 12, 60, 19, 216, 80, 84, 120, 4, 227, 242, 14, 209, 157, 7, 14, 137, 81, 16, 3, 219, 247, 35, 132, 236, 18, 170, 62, 44, 79, 7, 184, 17, 232, 10, 146, 171, 156,
    74, 236, 3, 192, 173, 167, 186, 69, 198, 1, 6, 118, 228, 92, 84, 137, 35, 135, 31, 211, 10, 42, 158, 247, 61, 168, 27, 165, 192, 57, 75, 181, 235, 200, 90, 238, 71, 110, 64, 115,
    208, 145, 28, 159, 33, 114, 159, 141, 174, 208, 47, 126, 76, 71, 127, 79, 108, 86, 192, 230, 2, 141, 240, 227, 251, 209, 229, 81, 19, 135, 126, 219, 160, 245, 221, 254, 192, 201, 199, 136,
    109, 200, 116, 122, 10, 249, 247, 129, 212, 98, 19, 69, 61, 61, 90, 124, 91, 125, 135, 82, 54, 243, 87, 179, 237, 40, 203, 135, 83, 63, 141, 135, 136, 164, 158, 244, 226, 186, 234, 89,
    118, 132, 32, 153, 97, 86, 39, 194, 42, 198, 179, 232, 223, 170, 217, 98, 56, 24, 32, 243, 200, 254, 161, 104, 186, 67, 68, 123, 119, 55, 60, 58, 246, 105, 209, 101, 177, 186, 252, 13,
    194, 182, 223, 204, 230, 229, 184, 88, 189, 91, 76, 130, 173, 28, 137, 17, 255, 209, 248, 244, 253, 188, 172, 131, 138, 97, 224, 82, 226, 95, 54, 248, 67, 89, 32, 162, 62, 94, 70, 213,
    98, 94, 21, 211, 77, 154, 84, 30, 73, 245, 197, 118, 164, 92, 70, 117, 177, 188, 40, 235, 104, 89, 174, 110, 230, 136, 251, 129, 252, 24, 9, 214, 112, 1, 164, 70, 75, 20, 23, 211,
    79, 87, 82, 247, 179, 155, 243, 115, 68, 235, 229, 209, 221, 209, 177, 199, 107, 147, 132, 220, 44, 254, 40, 147, 135, 132, 115, 57, 155, 150, 95, 204, 203, 171, 114, 81, 15, 7, 55, 215,
    196, 227, 69, 53, 191, 185, 90, 12, 142, 70, 189, 107, 72, 244, 106, 4, 169, 171, 221, 87, 207, 170, 98, 185, 167, 225, 217, 77, 93, 87, 139, 245, 181, 226, 109, 49, 107, 210, 201, 161,
    166, 240, 49, 89, 92, 87, 190, 94, 86, 23, 24, 220, 26, 202, 49, 233, 80, 143, 167, 213, 228, 134, 21, 34, 12, 190, 169, 251, 217, 187, 223, 78, 135, 131, 170, 46, 94, 129, 139, 131,
    163, 232, 182, 152, 223, 148, 163, 197, 254, 170, 203, 242, 172, 170, 234, 23, 151, 229, 228, 205, 89, 245, 195, 111, 23, 215, 55, 53, 154, 77, 120, 94, 78, 143, 235, 229, 187, 247, 24, 226,
    87, 13, 252, 175, 57, 109, 58, 28, 188, 6, 189, 235, 118, 214, 21, 215, 38, 184, 212, 32, 85, 141, 253, 72, 186, 18, 0, 130, 130, 189, 190, 252, 188, 172, 39, 151, 195, 127, 125, 6,
    12, 159, 173, 216, 205, 175, 145, 105, 151, 227, 191, 127, 95, 223, 61, 97, 27, 252, 170, 238, 158, 120, 164, 240, 123, 113, 247, 175, 71, 199, 179, 243, 225, 71, 144, 134, 55, 71, 245, 229,
    178, 122, 27, 124, 177, 92, 66, 158, 61, 18, 130, 193, 181, 199, 32, 56, 47, 0, 108, 218, 32, 178, 18, 41, 249, 231, 87, 47, 191, 172, 235, 235, 63, 148, 255, 126, 83, 174, 234, 227,
    85, 228, 121, 25, 21, 211, 233, 23, 183, 160, 193, 203, 217, 170, 46, 23, 144, 136, 53, 137, 7, 163, 109, 121, 171, 199, 175, 138, 250, 50, 90, 86, 55, 139, 41, 100, 141, 237, 203, 233,
    51, 8, 29, 198, 48, 255, 7, 21, 199, 71, 199, 123, 169, 219, 246, 250, 89, 177, 4, 85, 87, 245, 187, 121, 25, 249, 57, 224, 250, 233, 224, 227, 193, 232, 193, 134, 223, 144, 127, 104,
    58, 91, 0, 203, 47, 191, 126, 245, 210, 55, 188, 27, 125, 4, 139, 178, 30, 78, 181, 104, 235, 247, 180, 5, 132, 43, 27, 253, 124, 81, 93, 129, 179, 197, 217, 252, 175, 121, 80, 119,
    24, 81, 181, 160, 186, 190, 131, 108, 212, 37, 172, 209, 226, 162, 53, 32, 157, 217, 18, 59, 30, 175, 68, 171, 223, 189, 102, 181, 39, 79, 134, 136, 165, 89, 198, 86, 55, 171, 95, 15,
    127, 6, 234, 3, 140, 249, 49, 184, 251, 150, 27, 204, 155, 118, 61, 221, 222, 86, 215, 7, 180, 123, 117, 51, 153, 116, 107, 67, 225, 94, 251, 162, 87, 248, 20, 23, 208, 56, 111, 153,
    130, 166, 248, 252, 102, 190, 238, 148, 95, 191, 169, 150, 175, 203, 229, 109, 185, 252, 131, 232, 205, 107, 116, 254, 7, 49, 133, 195, 163, 163, 231, 246, 191, 50, 105, 74, 234, 122, 151, 48,
    162, 252, 141, 25, 250, 163, 8, 255, 90, 237, 215, 151, 225, 64, 86, 144, 19, 138, 200, 234, 26, 254, 168, 228, 68, 13, 40, 241, 55, 52, 246, 129, 151, 135, 192, 59, 238, 114, 26, 120,
    246, 7, 156, 162, 10, 6, 79, 91, 113, 160, 215, 22, 107, 233, 39, 180, 32, 71, 87, 159, 23, 117, 113, 60, 143, 138, 235, 235, 18, 150, 97, 112, 142, 254, 7, 163, 114, 84, 70, 92,
    142, 163, 201, 169, 112, 97, 56, 248, 234, 247, 175, 191, 30, 140, 6, 98, 199, 189, 17, 34, 18, 209, 138, 141, 230, 130, 206, 150, 207, 240, 8, 211, 105, 12, 158, 54, 157, 221, 77, 10,
    58, 131, 98, 203, 221, 254, 5, 201, 84, 68, 87, 94, 195, 16, 188, 108, 102, 48, 23, 116, 90, 226, 9, 105, 68, 155, 73, 68, 162, 248, 226, 102, 85, 87, 87, 159, 206, 203, 37, 52,
    107, 212, 154, 214, 83, 117, 244, 235, 33, 81, 234, 94, 30, 252, 126, 49, 127, 23, 20, 193, 10, 35, 158, 151, 65, 116, 54, 91, 112, 50, 186, 12, 38, 197, 34, 56, 43, 3, 79, 51,
    48, 166, 128, 207, 92, 76, 202, 8, 200, 193, 164, 63, 31, 160, 226, 224, 163, 113, 249, 109, 252, 157, 16, 41, 90, 93, 207, 103, 232, 14, 215, 163, 235, 234, 122, 184, 23, 212, 26, 194,
    106, 27, 68, 219, 245, 109, 53, 155, 118, 163, 28, 128, 56, 186, 219, 31, 23, 84, 243, 249, 89, 49, 121, 243, 153, 196, 41, 128, 126, 223, 101, 78, 230, 179, 201, 155, 193, 104, 203, 60,
    55, 209, 83, 159, 86, 127, 233, 120, 170, 9, 144, 118, 132, 0, 245, 99, 61, 76, 189, 195, 195, 212, 107, 51, 250, 161, 6, 252, 15, 13, 57, 63, 220, 132, 127, 20, 183, 70, 124, 15,
    244, 131, 10, 176, 134, 187, 79, 5, 234, 123, 86, 242, 23, 236, 252, 1, 51, 84, 119, 204, 208, 168, 222, 97, 89, 90, 33, 68, 207, 181, 183, 45, 8, 220, 247, 27, 99, 31, 54, 254,
    215, 148, 216, 251, 86, 174, 15, 165, 43, 98, 175, 191, 249, 167, 61, 82, 38, 4, 224, 242, 195, 225, 16, 227, 63, 90, 61, 30, 41, 215, 207, 135, 251, 199, 248, 146, 182, 171, 105, 53,
    56, 192, 243, 94, 35, 95, 189, 33, 71, 223, 31, 191, 134, 244, 208, 251, 120, 25, 193, 65, 198, 219, 72, 110, 20, 28, 16, 212, 231, 29, 73, 221, 143, 199, 69, 245, 89, 215, 90, 78,
    103, 43, 6, 219, 211, 241, 71, 234, 113, 109, 116, 191, 209, 62, 141, 152, 86, 175, 138, 197, 77, 49, 95, 19, 230, 241, 122, 177, 157, 227, 237, 85, 143, 94, 2, 84, 77, 138, 249, 235,
    186, 90, 130, 160, 128, 84, 255, 182, 46, 175, 218, 14, 191, 159, 52, 61, 30, 136, 143, 14, 166, 151, 204, 194, 41, 137, 211, 101, 117, 253, 41, 196, 105, 127, 150, 202, 26, 63, 86, 11,
    240, 244, 120, 237, 167, 89, 246, 229, 236, 226, 114, 206, 219, 104, 136, 107, 219, 77, 52, 153, 23, 171, 21, 135, 197, 49, 110, 26, 135, 151, 109, 237, 65, 103, 21, 145, 87, 255, 184, 184,
    124, 160, 163, 101, 121, 85, 221, 150, 143, 233, 235, 203, 98, 49, 157, 203, 28, 195, 251, 50, 186, 94, 150, 36, 241, 231, 229, 121, 33, 225, 248, 113, 47, 184, 136, 120, 47, 209, 215, 203,
    98, 177, 58, 47, 151, 145, 56, 239, 94, 103, 197, 197, 239, 33, 148, 7, 59, 236, 172, 134, 118, 244, 157, 99, 216, 67, 202, 242, 104, 199, 168, 160, 134, 211, 114, 209, 29, 73, 87, 49,
    31, 219, 155, 16, 251, 126, 87, 247, 98, 193, 3, 253, 173, 131, 63, 169, 217, 211, 224, 178, 215, 227, 150, 229, 59, 212, 229, 170, 87, 245, 64, 159, 29, 215, 118, 168, 191, 114, 93, 237,
    161, 190, 26, 47, 248, 96, 103, 190, 222, 222, 222, 182, 226, 189, 114, 84, 211, 64, 236, 239, 115, 1, 23, 112, 62, 67, 112, 141, 214, 91, 163, 166, 143, 31, 163, 131, 95, 63, 170, 177,
    79, 106, 182, 24, 188, 85, 161, 97, 196, 224, 232, 249, 207, 234, 178, 149, 192, 125, 189, 238, 183, 44, 15, 34, 74, 186, 161, 131, 201, 188, 44, 150, 237, 205, 24, 157, 91, 48, 188, 135,
    108, 78, 198, 157, 27, 54, 58, 126, 238, 207, 26, 146, 135, 127, 55, 74, 75, 179, 165, 88, 189, 72, 227, 253, 126, 4, 127, 9, 240, 155, 249, 205, 18, 99, 252, 102, 86, 190, 5, 200,
    183, 179, 197, 180, 122, 27, 209, 184, 243, 26, 218, 48, 190, 129, 53, 217, 154, 19, 133, 143, 92, 190, 251, 237, 226, 188, 26, 250, 89, 163, 114, 87, 200, 80, 238, 10, 25, 58, 68, 156,
    157, 15, 17, 47, 148, 157, 120, 65, 202, 36, 98, 40, 219, 8, 176, 153, 148, 146, 27, 37, 174, 121, 167, 233, 176, 190, 156, 109, 101, 240, 251, 103, 164, 206, 103, 203, 171, 183, 197, 178,
    252, 30, 230, 114, 5, 168, 223, 215, 168, 223, 147, 249, 58, 106, 235, 124, 227, 171, 28, 136, 40, 166, 111, 14, 245, 131, 203, 15, 118, 113, 118, 51, 155, 79, 191, 175, 193, 199, 93, 61,
    200, 85, 228, 217, 208, 195, 168, 141, 112, 191, 170, 86, 171, 25, 124, 255, 129, 9, 154, 123, 25, 217, 163, 98, 140, 182, 85, 139, 136, 76, 110, 140, 7, 147, 106, 94, 45, 159, 255, 42,
    142, 207, 207, 227, 248, 248, 144, 3, 223, 106, 191, 25, 200, 224, 127, 151, 84, 251, 159, 133, 112, 252, 115, 17, 62, 63, 119, 248, 251, 153, 8, 255, 174, 130, 66, 148, 243, 85, 25, 216,
    174, 240, 253, 154, 139, 22, 213, 156, 179, 160, 23, 195, 193, 90, 230, 159, 223, 11, 10, 57, 115, 209, 147, 200, 231, 143, 109, 217, 207, 123, 214, 82, 127, 119, 55, 42, 155, 32, 239, 159,
    190, 88, 199, 120, 235, 126, 6, 35, 4, 201, 163, 178, 141, 240, 182, 148, 115, 71, 120, 189, 86, 83, 37, 62, 66, 22, 126, 186, 121, 133, 145, 137, 221, 242, 68, 197, 199, 71, 239, 187,
    23, 148, 227, 5, 206, 246, 111, 86, 88, 182, 212, 124, 209, 172, 199, 0, 151, 174, 118, 3, 86, 76, 96, 241, 221, 136, 53, 196, 159, 245, 174, 63, 125, 42, 87, 182, 7, 217, 9, 12,
    97, 164, 23, 237, 24, 101, 74, 72, 26, 181, 247, 100, 213, 143, 24, 119, 39, 173, 40, 197, 55, 62, 176, 62, 114, 120, 209, 131, 235, 13, 245, 147, 39, 31, 61, 34, 168, 120, 48, 237,
    248, 244, 166, 174, 218, 156, 99, 182, 10, 90, 13, 136, 130, 175, 96, 245, 33, 136, 205, 165, 43, 9, 234, 231, 239, 2, 212, 190, 65, 113, 125, 89, 6, 228, 65, 107, 180, 162, 193, 129,
    116, 176, 159, 42, 53, 139, 117, 251, 103, 118, 246, 102, 42, 7, 148, 114, 127, 166, 18, 31, 123, 137, 217, 155, 242, 13, 15, 216, 237, 95, 56, 105, 26, 45, 14, 152, 207, 199, 114, 204,
    95, 226, 2, 22, 168, 191, 152, 173, 46, 203, 233, 8, 17, 157, 232, 51, 56, 184, 188, 89, 44, 120, 87, 218, 227, 25, 114, 200, 68, 62, 22, 169, 23, 213, 205, 124, 26, 44, 36, 113,
    133, 205, 89, 148, 147, 58, 10, 26, 76, 39, 114, 237, 178, 184, 45, 155, 108, 54, 168, 150, 247, 4, 40, 152, 86, 229, 74, 58, 56, 43, 165, 234, 164, 90, 162, 171, 122, 254, 238, 67,
    70, 114, 183, 206, 140, 238, 39, 143, 76, 87, 16, 120, 44, 97, 154, 251, 137, 139, 44, 85, 29, 108, 88, 93, 15, 70, 157, 212, 233, 225, 6, 160, 207, 162, 246, 160, 58, 57, 224, 99,
    218, 181, 24, 126, 96, 51, 40, 235, 109, 233, 219, 117, 114, 197, 199, 143, 236, 3, 26, 237, 72, 194, 15, 196, 61, 77, 46, 41, 17, 32, 218, 201, 60, 64, 19, 221, 117, 82, 205, 113,
    231, 119, 123, 121, 29, 15, 142, 215, 191, 54, 45, 101, 225, 125, 200, 5, 250, 123, 185, 254, 108, 17, 116, 39, 5, 126, 250, 233, 145, 83, 4, 116, 101, 63, 207, 32, 143, 7, 245, 242,
    166, 28, 140, 199, 61, 72, 23, 251, 32, 29, 141, 58, 97, 235, 221, 241, 230, 6, 239, 103, 254, 14, 239, 238, 45, 223, 140, 45, 250, 247, 117, 203, 3, 81, 239, 207, 171, 69, 29, 158,
    23, 87, 179, 249, 187, 231, 193, 10, 9, 122, 8, 11, 48, 59, 63, 190, 59, 171, 166, 239, 130, 247, 140, 47, 46, 100, 237, 52, 244, 113, 73, 240, 43, 149, 243, 239, 184, 61, 45, 19,
    254, 29, 223, 69, 231, 192, 13, 150, 227, 253, 117, 181, 154, 145, 159, 207, 161, 146, 63, 192, 201, 204, 203, 243, 250, 121, 16, 31, 159, 85, 48, 100, 87, 252, 37, 11, 78, 207, 3, 46,
    28, 29, 251, 103, 131, 158, 7, 58, 187, 254, 225, 120, 62, 227, 124, 67, 83, 98, 80, 176, 3, 188, 81, 252, 91, 131, 207, 114, 254, 29, 51, 4, 10, 11, 136, 29, 192, 78, 68, 101,
    142, 101, 100, 171, 217, 143, 37, 32, 177, 175, 187, 232, 170, 152, 45, 62, 159, 221, 6, 239, 97, 73, 175, 231, 5, 6, 124, 62, 47, 127, 56, 190, 42, 150, 23, 179, 69, 88, 87, 215,
    0, 138, 164, 162, 45, 104, 17, 182, 44, 99, 205, 112, 58, 163, 37, 145, 177, 77, 196, 106, 28, 11, 200, 112, 6, 246, 172, 214, 128, 239, 162, 75, 185, 177, 227, 15, 213, 91, 16, 176,
    90, 226, 231, 186, 47, 117, 253, 67, 128, 56, 106, 54, 109, 9, 167, 38, 45, 56, 79, 39, 229, 174, 215, 24, 45, 61, 33, 164, 232, 206, 175, 92, 47, 63, 171, 126, 64, 102, 49, 121,
    19, 188, 151, 39, 202, 64, 184, 72, 187, 53, 21, 93, 140, 170, 13, 121, 109, 188, 233, 169, 5, 239, 58, 189, 203, 120, 109, 42, 125, 67, 154, 186, 140, 67, 150, 132, 116, 233, 182, 60,
    174, 174, 139, 201, 172, 126, 71, 166, 53, 232, 197, 82, 127, 5, 59, 42, 8, 119, 91, 21, 103, 24, 217, 77, 93, 238, 224, 218, 229, 106, 62, 84, 169, 25, 5, 73, 252, 241, 40, 208,
    250, 227, 163, 181, 16, 228, 232, 112, 141, 62, 126, 215, 50, 75, 84, 45, 129, 237, 234, 13, 114, 184, 120, 90, 94, 140, 130, 80, 59, 28, 17, 184, 17, 105, 101, 41, 43, 247, 240, 17,
    114, 253, 44, 132, 172, 249, 96, 132, 246, 224, 19, 230, 27, 124, 112, 237, 103, 97, 99, 220, 6, 27, 29, 119, 176, 145, 147, 101, 197, 196, 18, 156, 35, 2, 247, 144, 11, 117, 75, 175,
    88, 240, 19, 214, 134, 42, 120, 95, 44, 102, 87, 69, 163, 150, 203, 234, 202, 51, 207, 174, 130, 217, 130, 190, 31, 88, 249, 154, 250, 126, 77, 79, 214, 110, 213, 117, 141, 112, 90, 138,
    26, 169, 85, 211, 220, 60, 2, 208, 189, 214, 186, 109, 109, 127, 22, 112, 131, 230, 255, 248, 166, 124, 119, 190, 44, 174, 224, 249, 55, 64, 223, 199, 31, 7, 239, 127, 12, 97, 233, 203,
    31, 72, 188, 174, 52, 11, 221, 230, 66, 200, 144, 100, 13, 194, 132, 140, 211, 189, 38, 170, 211, 68, 117, 155, 176, 129, 8, 158, 237, 213, 207, 183, 235, 80, 46, 238, 146, 94, 157, 108,
    187, 14, 237, 222, 93, 214, 171, 147, 30, 0, 171, 52, 235, 211, 116, 118, 26, 184, 237, 90, 134, 216, 117, 134, 123, 119, 143, 66, 141, 178, 60, 142, 68, 127, 19, 20, 106, 12, 108, 19,
    107, 110, 124, 196, 108, 33, 110, 233, 12, 62, 249, 205, 218, 72, 152, 142, 90, 202, 201, 53, 226, 27, 68, 203, 208, 203, 104, 219, 198, 18, 159, 198, 13, 44, 139, 233, 236, 102, 69, 59,
    253, 113, 199, 12, 192, 141, 105, 119, 22, 231, 103, 199, 97, 248, 253, 21, 125, 203, 98, 54, 9, 47, 88, 153, 129, 234, 175, 98, 252, 3, 169, 97, 26, 248, 243, 104, 20, 16, 161, 98,
    217, 175, 17, 224, 239, 168, 125, 110, 24, 6, 255, 135, 227, 240, 109, 121, 246, 102, 86, 135, 87, 197, 234, 205, 243, 224, 182, 88, 14, 217, 253, 209, 241, 246, 121, 183, 30, 44, 210, 149,
    152, 44, 144, 105, 85, 221, 44, 39, 101, 88, 221, 212, 199, 247, 46, 221, 156, 129, 158, 147, 250, 184, 163, 175, 115, 3, 59, 176, 214, 211, 6, 199, 158, 106, 162, 198, 251, 186, 122, 223,
    177, 89, 222, 152, 13, 21, 243, 184, 35, 242, 160, 187, 254, 24, 188, 239, 121, 170, 29, 238, 76, 187, 46, 19, 27, 73, 104, 204, 109, 83, 28, 196, 240, 143, 171, 128, 41, 40, 100, 97,
    20, 52, 108, 237, 23, 7, 200, 72, 171, 183, 112, 239, 136, 155, 74, 177, 133, 237, 234, 71, 240, 190, 225, 184, 177, 93, 75, 172, 228, 204, 51, 213, 59, 245, 105, 193, 252, 169, 245, 234,
    198, 108, 115, 92, 28, 85, 39, 36, 225, 243, 197, 142, 129, 69, 47, 230, 81, 192, 138, 133, 59, 194, 153, 238, 216, 154, 190, 197, 123, 4, 58, 141, 175, 154, 145, 144, 85, 147, 155, 229,
    138, 62, 229, 186, 154, 53, 209, 72, 59, 150, 231, 151, 204, 9, 214, 33, 73, 63, 128, 59, 203, 58, 53, 55, 107, 62, 247, 106, 155, 248, 204, 22, 73, 167, 46, 167, 135, 90, 78, 53,
    92, 234, 95, 252, 124, 118, 21, 188, 111, 155, 167, 37, 255, 80, 195, 199, 79, 95, 74, 160, 180, 29, 144, 109, 199, 90, 203, 234, 237, 241, 191, 221, 172, 234, 217, 249, 187, 176, 17, 240,
    53, 89, 118, 5, 96, 221, 200, 79, 111, 135, 149, 138, 102, 76, 232, 219, 145, 195, 155, 235, 235, 114, 57, 1, 9, 143, 111, 16, 254, 34, 4, 158, 3, 246, 115, 100, 145, 139, 178, 167,
    202, 74, 70, 215, 197, 189, 59, 252, 166, 78, 114, 95, 80, 25, 101, 181, 36, 56, 139, 249, 183, 238, 102, 75, 194, 186, 50, 213, 11, 20, 247, 136, 84, 207, 208, 252, 135, 169, 131, 71,
    245, 133, 167, 253, 67, 236, 106, 66, 227, 30, 213, 227, 40, 233, 19, 178, 99, 36, 239, 7, 190, 45, 217, 178, 77, 52, 107, 98, 215, 161, 125, 131, 201, 23, 139, 122, 249, 238, 103, 73,
    207, 10, 228, 128, 77, 47, 235, 183, 101, 185, 47, 138, 239, 129, 146, 59, 57, 55, 114, 220, 50, 209, 75, 202, 166, 188, 201, 134, 250, 182, 221, 242, 175, 227, 33, 90, 39, 181, 131, 215,
    38, 227, 223, 54, 167, 147, 190, 237, 240, 241, 102, 151, 188, 18, 25, 242, 78, 182, 98, 201, 167, 56, 27, 201, 109, 176, 219, 163, 247, 113, 156, 156, 157, 35, 209, 139, 118, 164, 164, 29,
    154, 250, 158, 162, 186, 186, 184, 152, 151, 175, 223, 206, 234, 201, 229, 54, 197, 119, 145, 111, 159, 190, 238, 72, 50, 90, 14, 119, 3, 111, 173, 246, 100, 127, 185, 85, 238, 30, 125, 68,
    240, 183, 13, 223, 70, 250, 195, 233, 205, 178, 113, 82, 113, 164, 220, 106, 107, 56, 207, 159, 23, 231, 146, 185, 174, 113, 29, 12, 142, 119, 196, 237, 45, 110, 201, 70, 42, 147, 117, 224,
    191, 39, 91, 109, 229, 225, 190, 251, 223, 131, 30, 130, 97, 134, 194, 171, 203, 98, 90, 189, 149, 4, 132, 241, 3, 13, 8, 56, 150, 241, 207, 234, 181, 224, 184, 109, 35, 177, 155, 155,
    207, 155, 233, 133, 224, 105, 176, 123, 224, 29, 75, 184, 14, 147, 254, 25, 25, 201, 245, 15, 71, 135, 200, 184, 127, 188, 31, 132, 198, 206, 89, 134, 70, 58, 15, 50, 209, 175, 45, 180,
    193, 194, 129, 164, 94, 124, 239, 135, 36, 240, 190, 103, 89, 250, 222, 97, 224, 119, 88, 42, 111, 156, 166, 101, 93, 204, 230, 190, 197, 182, 190, 110, 89, 142, 110, 135, 123, 251, 107, 38,
    153, 125, 72, 250, 249, 47, 218, 121, 99, 141, 194, 126, 26, 221, 157, 17, 253, 95, 93, 224, 135, 200, 171, 118, 32, 123, 176, 190, 4, 244, 81, 119, 122, 123, 187, 122, 207, 126, 198, 165,
    210, 234, 124, 51, 225, 100, 33, 98, 103, 247, 212, 189, 141, 204, 123, 25, 179, 213, 91, 150, 211, 116, 204, 174, 222, 104, 143, 158, 186, 243, 114, 178, 173, 166, 52, 72, 187, 228, 163, 171,
    160, 177, 40, 33, 73, 32, 193, 57, 254, 229, 186, 231, 120, 225, 75, 3, 238, 158, 225, 189, 107, 95, 46, 221, 61, 66, 172, 109, 245, 125, 141, 104, 112, 220, 34, 220, 105, 192, 13, 121,
    214, 49, 196, 122, 194, 162, 129, 190, 214, 108, 226, 192, 105, 241, 229, 85, 49, 63, 110, 166, 142, 84, 100, 118, 131, 151, 46, 119, 27, 133, 208, 209, 40, 108, 181, 66, 38, 0, 67, 222,
    107, 34, 32, 134, 113, 148, 187, 123, 181, 219, 117, 140, 214, 35, 245, 28, 160, 152, 184, 120, 167, 233, 247, 174, 177, 61, 205, 11, 254, 245, 120, 33, 174, 170, 145, 135, 80, 238, 30, 90,
    173, 253, 87, 127, 137, 246, 151, 147, 55, 29, 247, 228, 45, 221, 146, 55, 247, 33, 242, 150, 253, 114, 242, 166, 183, 228, 173, 27, 81, 117, 34, 196, 109, 186, 60, 70, 252, 182, 40, 217,
    8, 224, 14, 127, 217, 206, 67, 234, 3, 50, 233, 238, 203, 164, 222, 135, 213, 175, 0, 232, 123, 159, 49, 6, 59, 146, 200, 80, 101, 237, 156, 215, 86, 243, 7, 197, 115, 171, 254, 95,
    129, 128, 246, 188, 142, 183, 209, 86, 230, 74, 162, 238, 173, 191, 127, 157, 98, 252, 11, 154, 205, 109, 49, 22, 179, 121, 95, 134, 59, 36, 121, 148, 4, 119, 73, 248, 176, 252, 210, 103,
    172, 165, 83, 217, 109, 128, 15, 75, 87, 183, 246, 127, 142, 108, 117, 48, 216, 33, 89, 169, 204, 152, 69, 157, 39, 124, 152, 244, 20, 72, 48, 150, 247, 231, 193, 246, 230, 88, 23, 69,
    27, 11, 236, 142, 169, 218, 238, 187, 188, 241, 217, 145, 211, 247, 34, 100, 9, 72, 214, 25, 83, 111, 234, 165, 179, 196, 161, 211, 184, 135, 121, 120, 235, 179, 180, 141, 32, 5, 207, 253,
    78, 116, 156, 111, 217, 216, 154, 93, 192, 182, 166, 227, 18, 3, 101, 217, 5, 179, 15, 81, 210, 194, 95, 42, 38, 107, 71, 229, 195, 130, 173, 91, 223, 130, 247, 183, 179, 213, 236, 108,
    54, 23, 177, 247, 55, 159, 30, 111, 175, 181, 73, 239, 93, 106, 153, 251, 203, 106, 157, 164, 58, 219, 158, 134, 156, 76, 140, 181, 110, 215, 244, 83, 59, 154, 115, 249, 119, 47, 27, 149,
    243, 183, 13, 8, 153, 57, 66, 155, 237, 201, 228, 173, 169, 8, 237, 214, 19, 87, 156, 138, 216, 12, 47, 232, 148, 251, 90, 219, 28, 75, 119, 81, 40, 226, 141, 128, 125, 50, 201, 239,
    121, 217, 55, 23, 187, 239, 192, 220, 22, 75, 53, 49, 154, 174, 200, 83, 122, 59, 33, 238, 206, 28, 119, 215, 93, 55, 203, 172, 39, 207, 54, 155, 75, 158, 112, 49, 181, 179, 26, 59,
    157, 221, 6, 114, 31, 227, 120, 208, 172, 73, 14, 250, 107, 179, 39, 31, 133, 97, 240, 178, 186, 168, 130, 48, 220, 186, 178, 217, 127, 113, 176, 127, 255, 197, 65, 208, 220, 215, 55, 30,
    192, 100, 13, 154, 221, 24, 7, 50, 197, 52, 104, 247, 99, 28, 36, 57, 207, 184, 145, 229, 103, 213, 15, 227, 1, 167, 144, 117, 170, 114, 216, 230, 196, 196, 91, 24, 9, 236, 102, 147,
    197, 193, 171, 4, 61, 5, 105, 106, 10, 149, 219, 128, 31, 180, 141, 67, 148, 25, 29, 79, 18, 29, 184, 52, 72, 98, 126, 167, 206, 201, 65, 230, 167, 211, 56, 193, 119, 102, 98, 92,
    44, 28, 225, 228, 50, 109, 173, 2, 116, 18, 59, 51, 9, 149, 113, 129, 108, 169, 134, 42, 105, 200, 109, 18, 113, 200, 99, 244, 31, 102, 49, 183, 124, 51, 56, 234, 32, 203, 146, 219,
    212, 196, 115, 109, 2, 235, 122, 56, 16, 129, 192, 198, 19, 151, 134, 137, 9, 248, 77, 248, 97, 26, 231, 223, 104, 180, 184, 116, 177, 153, 164, 177, 33, 26, 220, 40, 46, 3, 92, 195,
    253, 229, 226, 34, 7, 46, 185, 199, 39, 14, 21, 183, 95, 75, 13, 49, 74, 109, 136, 255, 202, 154, 48, 85, 97, 174, 227, 48, 117, 115, 244, 23, 135, 38, 180, 220, 183, 241, 42, 213,
    150, 179, 243, 147, 16, 227, 82, 73, 232, 84, 96, 0, 150, 152, 207, 67, 110, 235, 104, 57, 58, 48, 102, 98, 144, 126, 88, 180, 195, 25, 202, 83, 13, 205, 209, 10, 152, 3, 79, 101,
    130, 92, 167, 65, 102, 179, 32, 71, 55, 86, 115, 196, 74, 101, 33, 55, 9, 76, 12, 247, 190, 9, 117, 108, 139, 4, 21, 248, 33, 209, 66, 11, 106, 88, 149, 79, 112, 37, 116, 121,
    168, 85, 152, 217, 80, 59, 224, 153, 207, 129, 93, 226, 210, 75, 109, 64, 158, 44, 3, 98, 252, 18, 2, 105, 118, 23, 79, 148, 78, 67, 155, 19, 133, 80, 27, 150, 134, 70, 197, 4,
    135, 14, 128, 36, 190, 117, 134, 67, 198, 49, 152, 208, 220, 134, 198, 234, 73, 204, 109, 115, 208, 181, 201, 227, 48, 225, 118, 123, 54, 228, 46, 131, 177, 80, 41, 97, 43, 124, 226, 43,
    101, 113, 221, 16, 47, 208, 37, 4, 186, 134, 87, 3, 167, 133, 32, 198, 144, 4, 42, 117, 147, 16, 132, 49, 96, 119, 130, 131, 65, 25, 55, 32, 116, 168, 72, 130, 218, 148, 91, 120,
    66, 102, 72, 22, 28, 41, 112, 36, 137, 38, 118, 42, 177, 220, 7, 195, 147, 196, 168, 128, 31, 79, 18, 3, 120, 46, 33, 219, 136, 15, 55, 11, 228, 39, 39, 195, 110, 33, 17, 110,
    174, 45, 16, 158, 152, 216, 1, 170, 65, 21, 180, 228, 1, 12, 103, 247, 78, 135, 36, 79, 166, 49, 80, 72, 64, 102, 190, 84, 206, 164, 49, 201, 105, 18, 59, 33, 207, 21, 241, 48,
    121, 66, 98, 91, 144, 6, 77, 12, 219, 227, 160, 192, 3, 208, 241, 42, 52, 28, 69, 42, 120, 88, 142, 7, 180, 134, 72, 83, 90, 140, 13, 32, 145, 58, 137, 33, 150, 25, 120, 137,
    17, 115, 99, 69, 75, 217, 81, 49, 68, 13, 136, 203, 86, 129, 220, 40, 210, 133, 220, 163, 211, 36, 16, 232, 34, 75, 85, 192, 143, 12, 19, 4, 6, 151, 52, 232, 9, 9, 209, 95,
    66, 80, 44, 57, 170, 92, 192, 110, 40, 142, 160, 172, 50, 148, 9, 104, 92, 152, 130, 198, 169, 114, 208, 174, 52, 145, 125, 168, 66, 165, 93, 118, 5, 164, 161, 122, 6, 146, 107, 41,
    33, 64, 159, 170, 233, 180, 9, 115, 163, 169, 24, 108, 143, 35, 134, 68, 153, 197, 41, 187, 53, 148, 79, 84, 7, 79, 52, 63, 218, 65, 222, 85, 224, 80, 148, 130, 106, 1, 137, 45,
    223, 9, 117, 30, 112, 117, 0, 232, 9, 59, 140, 195, 60, 81, 5, 119, 240, 228, 71, 20, 63, 161, 217, 200, 28, 144, 55, 2, 37, 99, 29, 57, 104, 105, 46, 194, 143, 107, 90, 115,
    164, 150, 74, 121, 149, 56, 17, 172, 66, 115, 115, 86, 124, 188, 198, 234, 132, 20, 196, 88, 64, 39, 136, 37, 109, 12, 116, 143, 244, 72, 243, 185, 37, 122, 177, 231, 19, 60, 32, 170,
    145, 50, 46, 78, 113, 68, 77, 11, 89, 0, 46, 214, 81, 53, 73, 67, 43, 216, 80, 91, 109, 158, 22, 24, 179, 38, 163, 248, 45, 88, 115, 131, 74, 144, 113, 66, 187, 128, 147, 12,
    181, 50, 88, 34, 42, 22, 183, 69, 117, 25, 180, 131, 208, 185, 255, 104, 194, 43, 49, 183, 1, 226, 174, 178, 220, 58, 76, 6, 163, 51, 128, 128, 44, 42, 94, 203, 228, 138, 3, 22,
    80, 64, 131, 138, 25, 25, 207, 145, 0, 67, 3, 129, 201, 40, 169, 32, 107, 102, 216, 130, 102, 33, 11, 83, 163, 41, 182, 52, 72, 236, 86, 236, 111, 200, 125, 81, 169, 32, 148, 31,
    240, 32, 75, 174, 64, 94, 170, 79, 66, 3, 5, 233, 131, 17, 75, 114, 7, 220, 180, 28, 83, 69, 70, 128, 133, 32, 95, 14, 48, 46, 200, 47, 241, 13, 11, 23, 210, 250, 101, 48,
    18, 48, 45, 14, 72, 167, 25, 71, 3, 204, 147, 60, 30, 248, 237, 38, 7, 191, 210, 147, 51, 91, 88, 127, 26, 46, 111, 120, 251, 50, 67, 207, 106, 58, 29, 60, 59, 228, 63, 52,
    165, 200, 229, 121, 161, 28, 48, 1, 193, 253, 65, 132, 91, 246, 188, 36, 71, 116, 198, 125, 108, 229, 219, 43, 119, 158, 6, 58, 131, 85, 5, 3, 33, 119, 49, 181, 28, 54, 155, 230,
    155, 187, 140, 102, 33, 183, 23, 117, 110, 238, 156, 21, 55, 0, 1, 0, 19, 169, 70, 144, 160, 9, 234, 18, 127, 142, 52, 164, 183, 128, 34, 195, 26, 233, 66, 37, 80, 31, 8, 172,
    63, 136, 137, 68, 7, 33, 29, 153, 130, 107, 64, 215, 105, 10, 6, 67, 54, 82, 106, 60, 204, 187, 162, 72, 130, 195, 96, 85, 6, 114, 128, 21, 54, 142, 139, 84, 211, 88, 181, 254,
    3, 213, 82, 119, 5, 209, 227, 102, 172, 42, 125, 193, 189, 132, 210, 32, 231, 58, 110, 38, 232, 39, 212, 248, 28, 209, 22, 88, 99, 210, 73, 6, 119, 144, 115, 143, 94, 131, 6, 14,
    78, 83, 167, 208, 129, 132, 50, 28, 131, 205, 26, 95, 46, 75, 104, 139, 41, 46, 144, 22, 173, 19, 117, 165, 242, 156, 238, 173, 160, 15, 225, 71, 96, 83, 140, 98, 59, 129, 220, 1,
    239, 60, 72, 105, 108, 33, 97, 169, 185, 132, 6, 38, 115, 216, 108, 109, 10, 106, 151, 142, 27, 108, 97, 186, 92, 10, 241, 72, 233, 73, 18, 154, 85, 238, 111, 4, 199, 16, 95, 114,
    159, 49, 59, 23, 79, 103, 174, 12, 247, 27, 205, 11, 88, 121, 70, 101, 205, 72, 105, 180, 99, 238, 99, 108, 53, 77, 157, 63, 52, 42, 169, 105, 35, 50, 74, 183, 147, 143, 80, 87,
    81, 103, 124, 152, 64, 51, 227, 208, 147, 120, 78, 238, 129, 75, 21, 14, 193, 62, 202, 48, 148, 44, 160, 216, 195, 42, 194, 220, 195, 28, 91, 138, 58, 196, 47, 229, 129, 54, 0, 85,
    161, 69, 160, 12, 109, 53, 116, 23, 92, 203, 225, 63, 33, 250, 180, 76, 57, 251, 208, 80, 38, 152, 101, 96, 15, 47, 235, 114, 120, 90, 238, 197, 12, 102, 38, 208, 46, 110, 234, 6,
    242, 41, 130, 67, 9, 247, 182, 133, 69, 167, 79, 164, 145, 166, 63, 228, 72, 115, 18, 2, 160, 197, 161, 104, 58, 201, 24, 40, 161, 19, 240, 63, 118, 42, 100, 120, 1, 154, 90, 110,
    113, 139, 139, 56, 38, 208, 58, 184, 120, 54, 206, 50, 72, 169, 102, 28, 68, 77, 15, 40, 47, 64, 220, 184, 140, 241, 143, 18, 37, 144, 67, 67, 75, 41, 112, 47, 64, 57, 16, 13,
    230, 25, 184, 146, 168, 113, 222, 254, 114, 42, 189, 53, 137, 158, 3, 113, 18, 15, 245, 211, 100, 162, 48, 248, 148, 6, 14, 18, 102, 69, 19, 140, 74, 231, 228, 170, 163, 122, 56, 186,
    121, 24, 119, 93, 112, 143, 47, 74, 148, 105, 88, 4, 61, 131, 159, 71, 173, 84, 39, 169, 56, 91, 57, 120, 54, 65, 57, 232, 142, 38, 112, 71, 224, 8, 250, 177, 89, 152, 41, 138,
    54, 189, 26, 130, 51, 31, 142, 177, 3, 152, 69, 200, 58, 221, 54, 205, 140, 146, 93, 130, 97, 66, 21, 205, 34, 234, 34, 116, 114, 80, 68, 13, 41, 74, 81, 146, 193, 163, 105, 84,
    135, 241, 78, 229, 71, 200, 152, 7, 20, 6, 165, 19, 137, 181, 20, 221, 148, 236, 244, 171, 236, 43, 35, 198, 219, 88, 40, 62, 60, 5, 72, 26, 23, 8, 14, 98, 112, 168, 57, 120,
    218, 65, 203, 192, 84, 248, 104, 120, 236, 128, 200, 241, 0, 84, 161, 218, 46, 155, 235, 140, 155, 13, 39, 19, 50, 90, 27, 6, 33, 16, 66, 104, 133, 83, 20, 72, 232, 56, 84, 27,
    156, 135, 9, 103, 69, 114, 43, 142, 63, 197, 248, 48, 150, 160, 57, 136, 229, 55, 25, 44, 147, 142, 225, 104, 28, 244, 19, 30, 1, 252, 74, 184, 247, 21, 99, 102, 104, 144, 131, 71,
    102, 196, 74, 169, 128, 87, 22, 145, 176, 18, 79, 65, 76, 169, 106, 176, 162, 142, 150, 71, 54, 11, 150, 200, 13, 150, 54, 212, 9, 193, 100, 87, 220, 216, 139, 253, 103, 18, 60, 177,
    42, 35, 51, 196, 38, 52, 237, 134, 234, 192, 40, 43, 228, 246, 225, 144, 47, 222, 113, 193, 136, 25, 97, 48, 140, 53, 37, 157, 98, 67, 239, 75, 25, 227, 94, 202, 144, 2, 134, 169,
    223, 232, 76, 39, 19, 138, 47, 90, 146, 111, 84, 40, 113, 172, 136, 95, 50, 9, 224, 104, 216, 173, 8, 186, 201, 94, 89, 90, 173, 212, 194, 1, 0, 38, 162, 52, 71, 91, 39, 116,
    16, 144, 52, 216, 140, 24, 16, 125, 33, 168, 230, 246, 208, 242, 237, 227, 111, 138, 78, 170, 39, 176, 75, 1, 205, 45, 133, 150, 186, 169, 17, 136, 66, 199, 157, 144, 91, 185, 38, 238,
    135, 200, 66, 102, 32, 100, 162, 28, 64, 28, 214, 138, 50, 3, 91, 134, 51, 205, 45, 187, 209, 57, 148, 137, 145, 62, 14, 192, 20, 162, 65, 77, 129, 67, 162, 122, 179, 70, 82, 232,
    36, 225, 46, 233, 242, 237, 93, 5, 140, 178, 78, 33, 139, 16, 41, 132, 87, 153, 152, 12, 244, 104, 50, 242, 17, 50, 135, 111, 198, 112, 32, 28, 21, 36, 112, 158, 57, 105, 203, 28,
    70, 247, 128, 192, 157, 233, 240, 109, 117, 122, 139, 184, 2, 2, 152, 53, 196, 130, 102, 196, 19, 111, 39, 233, 84, 72, 68, 197, 109, 163, 99, 198, 207, 20, 94, 132, 78, 137, 22, 93,
    145, 221, 169, 105, 60, 17, 163, 65, 88, 24, 202, 7, 121, 2, 85, 212, 8, 174, 252, 183, 55, 219, 220, 161, 94, 204, 163, 102, 130, 210, 28, 228, 18, 119, 123, 134, 139, 129, 81, 98,
    196, 196, 47, 159, 110, 25, 110, 247, 238, 38, 18, 63, 112, 63, 116, 16, 140, 59, 172, 83, 211, 32, 20, 52, 15, 112, 46, 129, 80, 21, 236, 46, 28, 183, 34, 12, 252, 183, 15, 190,
    76, 44, 209, 5, 200, 170, 104, 225, 253, 161, 97, 12, 67, 124, 157, 77, 52, 195, 70, 68, 74, 204, 110, 24, 120, 160, 182, 149, 192, 94, 139, 11, 10, 185, 5, 183, 102, 56, 142, 159,
    176, 131, 1, 253, 19, 237, 64, 190, 142, 17, 202, 41, 255, 30, 19, 35, 156, 48, 117, 61, 253, 187, 251, 153, 112, 179, 185, 73, 115, 195, 196, 189, 148, 152, 233, 244, 12, 97, 69, 111,
    243, 130, 54, 193, 238, 21, 238, 136, 73, 216, 255, 231, 203, 234, 58, 144, 219, 125, 182, 251, 150, 42, 156, 212, 187, 95, 220, 3, 189, 126, 108, 187, 5, 187, 46, 216, 221, 208, 135, 67,
    219, 149, 57, 145, 52, 56, 253, 124, 89, 92, 4, 197, 98, 42, 15, 89, 35, 89, 95, 150, 39, 103, 203, 224, 217, 233, 201, 234, 186, 88, 236, 106, 242, 249, 236, 106, 112, 90, 45, 125,
    45, 185, 59, 158, 79, 215, 52, 183, 38, 12, 185, 95, 202, 145, 108, 152, 2, 250, 162, 135, 211, 147, 103, 215, 7, 144, 154, 201, 250, 191, 223, 27, 92, 246, 196, 145, 241, 109, 238, 191,
    111, 17, 104, 30, 127, 14, 138, 201, 164, 188, 174, 199, 3, 130, 25, 201, 230, 44, 209, 197, 143, 3, 110, 245, 226, 159, 143, 28, 116, 31, 4, 247, 79, 126, 247, 118, 35, 239, 11, 0,
    232, 185, 131, 1, 207, 238, 115, 160, 169, 122, 95, 86, 218, 39, 176, 31, 148, 150, 173, 221, 119, 218, 113, 245, 22, 149, 155, 65, 238, 22, 155, 238, 52, 142, 191, 119, 176, 133, 61, 56,
    245, 232, 237, 148, 166, 123, 173, 218, 91, 186, 247, 136, 74, 183, 1, 239, 211, 150, 27, 122, 15, 137, 85, 167, 254, 250, 62, 237, 22, 163, 199, 183, 146, 27, 68, 63, 188, 89, 93, 93,
    31, 108, 116, 232, 210, 142, 129, 234, 191, 149, 129, 154, 191, 149, 129, 218, 255, 110, 3, 221, 87, 124, 221, 179, 50, 126, 27, 133, 181, 245, 94, 223, 203, 49, 216, 109, 142, 187, 200, 237,
    90, 151, 121, 132, 173, 88, 239, 243, 248, 0, 9, 186, 88, 242, 17, 251, 237, 246, 126, 81, 101, 16, 52, 143, 39, 183, 203, 32, 31, 255, 108, 161, 232, 19, 198, 111, 145, 184, 13, 116,
    189, 174, 50, 56, 141, 63, 222, 77, 161, 251, 16, 246, 250, 132, 118, 138, 255, 33, 151, 208, 223, 60, 232, 3, 61, 2, 39, 230, 239, 117, 194, 13, 140, 30, 53, 93, 223, 157, 132, 119,
    6, 137, 137, 73, 215, 211, 246, 73, 127, 214, 94, 206, 122, 243, 251, 251, 8, 205, 233, 150, 38, 10, 139, 207, 39, 185, 57, 35, 23, 151, 213, 27, 176, 113, 33, 193, 202, 142, 152, 76,
    230, 103, 152, 47, 71, 49, 179, 45, 190, 167, 38, 120, 17, 240, 45, 39, 105, 130, 164, 211, 69, 185, 114, 163, 0, 121, 95, 196, 160, 220, 36, 124, 143, 142, 26, 49, 61, 141, 18, 167,
    3, 155, 39, 145, 202, 83, 52, 209, 57, 234, 26, 38, 45, 58, 114, 185, 25, 5, 78, 187, 40, 205, 243, 192, 102, 73, 164, 51, 139, 2, 147, 68, 41, 231, 14, 178, 44, 74, 145, 36,
    188, 224, 168, 229, 45, 65, 200, 87, 162, 212, 87, 73, 163, 132, 120, 164, 56, 230, 142, 5, 89, 164, 248, 158, 35, 20, 216, 56, 145, 54, 121, 100, 152, 77, 166, 130, 193, 72, 10, 16,
    147, 114, 30, 78, 234, 243, 71, 211, 55, 231, 95, 155, 226, 36, 202, 115, 137, 159, 249, 178, 162, 166, 32, 99, 1, 239, 193, 142, 165, 62, 74, 24, 72, 19, 5, 67, 252, 249, 182, 24,
    206, 57, 198, 57, 170, 178, 19, 205, 119, 38, 113, 10, 95, 129, 88, 22, 109, 44, 70, 18, 39, 9, 18, 209, 40, 215, 201, 8, 228, 209, 168, 26, 7, 124, 37, 77, 170, 242, 209, 22,
    93, 65, 103, 12, 197, 153, 40, 73, 20, 90, 167, 113, 4, 218, 4, 169, 138, 16, 149, 131, 198, 124, 195, 141, 35, 121, 92, 132, 236, 99, 196, 4, 44, 178, 76, 6, 85, 34, 239, 65,
    2, 141, 65, 13, 199, 52, 214, 130, 130, 73, 60, 10, 44, 1, 90, 208, 56, 213, 145, 74, 209, 198, 130, 146, 76, 175, 145, 211, 128, 162, 57, 113, 204, 83, 190, 109, 135, 105, 113, 148,
    39, 160, 151, 65, 21, 23, 51, 199, 36, 191, 70, 93, 156, 94, 49, 37, 193, 69, 180, 55, 56, 230, 108, 143, 168, 63, 146, 185, 141, 132, 175, 198, 137, 249, 56, 87, 30, 197, 200, 182,
    77, 172, 162, 60, 213, 44, 224, 123, 162, 18, 95, 0, 154, 190, 224, 12, 120, 148, 187, 220, 151, 228, 172, 194, 161, 48, 149, 206, 112, 193, 162, 19, 5, 185, 209, 50, 239, 5, 60, 113,
    124, 137, 116, 29, 68, 228, 148, 31, 216, 233, 98, 206, 97, 176, 134, 34, 255, 112, 76, 88, 3, 189, 186, 216, 11, 71, 204, 119, 121, 165, 160, 126, 204, 201, 63, 150, 43, 212, 240, 152,
    0, 53, 185, 130, 244, 93, 229, 124, 79, 143, 128, 101, 205, 151, 156, 6, 4, 209, 51, 129, 47, 111, 6, 203, 181, 92, 1, 241, 208, 146, 52, 54, 153, 138, 50, 195, 55, 23, 165, 17,
    122, 6, 189, 82, 35, 76, 86, 78, 198, 205, 2, 16, 144, 19, 9, 40, 224, 84, 219, 11, 206, 136, 99, 188, 206, 151, 100, 164, 49, 7, 193, 228, 23, 162, 130, 204, 124, 116, 143, 174,
    175, 120, 131, 150, 44, 13, 100, 82, 254, 66, 206, 153, 206, 67, 11, 80, 133, 211, 2, 16, 112, 164, 158, 60, 77, 41, 213, 41, 95, 143, 149, 72, 205, 220, 42, 161, 28, 164, 145, 151,
    115, 131, 36, 48, 113, 81, 230, 79, 83, 74, 125, 178, 169, 237, 56, 77, 144, 240, 181, 76, 210, 25, 116, 152, 151, 71, 125, 12, 118, 6, 233, 77, 134, 182, 199, 164, 111, 237, 63, 212,
    183, 159, 235, 155, 41, 7, 167, 247, 246, 120, 125, 208, 5, 238, 191, 49, 113, 159, 237, 147, 92, 233, 158, 57, 238, 61, 229, 221, 143, 194, 219, 238, 154, 36, 233, 144, 235, 58, 240, 44,
    123, 219, 231, 158, 59, 55, 7, 167, 235, 141, 235, 2, 255, 158, 192, 40, 138, 30, 235, 222, 164, 216, 239, 165, 183, 222, 94, 65, 240, 233, 109, 46, 192, 204, 139, 41, 224, 120, 208, 217,
    7, 167, 125, 207, 223, 89, 83, 167, 193, 178, 215, 112, 31, 33, 31, 183, 222, 220, 110, 34, 107, 187, 174, 202, 159, 245, 23, 152, 185, 10, 214, 206, 13, 120, 39, 212, 186, 164, 183, 151,
    179, 122, 125, 26, 54, 29, 234, 117, 1, 239, 98, 152, 20, 215, 24, 23, 151, 232, 123, 197, 220, 167, 189, 45, 63, 148, 111, 55, 203, 15, 87, 74, 203, 50, 85, 152, 6, 248, 236, 205,
    70, 123, 109, 94, 41, 88, 32, 253, 165, 59, 144, 187, 238, 84, 13, 254, 251, 167, 42, 32, 157, 119, 240, 216, 243, 227, 145, 81, 140, 236, 180, 245, 96, 12, 211, 221, 199, 242, 103, 68,
    48, 127, 13, 177, 202, 249, 185, 198, 191, 199, 199, 42, 112, 210, 48, 102, 176, 98, 47, 248, 86, 69, 153, 39, 71, 248, 144, 36, 12, 83, 96, 221, 249, 150, 197, 156, 47, 127, 68, 1,
    163, 6, 248, 99, 235, 248, 38, 65, 241, 102, 198, 194, 222, 167, 65, 194, 23, 211, 73, 148, 194, 215, 174, 113, 154, 84, 3, 91, 246, 225, 12, 95, 226, 198, 62, 242, 198, 50, 51, 50,
    176, 6, 158, 41, 111, 34, 20, 203, 105, 202, 204, 70, 154, 158, 140, 17, 10, 95, 122, 72, 175, 4, 3, 44, 245, 225, 105, 181, 247, 152, 202, 7, 27, 25, 189, 158, 24, 101, 184, 137,
    38, 170, 161, 151, 118, 155, 54, 169, 183, 211, 240, 196, 77, 183, 64, 80, 166, 223, 44, 220, 144, 243, 120, 229, 84, 39, 35, 209, 13, 134, 12, 71, 28, 136, 27, 205, 232, 212, 225, 88,
    99, 70, 30, 6, 213, 25, 121, 172, 169, 68, 138, 193, 13, 114, 140, 0, 47, 113, 75, 154, 71, 41, 162, 57, 122, 45, 139, 49, 133, 214, 83, 45, 225, 219, 38, 1, 59, 231, 187, 42,
    181, 204, 65, 190, 224, 186, 4, 95, 103, 23, 192, 157, 1, 2, 67, 12, 32, 237, 184, 104, 7, 10, 56, 6, 20, 140, 57, 172, 179, 164, 15, 130, 54, 82, 25, 116, 67, 232, 4, 175,
    10, 175, 99, 233, 106, 76, 134, 97, 165, 156, 126, 141, 50, 109, 71, 219, 24, 189, 18, 255, 155, 112, 213, 24, 78, 143, 222, 247, 165, 196, 43, 25, 28, 155, 66, 92, 153, 112, 250, 25,
    71, 46, 0, 106, 67, 255, 28, 211, 219, 227, 151, 248, 84, 120, 234, 188, 169, 161, 185, 228, 23, 91, 190, 36, 178, 233, 131, 183, 147, 24, 196, 58, 9, 34, 20, 149, 58, 80, 7, 104,
    96, 8, 12, 97, 32, 64, 24, 132, 225, 2, 98, 130, 120, 32, 207, 25, 152, 48, 162, 66, 39, 169, 101, 19, 22, 128, 58, 144, 24, 131, 182, 185, 19, 204, 16, 81, 197, 169, 143, 50,
    16, 168, 201, 98, 19, 232, 37, 184, 188, 20, 127, 202, 155, 59, 76, 12, 6, 202, 27, 57, 129, 101, 194, 112, 41, 151, 112, 242, 133, 120, 114, 121, 39, 35, 98, 17, 67, 153, 210, 89,
    238, 169, 195, 23, 71, 74, 136, 22, 51, 252, 229, 171, 68, 17, 134, 75, 116, 202, 75, 92, 172, 246, 1, 56, 25, 206, 151, 40, 130, 45, 64, 194, 159, 100, 92, 35, 74, 37, 26, 177,
    148, 13, 221, 92, 2, 219, 50, 8, 175, 129, 48, 38, 12, 46, 12, 226, 57, 70, 79, 198, 49, 54, 74, 129, 177, 129, 56, 112, 169, 133, 84, 226, 10, 163, 177, 148, 65, 43, 116, 76,
    45, 163, 38, 226, 19, 199, 70, 198, 102, 115, 211, 212, 128, 204, 27, 45, 49, 90, 219, 71, 39, 174, 74, 24, 239, 104, 225, 43, 161, 189, 20, 28, 29, 151, 6, 64, 123, 129, 18, 131,
    91, 242, 98, 84, 42, 146, 22, 202, 229, 18, 31, 89, 222, 103, 128, 158, 83, 46, 209, 172, 175, 178, 103, 98, 217, 182, 223, 150, 24, 137, 168, 68, 235, 50, 31, 77, 233, 216, 211, 62,
    117, 18, 81, 197, 218, 19, 158, 196, 139, 69, 252, 121, 213, 199, 254, 177, 143, 252, 65, 34, 33, 127, 123, 74, 13, 220, 212, 78, 90, 94, 52, 157, 49, 244, 246, 181, 61, 88, 136, 137,
    118, 155, 211, 236, 103, 68, 84, 157, 29, 24, 31, 138, 166, 252, 142, 56, 187, 99, 137, 78, 103, 205, 14, 140, 187, 38, 34, 154, 141, 154, 248, 72, 93, 113, 81, 204, 22, 187, 251, 106,
    2, 144, 237, 184, 67, 255, 167, 7, 30, 221, 176, 227, 255, 7, 29, 191, 84, 208, 241, 25, 183, 117, 230, 83, 221, 213, 131, 145, 71, 119, 7, 232, 150, 209, 147, 189, 235, 46, 157, 232,
    190, 251, 60, 237, 222, 248, 96, 87, 101, 47, 183, 27, 20, 63, 40, 146, 238, 32, 176, 222, 175, 101, 239, 156, 214, 125, 116, 155, 231, 66, 31, 49, 17, 119, 255, 145, 213, 131, 242, 114,
    250, 155, 118, 39, 171, 38, 110, 58, 188, 94, 179, 78, 116, 118, 111, 13, 185, 19, 9, 63, 231, 118, 56, 213, 121, 220, 172, 238, 135, 142, 237, 245, 231, 255, 243, 3, 135, 117, 111, 147,
    202, 191, 178, 17, 125, 198, 61, 46, 3, 154, 224, 71, 14, 104, 123, 203, 204, 191, 178, 241, 172, 183, 186, 191, 110, 54, 234, 124, 228, 176, 250, 187, 81, 254, 194, 131, 250, 160, 201, 222,
    102, 155, 250, 135, 103, 123, 251, 251, 217, 255, 37, 77, 86, 139, 227, 127, 15, 131, 197, 87, 83, 241, 45, 92, 15, 72, 138, 95, 143, 38, 229, 219, 183, 118, 237, 175, 45, 45, 170, 107,
    121, 132, 67, 214, 31, 96, 223, 150, 131, 102, 77, 187, 156, 174, 109, 228, 201, 51, 95, 233, 195, 122, 90, 13, 78, 185, 38, 29, 172, 222, 173, 234, 242, 234, 225, 62, 32, 177, 2, 248,
    47, 171, 136, 254, 65, 90, 255, 136, 246, 205, 245, 195, 22, 166, 187, 114, 191, 222, 35, 206, 235, 230, 142, 77, 231, 90, 180, 118, 94, 59, 20, 156, 204, 139, 179, 114, 30, 156, 87, 203,
    195, 253, 118, 159, 240, 166, 148, 74, 179, 255, 48, 165, 111, 30, 230, 122, 48, 68, 233, 190, 137, 98, 215, 236, 200, 190, 59, 68, 214, 86, 177, 9, 127, 63, 244, 62, 145, 93, 211, 118,
    91, 187, 6, 7, 124, 11, 206, 253, 210, 157, 241, 243, 86, 165, 67, 90, 135, 40, 186, 141, 106, 123, 83, 51, 254, 172, 23, 38, 171, 88, 91, 249, 218, 126, 124, 228, 17, 97, 184, 143,
    173, 123, 209, 116, 123, 250, 128, 110, 174, 131, 93, 62, 5, 161, 99, 19, 169, 73, 168, 242, 200, 240, 54, 123, 102, 119, 81, 202, 163, 113, 183, 156, 78, 208, 19, 222, 122, 20, 185, 32,
    137, 82, 134, 245, 42, 141, 152, 57, 70, 230, 101, 226, 120, 111, 20, 146, 196, 137, 99, 81, 132, 104, 91, 69, 73, 128, 28, 205, 87, 146, 31, 58, 226, 189, 83, 218, 68, 89, 152, 68,
    70, 26, 134, 114, 53, 7, 20, 197, 62, 109, 200, 169, 152, 16, 53, 179, 208, 166, 81, 54, 15, 149, 20, 100, 241, 109, 168, 83, 59, 137, 121, 49, 103, 51, 23, 37, 64, 44, 52, 54,
    202, 113, 252, 241, 176, 210, 236, 143, 211, 215, 92, 18, 151, 180, 126, 194, 117, 240, 95, 133, 107, 57, 178, 98, 29, 88, 157, 69, 124, 90, 70, 129, 50, 9, 191, 64, 22, 195, 39, 88,
    64, 164, 36, 19, 42, 199, 145, 14, 145, 196, 231, 161, 205, 241, 197, 217, 148, 48, 215, 17, 239, 164, 53, 56, 231, 250, 161, 229, 37, 48, 128, 207, 63, 216, 144, 83, 97, 188, 95, 31,
    141, 185, 38, 20, 114, 234, 136, 179, 89, 108, 161, 201, 5, 203, 159, 25, 11, 32, 51, 97, 158, 68, 188, 115, 51, 146, 59, 241, 162, 12, 178, 128, 66, 100, 243, 17, 159, 46, 113, 145,
    249, 38, 151, 59, 32, 27, 214, 165, 194, 58, 254, 95, 109, 73, 25, 167, 132, 28, 165, 140, 34, 200, 242, 64, 202, 241, 255, 146, 51, 12, 106, 226, 101, 51, 144, 59, 241, 229, 170, 116,
    210, 235, 243, 50, 204, 146, 40, 153, 56, 135, 129, 185, 4, 200, 112, 165, 42, 11, 57, 97, 5, 9, 79, 41, 107, 92, 67, 36, 215, 56, 244, 92, 10, 21, 132, 214, 200, 76, 165, 9,
    48, 234, 36, 224, 50, 105, 192, 73, 25, 222, 150, 28, 241, 46, 229, 140, 50, 156, 24, 246, 226, 20, 127, 183, 93, 72, 75, 246, 17, 74, 75, 233, 36, 116, 68, 20, 157, 240, 70, 92,
    105, 137, 94, 116, 200, 150, 137, 244, 162, 229, 241, 36, 82, 29, 212, 138, 248, 136, 8, 80, 146, 31, 224, 154, 60, 13, 3, 178, 133, 224, 14, 111, 192, 84, 168, 151, 228, 104, 35, 29,
    18, 171, 208, 247, 199, 190, 201, 39, 211, 244, 13, 70, 145, 18, 236, 135, 124, 79, 217, 156, 188, 86, 92, 104, 11, 148, 140, 151, 205, 200, 66, 206, 163, 134, 70, 196, 69, 100, 68, 46,
    112, 56, 9, 171, 74, 141, 140, 106, 202, 26, 144, 167, 192, 10, 16, 168, 107, 150, 6, 142, 85, 160, 192, 188, 103, 156, 20, 227, 23, 133, 46, 16, 161, 11, 40, 116, 129, 8, 93, 64,
    161, 11, 40, 116, 1, 133, 46, 160, 208, 5, 34, 116, 178, 104, 109, 121, 137, 51, 130, 188, 159, 53, 160, 208, 5, 34, 116, 92, 141, 77, 217, 22, 249, 122, 196, 27, 194, 133, 95, 248,
    202, 115, 194, 228, 47, 200, 60, 205, 9, 56, 76, 172, 192, 48, 202, 60, 59, 16, 13, 16, 180, 188, 6, 120, 188, 68, 3, 4, 47, 209, 0, 65, 75, 52, 64, 208, 242, 10, 224, 241,
    50, 94, 19, 2, 175, 2, 64, 75, 20, 192, 163, 5, 13, 112, 162, 11, 224, 103, 228, 188, 46, 208, 220, 121, 85, 248, 51, 205, 80, 231, 6, 195, 251, 207, 163, 15, 54, 185, 193, 38,
    252, 58, 20, 202, 239, 154, 104, 240, 87, 188, 167, 220, 227, 106, 125, 220, 243, 231, 57, 218, 77, 212, 179, 229, 93, 123, 101, 187, 125, 107, 183, 202, 3, 54, 251, 241, 243, 83, 186, 183,
    48, 166, 239, 47, 140, 117, 204, 248, 122, 25, 196, 156, 241, 150, 13, 62, 208, 126, 62, 175, 222, 110, 238, 185, 20, 176, 207, 111, 61, 224, 21, 32, 223, 34, 56, 45, 162, 89, 245, 108,
    81, 44, 170, 71, 155, 110, 3, 89, 74, 248, 28, 162, 131, 76, 153, 188, 224, 116, 111, 146, 7, 205, 65, 144, 226, 4, 125, 106, 20, 87, 6, 146, 228, 83, 89, 88, 231, 220, 113, 115,
    140, 125, 37, 202, 61, 44, 149, 18, 231, 156, 197, 178, 230, 207, 213, 250, 36, 207, 164, 106, 178, 117, 120, 157, 161, 87, 156, 37, 156, 90, 71, 221, 230, 84, 58, 224, 205, 233, 64, 202,
    209, 139, 240, 81, 21, 136, 119, 194, 187, 166, 97, 113, 82, 62, 107, 144, 241, 230, 131, 212, 163, 234, 49, 21, 52, 21, 60, 80, 20, 91, 71, 87, 97, 226, 236, 83, 11, 251, 202, 105,
    252, 246, 232, 7, 147, 107, 218, 62, 143, 168, 134, 190, 201, 253, 227, 80, 27, 78, 147, 179, 102, 18, 202, 183, 255, 253, 154, 166, 21, 170, 7, 19, 196, 201, 115, 127, 134, 182, 5, 175,
    90, 227, 107, 241, 232, 251, 214, 208, 119, 222, 235, 109, 92, 22, 217, 68, 253, 136, 112, 166, 105, 116, 25, 255, 123, 139, 104, 7, 237, 91, 1, 242, 239, 77, 89, 216, 185, 130, 250, 205,
    105, 28, 118, 46, 222, 134, 77, 139, 110, 93, 255, 251, 199, 93, 79, 91, 109, 180, 237, 3, 148, 126, 107, 163, 128, 118, 189, 250, 207, 211, 243, 126, 217, 189, 160, 254, 126, 52, 255, 187,
    206, 19, 218, 1, 159, 125, 223, 27, 208, 111, 191, 31, 166, 29, 200, 118, 249, 174, 213, 206, 118, 230, 98, 215, 91, 132, 118, 78, 82, 108, 225, 190, 117, 186, 41, 231, 16, 126, 227, 119,
    195, 238, 34, 222, 77, 6, 253, 102, 217, 219, 79, 125, 95, 159, 126, 181, 44, 235, 250, 29, 19, 234, 48, 104, 94, 190, 194, 5, 4, 156, 253, 223, 255, 3, 15, 175, 93, 47, 5, 236,
    96, 0, 46, 200, 51, 230, 39, 207, 184, 175, 247, 233, 255, 3, 236, 116, 132, 221, 255, 144, 0, 0
};

const uint8_t PrettyOTA::PRETTY_OTA_LOGIN_DATA[6101] = {
    31, 139, 8, 8, 247, 252, 213, 103, 0, 3, 108, 111, 103, 105, 110, 95, 109, 105, 110, 105, 102, 121, 46, 104, 116, 109, 108, 0, 189, 91, 253, 115, 219, 198, 153, 254, 61, 127, 5, 142, 113,
    108, 178, 38, 160, 253, 222, 133, 36, 170, 147, 248, 210, 73, 111, 146, 182, 211, 164, 153, 206, 100, 92, 15, 4, 66, 18, 26, 8, 208, 145, 160, 100, 215, 118, 255, 246, 123, 158, 5, 73,
    129, 140, 237, 100, 110, 110, 206, 10, 241, 177, 216, 221, 247, 235, 121, 63, 128, 221, 156, 255, 199, 178, 43, 251, 55, 119, 85, 114, 211, 223, 54, 23, 159, 157, 243, 148, 52, 69, 123, 189,
    152, 84, 237, 228, 226, 179, 4, 255, 206, 111, 170, 98, 57, 92, 198, 219, 219, 170, 47, 146, 242, 166, 88, 173, 171, 126, 49, 249, 219, 15, 127, 72, 195, 36, 57, 57, 238, 208, 22, 183,
    213, 98, 114, 95, 87, 15, 119, 221, 170, 159, 36, 101, 215, 246, 85, 139, 1, 15, 245, 178, 191, 89, 44, 171, 251, 186, 172, 210, 120, 51, 79, 234, 182, 238, 235, 162, 73, 215, 101, 209,
    84, 11, 153, 137, 143, 78, 184, 172, 214, 229, 170, 190, 235, 235, 174, 29, 205, 249, 101, 114, 89, 245, 125, 181, 74, 154, 174, 251, 185, 110, 175, 147, 63, 255, 240, 101, 242, 80, 93, 38,
    155, 187, 101, 129, 246, 236, 112, 190, 190, 238, 155, 234, 226, 219, 238, 186, 110, 147, 52, 249, 203, 10, 99, 223, 96, 196, 249, 201, 240, 224, 177, 99, 83, 183, 63, 39, 171, 170, 89, 76,
    234, 146, 4, 169, 42, 92, 223, 22, 215, 213, 201, 250, 254, 250, 249, 235, 219, 102, 146, 220, 172, 170, 43, 48, 86, 244, 197, 233, 193, 147, 249, 23, 250, 5, 46, 19, 92, 182, 235, 197,
    179, 155, 190, 191, 59, 61, 57, 121, 120, 120, 200, 30, 116, 214, 173, 174, 79, 148, 16, 130, 157, 159, 37, 131, 78, 158, 89, 169, 158, 37, 55, 85, 125, 125, 211, 111, 111, 226, 216, 211,
    251, 97, 244, 26, 195, 239, 171, 178, 47, 178, 186, 59, 105, 139, 182, 123, 246, 133, 254, 26, 68, 238, 138, 254, 38, 89, 46, 158, 125, 39, 18, 113, 131, 97, 247, 248, 125, 35, 126, 20,
    255, 122, 150, 92, 213, 77, 179, 120, 246, 133, 210, 198, 242, 239, 217, 201, 209, 8, 105, 109, 166, 109, 72, 66, 158, 5, 171, 27, 157, 105, 47, 211, 76, 40, 149, 232, 204, 11, 133, 75,
    17, 112, 25, 242, 156, 173, 137, 84, 89, 80, 14, 151, 70, 38, 38, 51, 90, 227, 82, 170, 68, 137, 44, 120, 182, 226, 82, 103, 185, 99, 15, 239, 19, 25, 50, 27, 56, 208, 132, 68,
    194, 168, 177, 93, 187, 23, 42, 87, 153, 87, 142, 68, 53, 8, 97, 180, 242, 46, 201, 109, 102, 148, 79, 180, 113, 32, 35, 74, 12, 176, 82, 114, 92, 176, 152, 10, 93, 49, 139, 114,
    153, 12, 38, 81, 38, 49, 170, 1, 33, 11, 222, 164, 176, 165, 205, 172, 3, 109, 208, 48, 58, 81, 153, 67, 31, 99, 50, 149, 218, 216, 199, 81, 0, 219, 164, 50, 211, 130, 35, 132,
    122, 161, 173, 206, 44, 70, 224, 148, 227, 172, 181, 198, 32, 12, 245, 42, 3, 53, 13, 194, 42, 200, 50, 133, 4, 14, 130, 184, 204, 231, 54, 213, 46, 115, 42, 79, 124, 166, 242, 212,
    186, 76, 67, 112, 159, 73, 78, 236, 178, 92, 81, 126, 145, 115, 132, 136, 170, 136, 151, 86, 80, 67, 230, 91, 233, 45, 38, 12, 77, 84, 39, 37, 82, 153, 52, 158, 60, 58, 80, 20,
    94, 146, 119, 39, 192, 154, 117, 84, 91, 0, 45, 161, 109, 146, 131, 127, 15, 126, 53, 245, 32, 13, 27, 53, 4, 208, 82, 151, 180, 7, 153, 17, 206, 164, 153, 133, 230, 165, 206, 148,
    132, 196, 80, 14, 103, 176, 26, 215, 193, 65, 17, 153, 119, 96, 70, 100, 34, 12, 204, 235, 84, 122, 8, 228, 227, 96, 13, 230, 37, 248, 102, 67, 236, 4, 198, 161, 26, 171, 82, 204,
    231, 189, 78, 67, 166, 157, 71, 147, 208, 42, 53, 80, 160, 73, 169, 170, 60, 245, 153, 101, 79, 192, 37, 130, 2, 90, 32, 108, 216, 18, 1, 34, 2, 122, 11, 104, 13, 173, 113, 92,
    84, 10, 58, 155, 76, 218, 1, 54, 104, 14, 62, 130, 73, 165, 74, 101, 185, 84, 17, 54, 41, 140, 108, 162, 58, 77, 72, 129, 13, 163, 243, 8, 27, 210, 81, 130, 232, 148, 224, 84,
    102, 38, 66, 142, 179, 40, 97, 202, 97, 40, 152, 53, 236, 65, 89, 0, 108, 88, 20, 8, 64, 31, 104, 151, 2, 67, 221, 138, 3, 164, 6, 248, 178, 92, 19, 32, 30, 234, 178, 208,
    187, 141, 215, 10, 46, 160, 242, 72, 196, 65, 209, 54, 200, 8, 112, 72, 149, 147, 83, 224, 34, 100, 210, 217, 193, 47, 192, 80, 110, 221, 96, 8, 24, 44, 152, 65, 0, 186, 131, 142,
    237, 214, 38, 80, 169, 55, 113, 168, 47, 21, 167, 9, 177, 217, 104, 114, 151, 82, 232, 196, 1, 233, 150, 104, 145, 240, 2, 244, 119, 80, 32, 205, 157, 131, 130, 3, 74, 161, 5, 72,
    1, 26, 184, 83, 208, 163, 129, 236, 176, 15, 232, 193, 172, 108, 114, 176, 161, 247, 176, 6, 204, 135, 222, 176, 110, 110, 99, 183, 92, 230, 209, 140, 212, 59, 38, 212, 169, 130, 253, 189,
    138, 186, 145, 41, 208, 23, 100, 188, 81, 94, 54, 176, 92, 136, 14, 47, 29, 212, 40, 53, 149, 43, 67, 52, 238, 224, 195, 50, 213, 128, 42, 1, 45, 97, 5, 101, 160, 88, 234, 9,
    82, 160, 143, 143, 241, 33, 164, 12, 35, 106, 48, 41, 180, 7, 41, 133, 132, 109, 60, 12, 74, 29, 32, 0, 192, 254, 142, 134, 54, 208, 39, 244, 228, 34, 98, 3, 141, 226, 2, 1,
    27, 100, 74, 167, 50, 196, 162, 36, 56, 225, 192, 91, 188, 70, 136, 70, 180, 38, 91, 132, 70, 184, 38, 3, 66, 7, 184, 194, 196, 82, 218, 84, 49, 98, 17, 236, 193, 69, 184, 70,
    91, 169, 220, 69, 192, 142, 195, 162, 42, 47, 117, 225, 118, 97, 145, 193, 24, 87, 135, 201, 98, 200, 55, 219, 208, 127, 219, 45, 55, 77, 133, 204, 179, 234, 214, 235, 110, 85, 35, 131,
    60, 118, 229, 191, 251, 98, 149, 172, 111, 186, 135, 31, 234, 219, 170, 219, 244, 243, 219, 165, 93, 92, 109, 218, 146, 9, 107, 58, 123, 187, 187, 76, 94, 77, 95, 205, 171, 121, 63, 111,
    231, 79, 230, 171, 217, 91, 14, 171, 231, 155, 51, 164, 162, 205, 170, 77, 186, 233, 180, 94, 116, 211, 110, 90, 205, 95, 205, 230, 221, 180, 69, 159, 217, 124, 179, 120, 50, 175, 207, 207,
    55, 239, 234, 139, 139, 11, 128, 119, 51, 155, 247, 179, 247, 251, 41, 171, 233, 110, 194, 110, 190, 154, 215, 179, 183, 219, 201, 94, 77, 251, 167, 237, 187, 127, 247, 79, 159, 68, 138, 195,
    195, 199, 97, 253, 39, 134, 61, 121, 215, 62, 253, 247, 135, 135, 181, 31, 31, 246, 143, 246, 31, 31, 30, 243, 228, 163, 99, 218, 127, 76, 251, 119, 255, 126, 50, 251, 224, 176, 142, 186,
    26, 116, 212, 47, 166, 206, 90, 109, 159, 190, 154, 61, 223, 94, 85, 179, 173, 214, 166, 175, 46, 46, 164, 67, 123, 181, 61, 247, 241, 124, 126, 46, 221, 187, 161, 107, 255, 126, 75, 112,
    100, 6, 40, 31, 170, 111, 215, 125, 209, 150, 85, 119, 149, 252, 173, 110, 251, 240, 229, 106, 85, 188, 121, 247, 110, 186, 90, 180, 213, 67, 242, 67, 245, 186, 255, 186, 45, 187, 101, 181,
    154, 206, 178, 42, 94, 77, 39, 235, 126, 133, 74, 99, 178, 88, 16, 25, 24, 184, 250, 253, 234, 244, 191, 190, 255, 243, 159, 178, 225, 65, 125, 245, 6, 115, 207, 102, 103, 87, 221, 106,
    186, 53, 239, 226, 167, 151, 243, 117, 156, 242, 145, 10, 58, 205, 139, 133, 152, 47, 23, 235, 236, 242, 77, 95, 125, 91, 181, 215, 253, 205, 89, 113, 190, 60, 43, 158, 63, 159, 109, 178,
    187, 205, 250, 102, 250, 125, 156, 51, 187, 90, 117, 183, 47, 80, 121, 189, 32, 7, 235, 159, 138, 151, 179, 157, 240, 99, 145, 160, 171, 29, 81, 104, 123, 49, 65, 4, 67, 254, 119, 62,
    228, 197, 101, 185, 172, 174, 38, 243, 39, 139, 201, 100, 222, 45, 196, 89, 119, 94, 101, 205, 64, 177, 3, 181, 39, 207, 23, 109, 198, 210, 238, 203, 126, 58, 237, 23, 85, 188, 38, 49,
    220, 119, 179, 25, 96, 103, 158, 74, 59, 123, 190, 239, 36, 161, 212, 61, 11, 79, 222, 79, 63, 194, 5, 201, 181, 32, 215, 158, 107, 245, 187, 61, 197, 246, 249, 34, 204, 250, 231, 139,
    15, 9, 87, 253, 212, 94, 92, 216, 151, 160, 216, 126, 161, 213, 83, 101, 237, 158, 76, 127, 64, 102, 192, 209, 79, 53, 123, 191, 91, 72, 21, 206, 207, 107, 140, 152, 175, 126, 146, 230,
    249, 180, 126, 238, 12, 230, 200, 207, 207, 205, 236, 229, 162, 222, 27, 99, 179, 144, 94, 43, 27, 140, 204, 53, 76, 130, 192, 136, 123, 29, 124, 14, 91, 164, 251, 71, 6, 86, 217, 61,
    9, 243, 6, 2, 52, 231, 171, 29, 247, 205, 243, 5, 208, 21, 81, 89, 46, 54, 243, 171, 197, 122, 126, 189, 40, 230, 40, 109, 207, 214, 139, 39, 211, 195, 95, 123, 244, 235, 143, 126,
    213, 225, 15, 92, 84, 211, 2, 212, 171, 233, 18, 176, 169, 166, 155, 57, 218, 230, 75, 72, 213, 60, 23, 47, 231, 126, 158, 186, 32, 144, 61, 115, 237, 102, 241, 17, 31, 200, 151, 115,
    169, 230, 169, 70, 177, 227, 140, 13, 120, 194, 97, 124, 162, 240, 196, 207, 157, 112, 40, 150, 130, 204, 103, 152, 105, 19, 31, 232, 151, 115, 133, 33, 82, 24, 164, 20, 171, 181, 152, 125,
    146, 180, 137, 164, 145, 167, 140, 68, 86, 240, 143, 164, 109, 36, 45, 89, 209, 6, 4, 255, 17, 105, 23, 73, 35, 238, 67, 169, 168, 91, 140, 124, 36, 238, 7, 226, 198, 122, 97, 243,
    160, 63, 77, 58, 144, 180, 244, 30, 25, 200, 26, 57, 146, 58, 31, 164, 70, 33, 6, 147, 25, 35, 253, 35, 109, 41, 6, 226, 6, 57, 82, 63, 210, 149, 114, 43, 117, 158, 11, 131,
    196, 230, 212, 167, 73, 75, 21, 105, 67, 48, 148, 104, 46, 168, 145, 198, 245, 64, 220, 8, 8, 134, 180, 56, 34, 109, 182, 114, 91, 1, 165, 40, 149, 139, 17, 125, 27, 233, 195, 43,
    29, 162, 146, 86, 57, 201, 247, 145, 124, 31, 201, 247, 135, 228, 95, 206, 45, 38, 114, 22, 53, 136, 149, 226, 145, 58, 84, 155, 211, 118, 46, 183, 200, 218, 90, 141, 168, 19, 10, 102,
    238, 12, 202, 121, 239, 229, 72, 118, 104, 68, 9, 96, 196, 3, 37, 94, 11, 245, 105, 210, 54, 146, 246, 2, 175, 9, 193, 229, 114, 36, 184, 32, 109, 29, 64, 87, 208, 114, 123, 194,
    54, 18, 78, 157, 19, 198, 7, 173, 237, 35, 101, 51, 80, 54, 40, 127, 180, 15, 38, 124, 154, 114, 78, 202, 22, 133, 188, 129, 16, 97, 68, 216, 108, 133, 70, 121, 4, 99, 80, 173,
    59, 218, 122, 32, 45, 131, 215, 78, 231, 110, 4, 180, 16, 73, 75, 232, 200, 106, 24, 68, 254, 138, 190, 245, 160, 112, 3, 218, 1, 69, 247, 8, 230, 42, 18, 183, 18, 246, 134, 8,
    143, 164, 125, 36, 141, 64, 1, 107, 6, 32, 125, 100, 107, 53, 136, 45, 115, 5, 157, 160, 66, 49, 36, 222, 70, 226, 109, 36, 222, 30, 107, 220, 208, 60, 1, 26, 127, 164, 11, 1,
    164, 156, 163, 96, 82, 202, 122, 176, 165, 143, 76, 237, 128, 78, 157, 11, 188, 222, 16, 203, 123, 218, 84, 185, 198, 108, 86, 163, 18, 183, 238, 211, 148, 101, 164, 44, 217, 55, 135, 191,
    140, 112, 102, 34, 117, 137, 202, 49, 228, 48, 169, 62, 148, 219, 113, 144, 53, 185, 143, 8, 220, 211, 22, 3, 109, 84, 107, 208, 7, 94, 82, 196, 175, 80, 215, 36, 15, 125, 43, 159,
    75, 111, 30, 137, 139, 65, 116, 188, 164, 2, 54, 74, 169, 67, 123, 131, 56, 26, 173, 146, 185, 31, 69, 53, 23, 105, 123, 135, 194, 92, 134, 252, 211, 132, 243, 40, 54, 248, 211, 206,
    224, 149, 98, 132, 52, 53, 80, 54, 74, 6, 105, 3, 161, 124, 128, 114, 55, 135, 170, 240, 198, 96, 213, 200, 181, 213, 32, 117, 158, 35, 150, 6, 120, 43, 105, 63, 137, 180, 159, 68,
    218, 79, 142, 35, 57, 181, 151, 7, 167, 5, 144, 254, 72, 155, 122, 37, 96, 21, 222, 180, 164, 145, 246, 40, 174, 68, 116, 18, 205, 38, 23, 35, 15, 99, 88, 1, 195, 64, 136, 166,
    151, 125, 154, 54, 197, 3, 108, 16, 79, 13, 176, 230, 71, 190, 173, 35, 113, 248, 81, 110, 192, 25, 146, 198, 81, 64, 37, 117, 97, 165, 85, 99, 152, 15, 164, 149, 0, 75, 10, 38,
    204, 63, 77, 60, 68, 218, 112, 84, 100, 4, 109, 243, 145, 210, 237, 64, 28, 136, 145, 128, 129, 57, 204, 35, 164, 108, 29, 93, 31, 145, 103, 68, 92, 71, 234, 18, 200, 149, 86, 58,
    243, 43, 196, 205, 160, 117, 131, 87, 8, 24, 112, 132, 243, 232, 74, 148, 28, 121, 76, 73, 184, 120, 126, 152, 65, 237, 220, 131, 231, 224, 149, 29, 97, 45, 31, 36, 215, 208, 57, 244,
    72, 139, 111, 80, 185, 111, 230, 37, 230, 197, 197, 122, 126, 69, 110, 58, 112, 115, 141, 65, 184, 88, 206, 111, 102, 219, 58, 244, 167, 45, 91, 47, 63, 94, 56, 13, 53, 226, 174, 100,
    186, 184, 0, 254, 135, 66, 170, 127, 172, 162, 158, 207, 250, 159, 218, 151, 104, 229, 176, 225, 105, 56, 174, 178, 134, 114, 234, 221, 98, 138, 74, 234, 233, 65, 93, 215, 158, 132, 25, 138,
    100, 150, 89, 163, 10, 171, 94, 108, 178, 127, 118, 117, 59, 157, 76, 240, 230, 17, 126, 87, 111, 167, 67, 69, 251, 254, 253, 20, 85, 237, 142, 95, 190, 236, 188, 216, 172, 251, 238, 246,
    203, 166, 90, 245, 211, 87, 179, 183, 203, 174, 220, 220, 86, 109, 159, 93, 87, 253, 215, 77, 197, 203, 175, 222, 252, 113, 57, 157, 180, 93, 95, 95, 213, 101, 193, 129, 223, 85, 235, 117,
    113, 93, 77, 102, 89, 221, 182, 213, 138, 53, 246, 226, 213, 252, 55, 13, 253, 170, 88, 97, 88, 217, 20, 235, 245, 183, 245, 186, 207, 138, 37, 58, 144, 143, 201, 108, 94, 54, 85, 177,
    218, 190, 124, 77, 71, 47, 98, 176, 198, 227, 205, 98, 93, 245, 187, 62, 163, 151, 179, 255, 21, 241, 85, 117, 219, 221, 87, 59, 250, 239, 231, 190, 210, 163, 87, 151, 155, 122, 89, 141,
    181, 51, 123, 251, 113, 6, 255, 47, 200, 127, 116, 142, 134, 31, 59, 191, 218, 244, 125, 215, 98, 60, 52, 246, 245, 61, 158, 113, 138, 10, 218, 159, 78, 202, 166, 46, 127, 158, 204, 247,
    218, 128, 25, 155, 170, 79, 170, 248, 182, 242, 247, 239, 190, 253, 166, 239, 239, 254, 90, 253, 247, 166, 90, 247, 103, 85, 214, 181, 171, 170, 88, 190, 193, 75, 83, 95, 1, 74, 237, 117,
    53, 126, 201, 53, 11, 188, 57, 196, 14, 223, 179, 195, 211, 167, 83, 148, 64, 108, 99, 255, 205, 250, 247, 15, 117, 187, 236, 30, 178, 166, 27, 68, 66, 215, 187, 166, 40, 33, 196, 201,
    240, 185, 118, 50, 59, 53, 66, 142, 6, 76, 143, 65, 198, 233, 215, 119, 93, 187, 174, 136, 155, 79, 168, 110, 179, 174, 86, 245, 18, 18, 223, 23, 205, 166, 226, 107, 200, 71, 187, 222,
    61, 140, 251, 205, 78, 143, 105, 78, 134, 239, 197, 87, 69, 221, 84, 203, 44, 249, 190, 90, 221, 87, 171, 100, 199, 199, 105, 50, 121, 126, 196, 21, 192, 0, 77, 221, 85, 240, 161, 191,
    252, 249, 251, 31, 38, 243, 201, 73, 180, 2, 80, 10, 201, 170, 126, 171, 206, 111, 160, 40, 90, 224, 197, 240, 49, 59, 253, 1, 175, 147, 232, 91, 220, 221, 53, 91, 155, 159, 252, 115,
    221, 181, 103, 251, 79, 238, 195, 23, 247, 217, 25, 237, 211, 47, 142, 94, 57, 223, 82, 226, 63, 46, 79, 127, 163, 70, 230, 119, 0, 210, 67, 183, 90, 158, 222, 46, 237, 244, 183, 232,
    102, 246, 126, 118, 70, 246, 219, 229, 180, 199, 245, 111, 80, 253, 47, 193, 246, 115, 245, 102, 115, 119, 8, 54, 169, 23, 139, 197, 171, 12, 79, 24, 150, 158, 62, 253, 141, 64, 142, 176,
    157, 126, 146, 143, 129, 247, 255, 31, 38, 182, 200, 62, 242, 250, 197, 209, 253, 217, 227, 199, 165, 147, 225, 235, 210, 118, 161, 101, 221, 191, 25, 47, 63, 92, 118, 203, 55, 111, 47, 139,
    242, 231, 235, 85, 183, 105, 151, 167, 201, 231, 50, 231, 31, 226, 60, 112, 114, 85, 220, 214, 205, 155, 211, 100, 93, 180, 235, 148, 186, 190, 26, 218, 215, 245, 191, 128, 70, 105, 238, 94,
    159, 149, 93, 211, 173, 48, 172, 88, 242, 239, 236, 125, 118, 213, 117, 92, 37, 121, 123, 215, 173, 107, 10, 125, 154, 92, 213, 175, 171, 37, 160, 116, 213, 159, 38, 226, 236, 178, 131, 72,
    183, 188, 138, 43, 18, 152, 70, 136, 47, 206, 134, 21, 137, 211, 68, 5, 204, 217, 212, 109, 149, 238, 91, 208, 240, 200, 96, 186, 163, 135, 172, 142, 191, 61, 249, 144, 243, 239, 172, 135,
    83, 164, 69, 83, 95, 131, 108, 9, 85, 86, 171, 3, 134, 53, 230, 122, 159, 221, 22, 117, 251, 159, 245, 125, 242, 118, 89, 175, 17, 21, 32, 223, 85, 83, 189, 62, 187, 45, 86, 208,
    120, 218, 119, 119, 167, 137, 70, 204, 219, 53, 236, 24, 54, 108, 99, 207, 116, 89, 175, 170, 114, 144, 13, 244, 55, 183, 237, 89, 36, 153, 214, 125, 117, 187, 222, 19, 126, 143, 84, 121,
    155, 188, 189, 4, 242, 43, 176, 40, 239, 94, 39, 235, 174, 169, 151, 201, 234, 250, 178, 152, 162, 46, 152, 39, 143, 7, 145, 169, 217, 78, 33, 42, 8, 240, 185, 151, 223, 241, 110, 204,
    156, 101, 195, 29, 208, 6, 127, 4, 171, 188, 27, 136, 164, 171, 98, 89, 111, 192, 129, 164, 210, 62, 160, 139, 247, 217, 77, 140, 4, 127, 237, 30, 118, 140, 237, 197, 251, 53, 254, 164,
    156, 29, 88, 108, 203, 209, 214, 172, 143, 44, 174, 6, 182, 143, 153, 150, 150, 186, 191, 145, 201, 219, 113, 107, 106, 31, 187, 237, 25, 17, 209, 74, 117, 123, 183, 233, 163, 153, 126, 49,
    205, 111, 39, 189, 155, 83, 71, 234, 113, 202, 228, 16, 238, 202, 240, 111, 143, 163, 75, 205, 191, 189, 37, 236, 216, 18, 198, 28, 203, 20, 30, 13, 177, 229, 38, 242, 183, 107, 218, 242,
    19, 219, 118, 48, 248, 128, 181, 56, 237, 177, 91, 33, 225, 174, 174, 154, 238, 225, 148, 233, 125, 89, 181, 80, 200, 40, 32, 28, 201, 112, 21, 255, 9, 177, 151, 162, 50, 149, 171, 46,
    207, 202, 205, 106, 205, 251, 59, 20, 89, 52, 255, 206, 124, 135, 82, 217, 35, 242, 99, 110, 213, 30, 20, 159, 171, 165, 189, 170, 202, 99, 222, 115, 116, 254, 16, 248, 47, 187, 215, 233,
    250, 166, 88, 82, 2, 145, 96, 202, 56, 111, 242, 185, 136, 255, 114, 117, 214, 175, 16, 83, 182, 1, 162, 104, 154, 132, 235, 25, 235, 164, 42, 214, 213, 161, 168, 167, 55, 84, 197, 88,
    224, 125, 8, 216, 114, 116, 168, 153, 139, 132, 235, 161, 163, 232, 83, 92, 66, 128, 77, 95, 29, 88, 78, 29, 163, 40, 85, 192, 255, 94, 65, 142, 238, 51, 98, 48, 94, 71, 119, 22,
    25, 184, 108, 113, 85, 52, 103, 113, 37, 25, 189, 179, 173, 52, 236, 112, 154, 172, 58, 22, 36, 83, 25, 196, 178, 186, 158, 125, 80, 24, 112, 248, 246, 163, 35, 6, 98, 13, 90, 254,
    62, 165, 123, 28, 79, 81, 32, 242, 220, 87, 201, 120, 130, 200, 200, 84, 100, 185, 61, 234, 204, 26, 33, 121, 59, 54, 174, 63, 22, 124, 27, 19, 143, 234, 191, 95, 134, 239, 168, 182,
    49, 110, 244, 47, 34, 117, 108, 217, 170, 48, 32, 66, 28, 96, 180, 44, 181, 49, 246, 67, 65, 105, 103, 206, 1, 197, 191, 240, 132, 120, 255, 176, 37, 209, 240, 132, 49, 251, 200, 93,
    183, 145, 133, 75, 20, 122, 63, 159, 221, 215, 235, 250, 178, 110, 234, 254, 205, 222, 109, 186, 187, 162, 140, 247, 226, 192, 160, 219, 102, 58, 248, 237, 128, 186, 180, 110, 231, 201, 227, 4,
    201, 168, 125, 232, 117, 140, 124, 255, 33, 189, 101, 172, 232, 146, 183, 99, 70, 226, 117, 83, 61, 114, 34, 71, 156, 164, 203, 42, 138, 193, 249, 223, 127, 182, 77, 215, 67, 134, 62, 63,
    25, 246, 68, 156, 51, 69, 111, 147, 247, 18, 225, 48, 214, 229, 139, 201, 54, 137, 77, 70, 171, 72, 255, 145, 166, 9, 10, 200, 46, 73, 211, 241, 218, 210, 126, 123, 192, 228, 227, 219,
    3, 38, 9, 112, 185, 6, 67, 139, 137, 204, 228, 100, 187, 89, 96, 130, 119, 252, 187, 215, 147, 221, 118, 129, 137, 203, 121, 199, 253, 22, 95, 117, 175, 23, 19, 1, 207, 86, 94, 230,
    240, 111, 167, 197, 228, 112, 145, 234, 124, 187, 254, 63, 249, 206, 97, 150, 196, 123, 93, 200, 220, 36, 252, 97, 156, 72, 209, 166, 149, 40, 157, 74, 172, 79, 156, 224, 209, 91, 27, 79,
    130, 19, 123, 225, 112, 12, 90, 224, 97, 97, 73, 35, 103, 179, 144, 9, 38, 17, 86, 151, 169, 212, 54, 137, 171, 125, 232, 226, 83, 174, 224, 227, 148, 11, 204, 159, 6, 193, 213, 72,
    141, 179, 74, 66, 112, 247, 94, 139, 70, 105, 132, 186, 3, 30, 200, 64, 98, 68, 105, 125, 234, 116, 194, 35, 233, 167, 94, 228, 63, 42, 140, 184, 177, 66, 151, 94, 104, 178, 193, 53,
    204, 0, 186, 154, 75, 159, 162, 200, 193, 75, 62, 240, 35, 82, 201, 149, 65, 175, 201, 145, 55, 41, 254, 147, 70, 167, 94, 166, 185, 18, 169, 183, 13, 230, 19, 169, 78, 13, 183, 20,
    220, 122, 5, 110, 165, 40, 83, 200, 37, 93, 106, 101, 162, 65, 150, 156, 55, 41, 119, 28, 24, 74, 7, 163, 148, 26, 142, 105, 48, 14, 119, 104, 247, 10, 190, 160, 36, 56, 7, 159,
    82, 39, 185, 242, 73, 48, 33, 201, 49, 13, 178, 23, 36, 150, 50, 164, 92, 191, 118, 154, 95, 113, 83, 37, 76, 225, 208, 129, 63, 42, 45, 53, 208, 134, 145, 121, 137, 39, 169, 205,
    17, 237, 210, 96, 82, 101, 193, 103, 222, 128, 59, 103, 253, 141, 210, 80, 79, 8, 96, 140, 135, 168, 32, 197, 233, 68, 41, 149, 79, 77, 78, 22, 82, 20, 3, 104, 77, 181, 20, 36,
    135, 9, 192, 36, 142, 40, 89, 240, 163, 12, 58, 213, 247, 169, 54, 170, 20, 252, 0, 140, 169, 117, 46, 82, 199, 149, 96, 147, 114, 1, 92, 68, 45, 57, 142, 194, 79, 220, 74, 131,
    231, 154, 124, 65, 47, 41, 216, 213, 124, 154, 88, 21, 21, 162, 53, 85, 32, 189, 45, 83, 40, 70, 195, 220, 14, 39, 141, 54, 174, 141, 91, 116, 164, 66, 141, 231, 238, 18, 96, 134,
    106, 193, 153, 128, 163, 74, 20, 185, 147, 206, 240, 139, 206, 160, 18, 45, 19, 254, 6, 149, 104, 208, 179, 142, 102, 35, 63, 92, 199, 230, 47, 167, 193, 238, 129, 8, 219, 40, 3, 134,
    75, 45, 44, 168, 106, 116, 193, 72, 158, 96, 112, 78, 111, 85, 74, 245, 4, 5, 65, 129, 128, 160, 191, 145, 86, 123, 65, 117, 106, 103, 74, 218, 92, 146, 15, 157, 59, 42, 219, 64,
    53, 24, 162, 57, 30, 39, 9, 27, 64, 143, 183, 169, 166, 20, 62, 242, 97, 40, 15, 116, 13, 72, 19, 45, 218, 36, 64, 36, 234, 63, 192, 50, 192, 150, 144, 152, 107, 254, 134, 216,
    145, 2, 80, 3, 227, 113, 21, 155, 123, 24, 108, 202, 237, 35, 218, 1, 208, 69, 240, 50, 225, 47, 138, 9, 5, 195, 74, 10, 250, 4, 66, 212, 55, 0, 138, 161, 69, 165, 77, 56,
    13, 225, 8, 205, 74, 77, 76, 192, 227, 82, 15, 29, 123, 105, 225, 93, 222, 197, 21, 149, 84, 42, 27, 110, 193, 52, 92, 79, 3, 185, 134, 8, 1, 251, 116, 77, 171, 116, 154, 107,
    69, 199, 224, 120, 156, 33, 18, 49, 139, 91, 78, 171, 137, 79, 116, 135, 77, 20, 127, 202, 2, 239, 18, 5, 44, 18, 17, 180, 150, 80, 217, 241, 232, 232, 243, 160, 171, 18, 80, 119,
    156, 80, 164, 185, 147, 5, 55, 151, 240, 23, 29, 223, 49, 108, 4, 11, 230, 117, 164, 18, 216, 39, 158, 84, 28, 30, 193, 143, 103, 74, 81, 82, 67, 167, 188, 117, 54, 2, 171, 80,
    220, 55, 132, 223, 224, 177, 202, 81, 131, 144, 5, 122, 2, 44, 25, 99, 224, 123, 212, 135, 207, 27, 67, 246, 196, 96, 39, 228, 52, 116, 163, 102, 172, 240, 56, 163, 167, 1, 22, 192,
    139, 177, 116, 77, 234, 208, 68, 110, 232, 173, 38, 247, 5, 100, 86, 52, 20, 143, 145, 107, 238, 157, 128, 26, 75, 198, 5, 220, 4, 244, 10, 136, 68, 116, 44, 238, 216, 177, 1, 222,
    65, 234, 220, 26, 227, 248, 68, 240, 131, 54, 55, 60, 113, 17, 44, 10, 163, 2, 72, 0, 139, 146, 207, 66, 124, 98, 193, 5, 28, 80, 163, 99, 160, 225, 41, 9, 56, 212, 0, 76,
    32, 82, 161, 214, 160, 57, 130, 97, 33, 164, 94, 43, 194, 150, 1, 137, 211, 198, 248, 155, 114, 203, 14, 29, 132, 248, 129, 13, 130, 187, 133, 122, 233, 62, 142, 1, 10, 232, 67, 16,
    115, 185, 5, 111, 42, 158, 189, 164, 33, 96, 66, 168, 47, 7, 25, 155, 228, 55, 56, 34, 194, 165, 140, 126, 1, 65, 2, 161, 197, 130, 105, 31, 40, 13, 56, 119, 185, 152, 12, 59,
    33, 38, 159, 171, 242, 210, 20, 102, 184, 77, 87, 155, 166, 90, 76, 42, 188, 46, 119, 203, 229, 228, 228, 99, 185, 67, 17, 65, 54, 207, 11, 105, 193, 5, 148, 61, 156, 34, 176, 227,
    86, 12, 90, 67, 5, 110, 175, 138, 199, 193, 177, 115, 143, 119, 40, 68, 84, 24, 15, 152, 19, 244, 112, 196, 107, 134, 110, 110, 126, 9, 41, 119, 189, 88, 219, 88, 107, 98, 10, 128,
    241, 97, 64, 186, 16, 208, 83, 162, 47, 121, 167, 148, 41, 51, 5, 156, 24, 145, 72, 21, 210, 193, 117, 0, 214, 225, 20, 195, 35, 38, 72, 153, 196, 36, 210, 2, 166, 246, 30, 198,
    5, 46, 60, 189, 29, 161, 93, 18, 142, 176, 46, 204, 20, 160, 10, 152, 193, 8, 81, 120, 197, 64, 181, 203, 29, 232, 230, 237, 45, 96, 199, 61, 66, 210, 191, 224, 23, 113, 159, 228,
    130, 81, 56, 178, 239, 232, 237, 57, 106, 39, 152, 69, 251, 50, 32, 21, 228, 220, 58, 166, 49, 192, 34, 97, 42, 15, 252, 59, 226, 87, 192, 196, 10, 7, 27, 28, 227, 48, 161, 2,
    164, 40, 229, 228, 173, 204, 115, 166, 182, 130, 249, 131, 191, 72, 155, 16, 18, 166, 4, 230, 192, 119, 158, 120, 6, 90, 160, 203, 235, 27, 120, 159, 107, 16, 175, 149, 46, 232, 89, 209,
    187, 56, 2, 97, 203, 122, 64, 195, 51, 139, 56, 134, 84, 126, 165, 71, 82, 16, 55, 92, 45, 51, 77, 204, 114, 250, 86, 115, 27, 76, 94, 32, 194, 179, 116, 218, 74, 202, 128, 45,
    184, 189, 206, 40, 134, 185, 225, 180, 117, 71, 197, 248, 16, 136, 108, 27, 127, 81, 187, 146, 254, 50, 148, 8, 12, 49, 22, 51, 197, 172, 201, 173, 89, 116, 223, 20, 230, 35, 126, 225,
    96, 9, 33, 143, 136, 136, 80, 143, 80, 108, 8, 115, 64, 207, 243, 68, 255, 71, 87, 120, 16, 52, 195, 56, 13, 191, 133, 213, 114, 228, 78, 192, 158, 81, 41, 231, 28, 10, 142, 132,
    144, 12, 238, 145, 97, 109, 142, 44, 203, 45, 130, 48, 166, 131, 103, 113, 105, 18, 234, 147, 36, 135, 22, 110, 185, 66, 52, 103, 62, 100, 128, 102, 46, 164, 164, 57, 21, 1, 210, 49,
    153, 40, 38, 72, 1, 150, 48, 9, 236, 47, 172, 76, 89, 90, 64, 167, 134, 59, 175, 240, 16, 103, 7, 143, 67, 122, 231, 224, 16, 128, 82, 197, 26, 136, 94, 158, 16, 47, 96, 92,
    219, 192, 218, 71, 70, 39, 136, 167, 173, 46, 99, 131, 125, 1, 205, 65, 105, 8, 205, 224, 149, 74, 21, 249, 238, 202, 74, 127, 175, 157, 106, 192, 56, 149, 135, 254, 222, 149, 18, 194,
    123, 6, 55, 32, 204, 68, 79, 208, 210, 55, 180, 170, 165, 123, 88, 166, 120, 4, 118, 85, 112, 165, 138, 136, 210, 91, 19, 193, 207, 144, 227, 209, 203, 43, 231, 99, 162, 141, 167, 193,
    76, 112, 14, 166, 162, 18, 169, 8, 22, 193, 60, 38, 164, 65, 18, 218, 204, 104, 40, 204, 134, 82, 140, 19, 32, 36, 2, 235, 76, 217, 12, 49, 50, 110, 94, 67, 248, 148, 12, 137,
    232, 139, 178, 201, 194, 17, 21, 80, 228, 209, 18, 144, 205, 20, 186, 35, 112, 251, 120, 145, 178, 222, 129, 134, 161, 105, 23, 235, 44, 201, 20, 21, 55, 160, 73, 243, 157, 142, 129, 91,
    27, 56, 62, 178, 4, 191, 162, 20, 40, 12, 4, 44, 180, 61, 13, 186, 131, 151, 193, 168, 200, 207, 200, 214, 9, 153, 227, 9, 172, 194, 181, 109, 104, 84, 224, 30, 56, 87, 210, 208,
    74, 179, 0, 1, 8, 225, 21, 86, 18, 144, 240, 113, 184, 54, 44, 143, 240, 205, 142, 180, 150, 16, 95, 66, 62, 200, 146, 108, 79, 49, 234, 235, 128, 200, 164, 4, 146, 140, 133, 127,
    34, 27, 192, 94, 142, 43, 56, 172, 149, 225, 65, 22, 217, 152, 213, 42, 81, 129, 140, 28, 33, 97, 98, 45, 5, 152, 210, 213, 16, 65, 45, 35, 79, 220, 195, 22, 171, 54, 68, 217,
    84, 57, 146, 9, 183, 92, 158, 226, 252, 33, 22, 78, 236, 202, 170, 12, 117, 9, 195, 186, 166, 59, 176, 194, 74, 185, 171, 21, 248, 106, 232, 218, 154, 2, 65, 158, 146, 72, 39, 108,
    152, 121, 137, 49, 110, 241, 3, 10, 88, 162, 254, 168, 130, 114, 37, 225, 139, 145, 180, 27, 29, 42, 38, 85, 212, 46, 33, 22, 111, 12, 234, 38, 2, 93, 135, 239, 12, 163, 150, 55,
    8, 254, 160, 137, 10, 205, 50, 214, 69, 61, 68, 146, 12, 216, 172, 22, 80, 121, 161, 160, 230, 174, 197, 120, 28, 106, 111, 66, 199, 171, 18, 113, 41, 97, 184, 37, 104, 233, 155, 10,
    69, 40, 124, 220, 70, 117, 75, 187, 173, 249, 1, 89, 96, 6, 32, 139, 206, 1, 198, 17, 173, 136, 25, 196, 50, 220, 41, 238, 36, 197, 228, 112, 38, 86, 249, 56, 129, 83, 64, 131,
    158, 130, 100, 68, 247, 102, 15, 87, 40, 231, 184, 121, 55, 30, 135, 84, 129, 160, 172, 60, 176, 8, 72, 161, 180, 10, 49, 100, 96, 70, 29, 104, 71, 96, 14, 71, 214, 111, 80, 28,
    29, 36, 177, 131, 113, 252, 206, 56, 172, 236, 65, 129, 235, 171, 56, 26, 229, 239, 81, 83, 0, 128, 97, 171, 44, 120, 134, 40, 135, 56, 201, 164, 66, 37, 74, 238, 102, 20, 172, 157,
    9, 94, 148, 77, 78, 69, 95, 137, 155, 38, 25, 60, 81, 159, 1, 44, 44, 227, 147, 220, 193, 21, 21, 10, 171, 225, 56, 132, 109, 110, 156, 142, 225, 81, 241, 229, 100, 123, 138, 143,
    184, 9, 17, 41, 6, 65, 137, 213, 18, 15, 195, 171, 150, 230, 46, 100, 91, 198, 218, 129, 219, 116, 161, 48, 110, 252, 165, 167, 1, 20, 12, 15, 72, 46, 73, 212, 42, 204, 93, 88,
    46, 168, 39, 195, 113, 40, 188, 180, 136, 149, 5, 212, 42, 25, 225, 135, 211, 214, 48, 44, 239, 85, 40, 21, 75, 70, 84, 73, 124, 179, 97, 209, 129, 222, 38, 22, 245, 42, 166, 160,
    148, 59, 67, 21, 75, 113, 92, 34, 14, 38, 204, 79, 140, 3, 249, 190, 62, 168, 150, 252, 251, 181, 250, 224, 156, 175, 171, 23, 159, 253, 226, 173, 151, 203, 38, 252, 64, 115, 240, 238,
    27, 91, 134, 77, 253, 241, 171, 200, 31, 112, 127, 252, 158, 122, 35, 47, 190, 220, 244, 55, 85, 219, 111, 95, 227, 241, 226, 45, 143, 250, 140, 222, 187, 247, 31, 80, 39, 23, 231, 39,
    104, 255, 120, 207, 221, 7, 204, 35, 130, 177, 219, 240, 37, 178, 70, 137, 179, 93, 194, 216, 114, 185, 187, 139, 139, 85, 55, 93, 3, 82, 139, 201, 223, 208, 200, 199, 159, 158, 136, 107,
    16, 219, 89, 226, 229, 120, 138, 191, 108, 87, 96, 182, 59, 76, 119, 183, 199, 170, 248, 128, 60, 151, 195, 87, 53, 18, 24, 47, 72, 140, 149, 186, 107, 26, 230, 190, 220, 222, 109, 149,
    48, 238, 241, 1, 246, 127, 227, 199, 137, 237, 231, 8, 233, 30, 191, 69, 240, 250, 240, 75, 4, 95, 153, 118, 96, 106, 187, 182, 154, 36, 235, 126, 213, 253, 12, 158, 30, 110, 234, 126,
    127, 155, 110, 39, 83, 251, 6, 126, 65, 42, 139, 187, 197, 36, 126, 171, 58, 104, 230, 242, 244, 174, 253, 151, 236, 31, 212, 170, 183, 120, 121, 225, 251, 76, 138, 36, 158, 250, 131, 253,
    189, 31, 236, 255, 157, 68, 2, 81, 223, 216, 15, 246, 220, 162, 252, 151, 250, 186, 43, 218, 15, 168, 150, 223, 249, 38, 195, 255, 108, 130, 145, 232, 115, 108, 216, 193, 42, 99, 47, 162,
    107, 60, 222, 31, 186, 211, 159, 70, 31, 181, 18, 126, 13, 60, 112, 42, 66, 156, 120, 56, 94, 50, 222, 241, 117, 220, 126, 196, 75, 20, 225, 120, 252, 110, 165, 254, 226, 152, 253, 17,
    38, 71, 151, 159, 237, 89, 253, 195, 176, 218, 180, 99, 112, 236, 127, 195, 66, 212, 248, 3, 217, 221, 197, 254, 255, 195, 73, 210, 228, 199, 225, 139, 23, 191, 60, 159, 159, 220, 29, 208,
    128, 194, 226, 71, 55, 132, 130, 248, 255, 44, 253, 15, 90, 172, 235, 235, 196, 52, 0, 0
};
