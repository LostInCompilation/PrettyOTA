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

/*

====================================================================================
Example Json file:

{
  "Configuration": [
    {
      "HardwareID": ["Board1", "Board2", "Board3"],
      "CustomFilter": "custom1",
      "Version": "2.0.0",
      "FirmwareURL": "https://mydomain.com/firmware/board1_2_3.fw_v2_0_0.bin"
    },
    {
      "HardwareID": "Board10",
      "Version": "3.0.0",
      "FirmwareURL": "https://mydomain.com/firmware/board10.fw_v3_0_0.bin"
    },
    {
      "HardwareID": "Board99",
      "CustomFilter": "custom99",
      "Version": "10.0.0",
      "FirmwareURL": "https://mydomain.com/firmware/board99.fw_v10_0_0.bin"
    },
    {
      "HardwareID": "Invalid",
      "Version": "10.0.0",
      "FirmwareURL": ""
    }
  ]
}

====================================================================================

*/

#include "FirmwarePullManager.h"

using namespace NSPrettyOTA;

void FirmwarePullManager::Begin(Stream* const serialStream)
{
    m_SerialMonitorStream = serialStream;
}

void FirmwarePullManager::Log(const std::string& message)
{
    if(!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println(message.c_str());
}

PULL_RESULT FirmwarePullManager::CheckForNewFirmwareAvailable(const char* const jsonURL, std::string& out_firmwareURL)
{
    out_firmwareURL = "";

    this->Log("[FirmwarePullManager] Info: Checking for new firmware version...");

    HTTPClient http;
    http.useHTTP10(true);
    http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
    if(!http.begin(jsonURL))
    {
        this->Log("[FirmwarePullManager] Error: Could not initialize HTTPClient");
        return PULL_RESULT::ERROR;
    }

    // Send HTTP GET request
    const int32_t response = http.GET();
    if(response != 200)
    {
        http.end();
        this->Log("[FirmwarePullManager] Error: Server replied with HTTP code: " + std::to_string(response));
        return PULL_RESULT::ERROR;
    }

    // Get received data as stream
    Stream* const stream = http.getStreamPtr();
    if(!stream)
    {
        http.end();
        this->Log("[FirmwarePullManager] Error: Received Json is empty");
        return PULL_RESULT::ERROR;
    }

    // Parse received Json
    JsonDocument json;
    const DeserializationError jsonError = deserializeJson(json, *stream);
    if(jsonError)
    {
        http.end();
        this->Log("[FirmwarePullManager] Error: Could not parse Json (" + std::string(jsonError.c_str()) + ")");
        return PULL_RESULT::ERROR;
    }

    // End connection
    http.end();

    // Are there any "Configuration" entries
    if(json["Configuration"].as<JsonArray>().size() == 0)
    {
        this->Log("[FirmwarePullManager] Error (Json): No valid \"Configuration\" entries found");
        return PULL_RESULT::ERROR;
    }

    // Search if Json contains matching profile
    // Iterate all "Configuration" entries
    for (const auto configuration : json["Configuration"].as<JsonArray>())
    {
        // **********************************************************
        // Search matching HardwareID
        bool foundHardwareIDMatch = false;
        if(configuration["HardwareID"].is<JsonArray>()) // HardwareID is array
        {
            for (auto i : configuration["HardwareID"].as<JsonArray>())
            {
                if(i.as<std::string>() == m_HardwareID)
                {
                    foundHardwareIDMatch = true;
                    break;
                }
            }
        }
        else if(configuration["HardwareID"].is<std::string>()) // HardwareID is single string (only one HardwareID)
        {
            if(configuration["HardwareID"].as<std::string>() == m_HardwareID)
                foundHardwareIDMatch = true;
        }
        else // HardwareID entry not found
        {
            this->Log("[FirmwarePullManager] Error (Json): No valid \"HardwareID\" found in \"Configuration\". Skipping entry...");
            continue;
        }

        // Go to next "Configuration" if no HardwareID matched
        if(!foundHardwareIDMatch)
            continue;

        // **********************************************************
        // Search matching CustomFilter
        bool foundCustomFilterMatch = false;
        if(configuration["CustomFilter"].is<std::string>())
        {
            if(configuration["CustomFilter"].as<std::string>() == m_CustomFilter)
                foundCustomFilterMatch = true;
        }
        else
        {
            // If no CustomFilter entry is present, set as match
            foundCustomFilterMatch = true;
        }

        // Go to next "Configuration" if no CustomFilter matched
        if(!foundCustomFilterMatch)
            continue;

        // **********************************************************
        // Check if version is present
        if(!configuration["Version"].is<std::string>() || configuration["Version"].as<std::string>().length() == 0)
        {
            this->Log("[FirmwarePullManager] Error (Json): No valid \"Version\" found in \"Configuration\". Skipping entry...");
            continue;
        }

        // Check if version is newer (or different if downgrade is allowed)
        bool newVersionAvailable = false;
        if(m_AllowDowngrade)
        {
            if(configuration["Version"].as<std::string>() != m_CurrentAppVersion)
                newVersionAvailable = true;
        }
        else
        {
            // Use lexicographical comparison
            if(configuration["Version"].as<std::string>() > m_CurrentAppVersion)
                newVersionAvailable = true;
        }

        if(!newVersionAvailable)
        {
            this->Log("[FirmwarePullManager] Info: No updated firmware version available (Current: " + std::string(m_CurrentAppVersion) + ", New: " + configuration["Version"].as<std::string>() + ")");
            return PULL_RESULT::NO_UPDATE_AVAILABLE;
        }

        this->Log("[FirmwarePullManager] Info: New firmware version available (Current: " + std::string(m_CurrentAppVersion) + ", New: " + configuration["Version"].as<std::string>() + ")");

        // **********************************************************
        // Get firmware URL
        if(!configuration["FirmwareURL"].is<std::string>() || configuration["FirmwareURL"].as<std::string>().length() == 0)
        {
            this->Log("[FirmwarePullManager] Error (Json): No valid \"FirmwareURL\" found in \"Configuration\"");
            continue;
        }

        out_firmwareURL = configuration["FirmwareURL"].as<std::string>();

        return PULL_RESULT::OK;
    }

    this->Log("[FirmwarePullManager] Warning: No matching profile found in Json");

    return PULL_RESULT::NO_CONFIGURATION_PROFILE_MATCH_FOUND;
}

PULL_RESULT FirmwarePullManager::RunPullUpdate(const char* const jsonURL)
{
    std::string firmwareURL = "";

    const PULL_RESULT result = CheckForNewFirmwareAvailable(jsonURL, firmwareURL);
    if(result != PULL_RESULT::OK)
        return result;

    // Download firmware file
    HTTPClient http;
    http.useHTTP10(true);
    http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
    if(!http.begin(firmwareURL.c_str()))
    {
        this->Log("[FirmwarePullManager] Error: Could not initialize HTTPClient");
        return PULL_RESULT::ERROR;
    }

    // Send HTTP GET request
    const int32_t response = http.GET();
    if(response != 200)
    {
        http.end();
        this->Log("[FirmwarePullManager] Error: Server replied with HTTP code: " + std::to_string(response));
        return PULL_RESULT::ERROR;
    }




    // End connection
    http.end();

    return PULL_RESULT::OK;
}
