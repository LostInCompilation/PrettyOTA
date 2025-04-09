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
    Utils and helpers for PrettyOTA.

*/

#include "PrettyOTA.h"

// ********************************************************
// Log functions
void PrettyOTA::P_LOG_I(const std::string& message)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println(("[PrettyOTA] Info: " + message).c_str());
}

void PrettyOTA::P_LOG_W(const std::string& message)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println(("[PrettyOTA] Warning: " + message).c_str());
}

void PrettyOTA::P_LOG_E(const std::string& message)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println(("[PrettyOTA] Error: " + message).c_str());
}

// ********************************************************
// Get PrettyOTA version string
std::string PrettyOTA::GetVersionAsString() const
{
    return std::to_string(PRETTY_OTA_VERSION_MAJOR) + "." +
        std::to_string(PRETTY_OTA_VERSION_MINOR) + "." +
        std::to_string(PRETTY_OTA_VERSION_REVISION);
}

// ********************************************************
// UUID helpers
void PrettyOTA::GenerateUUID(UUID_t* out_uuid) const
{
    esp_fill_random(*out_uuid, sizeof(UUID_t));

    (*out_uuid)[6] = 0x40 | ((*out_uuid)[6] & 0xF);   // UUID version
    (*out_uuid)[8] = (0x80 | (*out_uuid)[8]) & ~0x40; // UUID variant
}

std::string PrettyOTA::UUIDToString(const UUID_t uuid) const
{
    char out[37] = {};

    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);

    return out;
}

// ********************************************************
// SHA256 helpers
/*std::string PrettyOTA::SHA256ToString(const uint8_t hash[32]) const
{
    static const char* const SHA256StringLookup = "0123456789abcdef";

    std::string result = "";
    for(uint32_t i = 0; i < 32; i++)
    {
        result += SHA256StringLookup[hash[i] >> 4];
        result += SHA256StringLookup[hash[i] & 0x0F];
    }
    return result;
}*/
