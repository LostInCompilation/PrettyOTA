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
    Internal handler for writing updates to ESP flash.

*/

#pragma once

// C++ API
#include <cstdint>
//#include <functional>
#include <string>   // For std::string

// Arduino dependencies
#include <HTTPClient.h>
#include <ArduinoJson.h>

// PrettyOTA
#include "CustomTypes.h"

namespace NSPrettyOTA
{
    class FirmwarePullManager
    {
    private:
        Stream*         m_SerialMonitorStream = nullptr;

        bool            m_AllowDowngrade = false;
        std::string     m_HardwareID = "";
        std::string     m_CustomFilter = "";
        std::string     m_CurrentAppVersion = "";

        // User callbacks
        std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> m_OnStartUpdate = nullptr;
        std::function<void(uint32_t currentSize, uint32_t totalSize)> m_OnProgressUpdate = nullptr;
        std::function<void(bool successful)> m_OnEndUpdate = nullptr;

        void Log(const std::string& message);

    public:
        FirmwarePullManager() = default;
        void Begin(Stream* const serialStream,
            std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> onStart,
            std::function<void(uint32_t currentSize, uint32_t totalSize)> onProgress,
            std::function<void(bool successful)> onEnd);

        PULL_RESULT CheckForNewFirmwareAvailable(const char* const jsonURL, std::string& out_firmwareURL);
        PULL_RESULT RunPullUpdate(const char* const jsonURL);

        void SetHardwareID(const char* const hardwareID) { m_HardwareID = hardwareID; }
        void SetCustomFilter(const char* const customFilter) { m_CustomFilter = customFilter; }
        void SetCurrentAppVersion(const char* const currentAppVersion) { m_CurrentAppVersion = currentAppVersion; }

        void SetAllowDowngrade(bool allowDowngrade) { m_AllowDowngrade = allowDowngrade; }
    };
}
