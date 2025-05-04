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
