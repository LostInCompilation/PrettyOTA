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
    Common type definitions used throughout the PrettyOTA library.

*/

#pragma once

#include <cstdint>

namespace NSPrettyOTA
{
    /**
     * @enum UPDATE_MODE
     * @brief Defines the type of update operation
     *
     * Determines whether the update targets the firmware (application code)
     * or the filesystem (SPIFFS/LittleFS data partition).
     */
    enum class UPDATE_MODE : uint8_t
    {
        FIRMWARE = 0,   ///< Update the firmware/application code
        FILESYSTEM      ///< Update the filesystem (SPIFFS or LittleFS)
    };

    /**
     * @enum UPDATE_ERROR
     * @brief Error codes for the ESPUpdateManager
     *
     * Detailed error codes that can occur during the update process,
     * allowing for specific error handling and user feedback.
     */
    enum class UPDATE_ERROR : uint8_t
    {
        OK = 0,                 ///< No error, operation successful
        ABORT,                  ///< Update was manually aborted
        ERROR_OUT_OF_MEMORY,    ///< Failed to allocate required memory
        ERROR_NO_PARTITION,     ///< Target partition not found
        ERROR_NO_SPACE,         ///< Not enough space in target partition
        ERROR_INVALID_HASH,     ///< MD5 hash format is invalid
        ERROR_HASH_MISMATCH,    ///< Calculated MD5 hash doesn't match expected hash
        ERROR_READ,             ///< Error reading from flash
        ERROR_WRITE,            ///< Error writing to flash
        ERROR_ERASE,            ///< Error erasing flash
        ERROR_ACTIVATE,         ///< Error setting new boot partition
        ERROR_MAGIC_BYTE        ///< Invalid firmware header magic byte
    };

    /**
     * @enum PULL_RESULT
     * @brief Result codes for firmware pull operations
     *
     * Status codes returned by the firmware pull mechanism when
     * checking for and downloading updates from a remote server.
     */
    enum class PULL_RESULT : uint8_t
    {
        OK = 0,                             ///< Pull operation successful
        NO_UPDATE_AVAILABLE = 1,            ///< No newer firmware available
        NO_CONFIGURATION_PROFILE_MATCH_FOUND = 2, ///< Device configuration doesn't match available updates
        ERROR = 3                           ///< General error during pull operation
    };
}
