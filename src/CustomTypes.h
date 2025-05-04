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
    Custom type declarations.

*/

#pragma once

#include <cstdint>

namespace NSPrettyOTA
{
    enum class UPDATE_MODE : uint8_t
    {
        FIRMWARE = 0,
        FILESYSTEM
    };

    // Return type for ESPUpdateManager
    enum class UPDATE_ERROR : uint8_t
    {
        OK = 0,
        ABORT,
        ERROR_OUT_OF_MEMORY,
        ERROR_NO_PARTITION,
        ERROR_NO_SPACE,
        ERROR_INVALID_HASH,
        ERROR_HASH_MISMATCH,
        ERROR_READ,
        ERROR_WRITE,
        ERROR_ERASE,
        ERROR_ACTIVATE,
        ERROR_MAGIC_BYTE
    };

    // Return type for FirmwarePullManager
    enum class PULL_RESULT : uint8_t
    {
        OK = 0,
        NO_UPDATE_AVAILABLE = 1,
        NO_CONFIGURATION_PROFILE_MATCH_FOUND = 2,
        ERROR = 3
    };
}
