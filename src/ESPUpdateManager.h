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
#include <functional>
#include <string>   // For std::string
#include <string.h> // For memcpy, memset

// ESP-IDF
#include <esp_err.h>
#include <esp_spi_flash.h>
#include <esp_partition.h>
#include <esp_ota_ops.h>
#include <esp_app_format.h>

// PrettyOTA
#include "CustomTypes.h"
#include "MD5Hasher.h"

namespace NSPrettyOTA
{
    class ESPUpdateManager
    {
    private:
        // Constants
        static const uint8_t  UM_ENCRYPTED_BLOCK_SIZE  = 16;
        static const uint8_t  UM_SPI_SECTORS_PER_BLOCK = 16;
        static const uint32_t UM_SPI_FLASH_BLOCK_SIZE  = (UM_SPI_SECTORS_PER_BLOCK * SPI_FLASH_SEC_SIZE);

    private:
        UPDATE_ERROR                m_LastError = UPDATE_ERROR::OK;
        UPDATE_MODE                 m_UpdateMode = UPDATE_MODE::FIRMWARE;

        uint64_t                    m_UpdateSize = 0;
        uint64_t                    m_UpdateProgress = 0;
        uint64_t                    m_BufferSize = 0;

        uint8_t*                    m_Buffer = nullptr;
        uint8_t*                    m_SkipBuffer = nullptr;

        std::string                 m_ExpectedMD5Hash = "";
        MD5Hasher                   m_MD5Hasher;

        const esp_partition_t*      m_TargetPartition = nullptr;

        // Methods
        void ResetState();
        void Abort(UPDATE_ERROR reason);
        bool WriteBufferToFlash();

        // Helper
        bool IsPartitionBootable(const esp_partition_t* const partition) const;
        bool CheckDataAlignment(const uint8_t* data, uint64_t size) const;

    public:
        ESPUpdateManager() = default;

        bool Begin(UPDATE_MODE updateMode, const char* const expectedMD5Hash, const char* const SPIFFSPartitionLabel = nullptr);
        bool End();
        void Abort();

        uint64_t Write(const uint8_t* const data, uint64_t size);

        bool HasError() const { return (m_LastError != UPDATE_ERROR::OK); }
        UPDATE_ERROR GetLastError() const { return m_LastError; }
        std::string GetLastErrorAsString() const;

        bool IsRollbackPossible() const;
        bool DoRollback();
    };
}
