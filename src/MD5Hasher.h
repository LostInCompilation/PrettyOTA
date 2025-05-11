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
    Helper class for building MD5 hashes.

*/

#pragma once

#include <string>   // For std::string
#include <string.h> // For memcpy, memset

#include <esp_system.h>
#include <esp_rom_md5.h>

namespace NSPrettyOTA
{
    /**
     * @brief Utility class for generating MD5 hash values
     *
     * This class provides a simple interface for calculating MD5 hashes
     * of data streams. It wraps the ESP-ROM MD5 implementation.
     */
    class MD5Hasher
    {
    private:
        md5_context_t m_Context;                                  // MD5 calculation context
        uint8_t       m_Buffer[ESP_ROM_MD5_DIGEST_LEN] = {0};     // Buffer to store the calculated hash

    public:
        /** Size of MD5 hash string including null terminator (33 bytes) */
        static const uint8_t MD5_HASH_STR_SIZE = (2 * ESP_ROM_MD5_DIGEST_LEN + 1);

        MD5Hasher() = default;

        /**
         * @brief Initialize the MD5 hasher
         *
         * Must be called before adding any data to calculate a new hash.
         */
        void Begin();

        /**
         * @brief Add binary data to the hash calculation
         *
         * @param data Pointer to the data buffer
         * @param size Size of the data in bytes
         */
        void AddData(const uint8_t* data, uint32_t size);

        /**
         * @brief Add character data to the hash calculation
         *
         * @param data Pointer to the character data
         * @param size Size of the data in bytes
         */
        void AddData(const char* data, uint32_t size);

        /**
         * @brief Finalize the hash calculation
         *
         * Call this after all data has been added to generate the final hash.
         */
        void Calculate();

        /**
         * @brief Get the calculated hash as a byte array
         *
         * @param out Buffer to store the hash (must be at least ESP_ROM_MD5_DIGEST_LEN bytes)
         */
        void GetHashAsBytes(uint8_t out[ESP_ROM_MD5_DIGEST_LEN]) const;

        /**
         * @brief Get the calculated hash as a hexadecimal string
         *
         * @return std::string Hash value as a 32-character hex string
         */
        std::string GetHashAsString() const;
    };
}
