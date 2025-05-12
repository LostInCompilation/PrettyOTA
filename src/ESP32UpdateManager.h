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
    Low-level handler for writing firmware and filesystem updates
    to ESP32 flash memory with safety mechanisms.

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
    /**
     * @class ESP32UpdateManager
     * @brief Manages the low-level process of writing updates to ESP32 flash memory
     *
     * This class handles the safe writing of firmware and filesystem updates to flash,
     * including partition selection, error handling, MD5 verification, and rollback support.
     * It implements safety mechanisms to prevent bricking the device during updates.
     */
    class ESP32UpdateManager
    {
    private:
        // Flash memory constants
        static const uint8_t  UM_ENCRYPTED_BLOCK_SIZE  = 16;    // Size of encrypted blocks in flash
        static const uint8_t  UM_SPI_SECTORS_PER_BLOCK = 16;    // Number of sectors per flash block
        static const uint32_t UM_SPI_FLASH_BLOCK_SIZE  = (UM_SPI_SECTORS_PER_BLOCK * SPI_FLASH_SEC_SIZE);

    private:
        // State tracking
        UPDATE_ERROR                m_LastError = UPDATE_ERROR::OK;      // Last error that occurred
        UPDATE_MODE                 m_UpdateMode = UPDATE_MODE::FIRMWARE; // Current update type

        // Update progress tracking
        uint64_t                    m_UpdateSize = 0;      // Total size of the update
        uint64_t                    m_UpdateProgress = 0;  // Bytes written so far
        uint64_t                    m_BufferSize = 0;      // Current buffer fill level

        // Flash write buffers
        uint8_t*                    m_Buffer = nullptr;    // Main data buffer
        uint8_t*                    m_SkipBuffer = nullptr; // Buffer for firmware header

        // Integrity verification
        std::string                 m_ExpectedMD5Hash = ""; // Expected MD5 hash from client
        MD5Hasher                   m_MD5Hasher;            // Calculates MD5 hash of update data

        // Target flash location
        const esp_partition_t*      m_TargetPartition = nullptr; // Partition to write to

        /**
         * @brief Resets internal state and frees allocated memory
         */
        void ResetState();

        /**
         * @brief Sets error state and resets internal state
         * @param reason The error that occurred
         */
        void Abort(UPDATE_ERROR reason);

        /**
         * @brief Writes buffered data to flash memory
         *
         * Handles the special case of firmware header stashing for safety.
         * Erases flash as needed before writing and optimizes by skipping writes
         * to regions that contain only 0xFF bytes.
         *
         * @return true if successful, false on error
         */
        bool WriteBufferToFlash();

        /**
         * @brief Checks if a partition contains valid bootable firmware
         *
         * Reads the first bytes of the partition and verifies the ESP32 firmware
         * magic byte (0xE9) is present at the beginning.
         *
         * @param partition Partition to check
         * @return true if partition is bootable, false otherwise
         */
        bool IsPartitionBootable(const esp_partition_t* const partition) const;

        /**
         * @brief Checks if a data block contains non-empty content
         *
         * Determines if a block of data needs to be written to flash by checking
         * if it contains any bytes that are not 0xFF (erased flash state).
         *
         * @param data Pointer to data block (must not be nullptr)
         * @param size Size of data block (must be > 0)
         * @return true if data contains non-empty content, false if all bytes are 0xFF
         */
        bool CheckDataAlignment(const uint8_t* data, uint64_t size) const;

    public:
        /**
         * @brief Default constructor
         */
        ESP32UpdateManager() = default;

        /**
         * @brief Begins an update process
         *
         * Prepares the system for receiving update data by selecting the appropriate
         * target partition and initializing buffers and verification.
         *
         * @param updateMode Type of update (FIRMWARE or FILESYSTEM)
         * @param expectedMD5Hash MD5 hash that the update should match when complete (must not be nullptr)
         * @param SPIFFSPartitionLabel Optional label for SPIFFS partition (for filesystem updates)
         * @return true if update initialization was successful, false otherwise
         */
        bool Begin(UPDATE_MODE updateMode, const char* const expectedMD5Hash, const char* const SPIFFSPartitionLabel = nullptr);

        /**
         * @brief Finalizes the update process
         *
         * Writes any remaining data, verifies the MD5 hash, and activates the new firmware
         * or filesystem partition if verification passes. For firmware updates, writes the
         * previously stashed header to make the partition bootable.
         *
         * @return true if update was successful, false if errors occurred
         */
        bool End();

        /**
         * @brief Aborts the current update process
         *
         * Cancels the update and frees all resources.
         */
        void Abort();

        /**
         * @brief Writes a block of update data to the flash buffer
         *
         * Data is buffered until a full sector is available, then written to flash.
         * Handles partial writes and automatically flushes the buffer when appropriate.
         *
         * @param data Pointer to data block (must not be nullptr)
         * @param size Size of data block in bytes (must be > 0)
         * @return Number of bytes successfully written
         */
        uint64_t Write(const uint8_t* const data, uint64_t size);

        /**
         * @brief Checks if an error has occurred during the update process
         * @return true if an error occurred, false otherwise
         */
        bool HasError() const { return (m_LastError != UPDATE_ERROR::OK); }

        /**
         * @brief Gets the last error that occurred
         * @return Error code
         */
        UPDATE_ERROR GetLastError() const { return m_LastError; }

        /**
         * @brief Gets a human-readable description of the last error
         * @return Error description string
         */
        std::string GetLastErrorAsString() const;

        /**
         * @brief Checks if rollback to previous firmware is possible
         *
         * Verifies that a valid bootable firmware exists in the alternate OTA partition.
         *
         * @return true if rollback is possible, false otherwise
         */
        bool IsRollbackPossible() const;

        /**
         * @brief Performs a rollback to previous firmware
         *
         * Sets the alternate OTA partition as the boot partition for the next restart
         * if it contains valid bootable firmware.
         *
         * @return true if rollback was successful, false otherwise
         */
        bool DoRollback();
    };
}
