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

#include "ESPUpdateManager.h"

using namespace NSPrettyOTA;

bool ESPUpdateManager::IsPartitionBootable(const esp_partition_t* const partition) const
{
    if(!partition)
        return false;

    uint8_t partitionData[UM_ENCRYPTED_BLOCK_SIZE] = {0};

    // Read the first bytes of the partition to check header
    if(esp_partition_read(partition, 0, reinterpret_cast<uint32_t*>(partitionData), UM_ENCRYPTED_BLOCK_SIZE) != ESP_OK)
        return false;

    // Verify the ESP32 firmware magic byte (0xE9) at the beginning of the partition
    if(partitionData[0] != ESP_IMAGE_HEADER_MAGIC)
        return false;

    return true;
}

bool ESPUpdateManager::CheckDataAlignment(const uint8_t* data, uint64_t size) const
{
    // Skip check for empty or non-aligned data blocks
    if (size == 0 || size % sizeof(uint32_t))
        return true;

    // Check if the data block contains only 0xFF bytes (erased flash state)
    // This optimization allows skipping writes to already-erased flash regions
    uint64_t dwl = size / sizeof(uint32_t);

    do {
        // If any 32-bit word is not 0xFFFFFFFF, the block contains actual data
        if (*reinterpret_cast<const uint32_t*>(data) ^ 0xffffffff)
            return true;

        data += sizeof(uint32_t);
    } while (--dwl);

    // All bytes are 0xFF, no need to write this block
    return false;
}

void ESPUpdateManager::ResetState()
{
    // Free allocated memory
    if(m_Buffer)
        delete[] m_Buffer;

    if(m_SkipBuffer)
        delete[] m_SkipBuffer;

    // Reset all member variables to initial state
    m_Buffer = nullptr;
    m_SkipBuffer = nullptr;

    m_UpdateMode = UPDATE_MODE::FIRMWARE;
    m_UpdateSize = 0;
    m_UpdateProgress = 0;
    m_BufferSize = 0;
    m_ExpectedMD5Hash = "";
    m_TargetPartition = nullptr;
}

bool ESPUpdateManager::Begin(UPDATE_MODE updateMode, const char* const expectedMD5Hash, const char* SPIFFSPartitionLabel)
{
    // Prevent starting a new update if one is already in progress
    if(m_UpdateSize > 0)
        return false;

    // Initialize state for a new update
    ResetState();
    m_LastError = UPDATE_ERROR::OK;
    m_ExpectedMD5Hash = expectedMD5Hash;

    // Convert hash to lowercase for case-insensitive comparison
    for(char& c : m_ExpectedMD5Hash)
        c = std::tolower(c);

    // Validate MD5 hash format (should be 32 hex characters)
    if(m_ExpectedMD5Hash.length() != 32)
    {
        m_LastError = UPDATE_ERROR::ERROR_INVALID_HASH;
        return false;
    }

    // Select appropriate target partition based on update type
    if(updateMode == UPDATE_MODE::FIRMWARE)
    {
        // For firmware updates, use the next OTA partition
        m_TargetPartition = esp_ota_get_next_update_partition(nullptr);
        if(!m_TargetPartition)
        {
            m_LastError = UPDATE_ERROR::ERROR_NO_PARTITION;
            return false;
        }
    }
    else if(updateMode == UPDATE_MODE::FILESYSTEM)
    {
        // For filesystem updates, try SPIFFS first, then FAT as fallback
        m_TargetPartition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, SPIFFSPartitionLabel);
        if(!m_TargetPartition)
        {
            // No SPIFFS partition found with the specified label
            // Try finding a FAT partition as fallback
            m_TargetPartition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, nullptr);
            if(!m_TargetPartition)
            {
                m_LastError = UPDATE_ERROR::ERROR_NO_PARTITION;
                return false;
            }
        }
    }

    // Store update parameters
    m_UpdateSize = m_TargetPartition->size;
    m_UpdateMode = updateMode;
    m_MD5Hasher.Begin();

    // Allocate buffer for flash operations (one sector size)
    m_Buffer = new (std::nothrow) uint8_t[SPI_FLASH_SEC_SIZE];
    if(!m_Buffer)
    {
        m_LastError = UPDATE_ERROR::ERROR_OUT_OF_MEMORY;
        return false;
    }

    return true;
}

bool ESPUpdateManager::End()
{
    // Cannot end an update that has errors or hasn't started
    if(HasError() || m_UpdateSize == 0)
        return false;

    // Write any remaining data in the buffer
    if(m_BufferSize > 0)
    {
        if(!WriteBufferToFlash())
            return false;
    }

    // Finalize MD5 calculation and update size
    m_MD5Hasher.Calculate();
    m_UpdateSize = m_UpdateProgress;

    // Verify MD5 hash matches expected value
    if(m_ExpectedMD5Hash != m_MD5Hasher.GetHashAsString())
    {
        Abort(UPDATE_ERROR::ERROR_HASH_MISMATCH);
        return false;
    }

    // For firmware updates, finalize the partition
    if(m_UpdateMode == UPDATE_MODE::FIRMWARE)
    {
        // Write the previously stashed header bytes to make the partition bootable
        if(esp_partition_write(m_TargetPartition, 0, reinterpret_cast<uint32_t*>(m_SkipBuffer), UM_ENCRYPTED_BLOCK_SIZE) != ESP_OK)
        {
            Abort(UPDATE_ERROR::ERROR_WRITE);
            return false;
        }

        // Verify the partition is now bootable
        if(!IsPartitionBootable(m_TargetPartition))
        {
            Abort(UPDATE_ERROR::ERROR_READ);
            return false;
        }

        // Set this partition as the boot partition for next restart
        if(esp_ota_set_boot_partition(m_TargetPartition) != ESP_OK)
        {
            Abort(UPDATE_ERROR::ERROR_ACTIVATE);
            return false;
        }
    }

    // Clean up resources
    ResetState();

    return true;
}

void ESPUpdateManager::Abort()
{
    // Public abort method with default reason
    Abort(UPDATE_ERROR::ABORT);
}

void NSPrettyOTA::ESPUpdateManager::Abort(UPDATE_ERROR reason)
{
    // Reset state and set error code
    ResetState();
    m_LastError = reason;
}

bool NSPrettyOTA::ESPUpdateManager::WriteBufferToFlash()
{
    uint8_t skipSize = 0;

    // Special handling for the beginning of firmware updates
    if(m_UpdateProgress == 0 && m_UpdateMode == UPDATE_MODE::FIRMWARE)
    {
        // Verify firmware starts with the correct magic byte
        if(m_Buffer[0] != ESP_IMAGE_HEADER_MAGIC)
        {
            Abort(UPDATE_ERROR::ERROR_MAGIC_BYTE);
            return false;
        }

        // Safety mechanism: Stash the first 16 bytes (header) and write them last
        // This prevents the device from booting incomplete firmware if the update fails
        skipSize = UM_ENCRYPTED_BLOCK_SIZE;
        m_SkipBuffer = new (std::nothrow) uint8_t[skipSize];

        if(!m_SkipBuffer)
        {
            Abort(UPDATE_ERROR::ERROR_OUT_OF_MEMORY);
            return false;
        }

        // Save header for later
        memcpy(m_SkipBuffer, m_Buffer, skipSize);
    }

    const uint64_t offset = m_TargetPartition->address + m_UpdateProgress;

    // Determine erase strategy based on flash block boundaries and alignment

    // Erase a full block if we're at a block boundary and have enough data remaining
    const bool eraseBlock = (m_UpdateSize - m_UpdateProgress >= UM_SPI_FLASH_BLOCK_SIZE) &&
                           (offset % UM_SPI_FLASH_BLOCK_SIZE == 0);

    // Special handling for sectors at the beginning of unaligned partitions
    const bool partitionSectorHead = (m_TargetPartition->address % UM_SPI_FLASH_BLOCK_SIZE != 0) &&
                                    (offset < (m_TargetPartition->address / UM_SPI_FLASH_BLOCK_SIZE + 1) * UM_SPI_FLASH_BLOCK_SIZE);

    // Special handling for sectors at the end of unaligned partitions
    const bool partitionSectorTail = (offset >= (m_TargetPartition->address + m_UpdateSize) / UM_SPI_FLASH_BLOCK_SIZE * UM_SPI_FLASH_BLOCK_SIZE);

    // Erase the appropriate range before writing
    if(eraseBlock || partitionSectorHead || partitionSectorTail)
    {
        if(esp_partition_erase_range(m_TargetPartition, m_UpdateProgress,
                                     eraseBlock ? UM_SPI_FLASH_BLOCK_SIZE : SPI_FLASH_SEC_SIZE) != ESP_OK)
        {
            Abort(UPDATE_ERROR::ERROR_ERASE);
            return false;
        }
    }

    // Write data to flash, skipping the first bytes for firmware updates
    // Also skip writing if the partition is not encrypted and the data is all 0xFF
    if ((m_TargetPartition->encrypted || CheckDataAlignment(m_Buffer + (skipSize / sizeof(uint32_t)), m_BufferSize - skipSize))
        && (esp_partition_write(m_TargetPartition, m_UpdateProgress + skipSize,
                              reinterpret_cast<const uint32_t*>(m_Buffer) + (skipSize / sizeof(uint32_t)),
                              m_BufferSize - skipSize) != ESP_OK))
    {
        Abort(UPDATE_ERROR::ERROR_WRITE);
        return false;
    }

    // Restore magic byte in buffer for correct MD5 calculation
    if((m_UpdateProgress == 0) && (m_UpdateMode == UPDATE_MODE::FIRMWARE))
        m_Buffer[0] = ESP_IMAGE_HEADER_MAGIC;

    // Update MD5 hash with the data
    m_MD5Hasher.AddData(m_Buffer, m_BufferSize);

    // Update progress tracking
    m_UpdateProgress += m_BufferSize;
    m_BufferSize = 0;

    return true;
}

uint64_t ESPUpdateManager::Write(const uint8_t* const data, uint64_t size)
{
    // Cannot write if there are errors or update hasn't started
    if(HasError() || m_UpdateSize == 0)
        return 0;

    // Check if there's enough space left in the partition
    if(size > (m_UpdateSize - m_UpdateProgress))
    {
        Abort(UPDATE_ERROR::ERROR_NO_SPACE);
        return 0;
    }

    uint64_t bytesLeft = size;

    // Process data in sector-sized chunks
    while((m_BufferSize + bytesLeft) > SPI_FLASH_SEC_SIZE)
    {
        // Fill buffer to sector size
        const uint64_t toCopy = SPI_FLASH_SEC_SIZE - m_BufferSize;
        memcpy(m_Buffer + m_BufferSize, data + (size - bytesLeft), toCopy);

        m_BufferSize += toCopy;

        // Write full sector to flash
        if(!WriteBufferToFlash())
            return (size - bytesLeft);

        bytesLeft -= toCopy;
    }

    // Copy remaining data to buffer
    memcpy(m_Buffer + m_BufferSize, data + (size - bytesLeft), bytesLeft);
    m_BufferSize += bytesLeft;

    // If buffer now contains all remaining data for the update, write it immediately
    if(m_BufferSize == (m_UpdateSize - m_UpdateProgress))
    {
        if(!WriteBufferToFlash())
            return (size - bytesLeft);
    }

    return size;
}

bool ESPUpdateManager::IsRollbackPossible() const
{
    // Cannot rollback during an active update
    if(m_Buffer)
        return false;

    // Check if the alternate OTA partition contains valid firmware
    const esp_partition_t* const partition = esp_ota_get_next_update_partition(nullptr);

    return IsPartitionBootable(partition);
}

bool ESPUpdateManager::DoRollback()
{
    // Cannot rollback during an active update
    if(m_Buffer)
        return false;

    // Get the alternate OTA partition
    const esp_partition_t* const partition = esp_ota_get_next_update_partition(nullptr);

    // Verify it contains valid firmware
    if(!IsPartitionBootable(partition))
        return false;

    // Set it as the boot partition for next restart
    if(esp_ota_set_boot_partition(partition) != ESP_OK)
        return false;

    return true;
}

std::string NSPrettyOTA::ESPUpdateManager::GetLastErrorAsString() const
{
    // Convert error codes to human-readable messages
    switch(m_LastError)
    {
        case UPDATE_ERROR::OK:
            return "No error";

        case UPDATE_ERROR::ABORT:
            return "Aborted";

        case UPDATE_ERROR::ERROR_OUT_OF_MEMORY:
            return "ERROR_OUT_OF_MEMORY: No available RAM for allocation";

        case UPDATE_ERROR::ERROR_NO_PARTITION:
            return "ERROR_NO_PARTITION: Partition could not be found";

        case UPDATE_ERROR::ERROR_NO_SPACE:
            return "ERROR_NO_SPACE: Not enough free space on partition";

        case UPDATE_ERROR::ERROR_INVALID_HASH:
            return "ERROR_INVALID_HASH: Invalid MD5 hash";

        case UPDATE_ERROR::ERROR_HASH_MISMATCH:
            return "ERROR_HASH_MISMATCH: The firmware hash does not match the expected hash";

        case UPDATE_ERROR::ERROR_READ:
            return "ERROR_READ: Could not read from flash";

        case UPDATE_ERROR::ERROR_WRITE:
            return "ERROR_WRITE: Could not write to flash";

        case UPDATE_ERROR::ERROR_ERASE:
            return "ERROR_ERASE: Could not erase flash";

        case UPDATE_ERROR::ERROR_ACTIVATE:
            return "ERROR_ACTIVATE: Could not activate target partition for booting";

        case UPDATE_ERROR::ERROR_MAGIC_BYTE:
            return "ERROR_MAGIC_BYTE: Magic byte is invalid";

        default:
            return "Unknown error";
    }
}
