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

#include "ESPUpdateManager.h"

using namespace NSPrettyOTA;

bool ESPUpdateManager::IsPartitionBootable(const esp_partition_t* const partition) const
{
    if(!partition)
        return false;

    uint8_t partitionData[UM_ENCRYPTED_BLOCK_SIZE] = {0};

    // Read beginning of partition
    if(esp_partition_read(partition, 0, reinterpret_cast<uint32_t*>(partitionData), UM_ENCRYPTED_BLOCK_SIZE) != ESP_OK)
        return false;

    // Check header magic byte
    if(partitionData[0] != ESP_IMAGE_HEADER_MAGIC)
        return false;

    return true;
}

bool ESPUpdateManager::CheckDataAlignment(const uint8_t* data, uint64_t size) const
{
    // Only check 32-bit aligned blocks
    if (size == 0 || size % sizeof(uint32_t))
        return true;

    uint64_t dwl = size / sizeof(uint32_t);

    do {
        if (*reinterpret_cast<const uint32_t*>(data) ^ 0xffffffff)
            return true;

        data += sizeof(uint32_t);
    } while (--dwl);

    return false;
}

void ESPUpdateManager::ResetState()
{
    if(m_Buffer)
        delete[] m_Buffer;

    if(m_SkipBuffer)
        delete[] m_SkipBuffer;

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
    if(m_UpdateSize > 0) // Already running?
        return false;

    // Reset state
    ResetState();
    m_LastError = UPDATE_ERROR::OK;
    m_ExpectedMD5Hash = expectedMD5Hash;

    // Convert hash to lower case
    for(char& c : m_ExpectedMD5Hash)
        c = std::tolower(c);

    // Check hash
    if(m_ExpectedMD5Hash.length() != 32)
    {
        m_LastError = UPDATE_ERROR::ERROR_INVALID_HASH;
        return false;
    }

    // Get target partition for update
    if(updateMode == UPDATE_MODE::FIRMWARE)
    {
        m_TargetPartition = esp_ota_get_next_update_partition(nullptr);
        if(!m_TargetPartition)
        {
            m_LastError = UPDATE_ERROR::ERROR_NO_PARTITION;
            return false;
        }
    }
    else if(updateMode == UPDATE_MODE::FILESYSTEM)
    {
        // Try finding SPIFFS partition (with given label) first
        m_TargetPartition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, SPIFFSPartitionLabel);
        if(!m_TargetPartition)
        {
            // No SPIFFS partition (with given label) found.
            // Fallback to searching for FAT partition (without a label)
            m_TargetPartition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, nullptr);
            if(!m_TargetPartition)
            {
                m_LastError = UPDATE_ERROR::ERROR_NO_PARTITION;
                return false;
            }
        }
    }

    m_UpdateSize = m_TargetPartition->size;
    m_UpdateMode = updateMode;
    m_MD5Hasher.Begin();

    // Initialize update buffer
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
    if(HasError() || m_UpdateSize == 0)
        return false;

    // Write remaining buffer
    if(m_BufferSize > 0)
    {
        if(!WriteBufferToFlash())
            return false;
    }

    m_MD5Hasher.Calculate();
    m_UpdateSize = m_UpdateProgress;

    // Compare expected hash to calculated firmware hash
    if(m_ExpectedMD5Hash != m_MD5Hasher.GetHashAsString())
    {
        Abort(UPDATE_ERROR::ERROR_HASH_MISMATCH);
        return false;
    }

    // Verify end of firmware
    if(m_UpdateMode == UPDATE_MODE::FIRMWARE)
    {
        // Enable partition by writing the stashed buffer (first 16 bytes of partition)
        if(esp_partition_write(m_TargetPartition, 0, reinterpret_cast<uint32_t*>(m_SkipBuffer), UM_ENCRYPTED_BLOCK_SIZE) != ESP_OK)
        {
            Abort(UPDATE_ERROR::ERROR_WRITE);
            return false;
        }

        if(!IsPartitionBootable(m_TargetPartition))
        {
            Abort(UPDATE_ERROR::ERROR_READ);
            return false;
        }

        // Set boot partition
        if(esp_ota_set_boot_partition(m_TargetPartition) != ESP_OK)
        {
            Abort(UPDATE_ERROR::ERROR_ACTIVATE);
            return false;
        }
    }

    ResetState();

    return true;
}

void ESPUpdateManager::Abort()
{
    Abort(UPDATE_ERROR::ABORT);
}

void NSPrettyOTA::ESPUpdateManager::Abort(UPDATE_ERROR reason)
{
    ResetState();
    m_LastError = reason;
}

bool NSPrettyOTA::ESPUpdateManager::WriteBufferToFlash()
{
    uint8_t skipSize = 0;

    // Is it the beginning of new firmware?
    if(m_UpdateProgress == 0 && m_UpdateMode == UPDATE_MODE::FIRMWARE)
    {
        // Check magic byte
        if(m_Buffer[0] != ESP_IMAGE_HEADER_MAGIC)
        {
            Abort(UPDATE_ERROR::ERROR_MAGIC_BYTE);
            return false;
        }

        // Stash the first 16 bytes of data and do not write them to flash now.
        // The stashed 16 bytes will be written after all data has been written to flash.
        // This way the partition stays invalid until all data and the stashed buffer has been written,
        // to prevent booting a partial firmware in case the update didn't succeed.
        skipSize = UM_ENCRYPTED_BLOCK_SIZE;
        m_SkipBuffer = new (std::nothrow) uint8_t[skipSize];

        if(!m_SkipBuffer)
        {
            Abort(UPDATE_ERROR::ERROR_OUT_OF_MEMORY);
            return false;
        }

        // Copy beginning to skip buffer
        memcpy(m_SkipBuffer, m_Buffer, skipSize);
    }

    const uint64_t offset = m_TargetPartition->address + m_UpdateProgress;

    // If it's the block boundary, then erase the whole block from here
    const bool eraseBlock = (m_UpdateSize - m_UpdateProgress >= UM_SPI_FLASH_BLOCK_SIZE) && (offset % UM_SPI_FLASH_BLOCK_SIZE == 0);

    // Sector belongs to unaligned partition heading block
    const bool partitionSectorHead = (m_TargetPartition->address % UM_SPI_FLASH_BLOCK_SIZE != 0) && (offset < (m_TargetPartition->address / UM_SPI_FLASH_BLOCK_SIZE + 1) * UM_SPI_FLASH_BLOCK_SIZE);

    // Sector belongs to unaligned partition tailing block
    const bool partitionSectorTail = (offset >= (m_TargetPartition->address + m_UpdateSize) / UM_SPI_FLASH_BLOCK_SIZE * UM_SPI_FLASH_BLOCK_SIZE);

    if(eraseBlock || partitionSectorHead || partitionSectorTail)
    {
        if(esp_partition_erase_range(m_TargetPartition, m_UpdateProgress, eraseBlock ? UM_SPI_FLASH_BLOCK_SIZE : SPI_FLASH_SEC_SIZE) != ESP_OK)
        {
            Abort(UPDATE_ERROR::ERROR_ERASE);
            return false;
        }
    }

    // Try skipping empty blocks on unencrypted partitions
    if ((m_TargetPartition->encrypted || CheckDataAlignment(m_Buffer + (skipSize / sizeof(uint32_t)), m_BufferSize - skipSize))
        && (esp_partition_write(m_TargetPartition, m_UpdateProgress + skipSize, reinterpret_cast<const uint32_t*>(m_Buffer) + (skipSize / sizeof(uint32_t)), m_BufferSize - skipSize) != ESP_OK))
    {
        Abort(UPDATE_ERROR::ERROR_WRITE);
        return false;
    }

    // Restore magic byte or MD5 hash will be wrong
    if((m_UpdateProgress == 0) && (m_UpdateMode == UPDATE_MODE::FIRMWARE))
        m_Buffer[0] = ESP_IMAGE_HEADER_MAGIC;

    // Add data to hasher
    m_MD5Hasher.AddData(m_Buffer, m_BufferSize);

    m_UpdateProgress += m_BufferSize;
    m_BufferSize = 0;

    return true;
}

uint64_t ESPUpdateManager::Write(const uint8_t* const data, uint64_t size)
{
    if(HasError() || m_UpdateSize == 0)
        return 0;

    if(size > (m_UpdateSize - m_UpdateProgress))
    {
        Abort(UPDATE_ERROR::ERROR_NO_SPACE);
        return 0;
    }

    uint64_t bytesLeft = size;

    while((m_BufferSize + bytesLeft) > SPI_FLASH_SEC_SIZE)
    {
        const uint64_t toCopy = SPI_FLASH_SEC_SIZE - m_BufferSize;
        memcpy(m_Buffer + m_BufferSize, data + (size - bytesLeft), toCopy);

        m_BufferSize += toCopy;

        if(!WriteBufferToFlash())
            return (size - bytesLeft);

        bytesLeft -= toCopy;
    }

    memcpy(m_Buffer + m_BufferSize, data + (size - bytesLeft), bytesLeft);
    m_BufferSize += bytesLeft;

    if(m_BufferSize == (m_UpdateSize - m_UpdateProgress))
    {
        if(!WriteBufferToFlash())
            return (size - bytesLeft);
    }

    return size;
}

bool ESPUpdateManager::IsRollbackPossible() const
{
    if(m_Buffer) // Update is running
        return false;

    const esp_partition_t* const partition = esp_ota_get_next_update_partition(nullptr);

    return IsPartitionBootable(partition);
}

bool ESPUpdateManager::DoRollback()
{
    if(m_Buffer) // Update is running
        return false;

    const esp_partition_t* const partition = esp_ota_get_next_update_partition(nullptr);

    if(!IsPartitionBootable(partition))
        return false;

    if(esp_ota_set_boot_partition(partition) != ESP_OK)
        return false;

    return true;
}

std::string NSPrettyOTA::ESPUpdateManager::GetLastErrorAsString() const
{
    switch(m_LastError)
    {
        case UPDATE_ERROR::OK:
            return "No error";
        break;
        case UPDATE_ERROR::ABORT:
            return "Aborted";
        break;
        case UPDATE_ERROR::ERROR_OUT_OF_MEMORY:
            return "ERROR_OUT_OF_MEMORY: No available memory for allocation";
        break;
        case UPDATE_ERROR::ERROR_NO_PARTITION:
            return "ERROR_NO_PARTITION: Partition could not be found";
        break;
        case UPDATE_ERROR::ERROR_NO_SPACE:
            return "ERROR_NO_SPACE: Not enough free space";
        break;
        case UPDATE_ERROR::ERROR_INVALID_HASH:
            return "ERROR_INVALID_HASH: Invalid MD5 hash";
        break;
        case UPDATE_ERROR::ERROR_HASH_MISMATCH:
            return "ERROR_HASH_MISMATCH: The firmware hash does not match the expected hash";
        break;
        case UPDATE_ERROR::ERROR_READ:
            return "ERROR_READ: Could not read flash";
        break;
        case UPDATE_ERROR::ERROR_WRITE:
            return "ERROR_WRITE: Could not write flash";
        break;
        case UPDATE_ERROR::ERROR_ERASE:
            return "ERROR_ERASE: Could not erase flash";
        break;
        case UPDATE_ERROR::ERROR_ACTIVATE:
            return "ERROR_ACTIVATE: Could not activate target partition";
        break;
        case UPDATE_ERROR::ERROR_MAGIC_BYTE:
            return "ERROR_MAGIC_BYTE: Magic byte is invalid";
        break;

        default:
            return "Unknown";
        break;
    }
}
