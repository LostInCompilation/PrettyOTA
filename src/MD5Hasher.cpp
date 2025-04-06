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
    Helper class for building MD5 hashes.

*/

#include "MD5Hasher.h"

using namespace NSPrettyOTA;

void MD5Hasher::Begin()
{
    memset(m_Buffer, 0x00, ESP_ROM_MD5_DIGEST_LEN);
    esp_rom_md5_init(&m_Context);
}

void MD5Hasher::AddData(const uint8_t* data, uint32_t size)
{
    esp_rom_md5_update(&m_Context, data, size);
}

void MD5Hasher::AddData(const char* data, uint32_t size)
{
    AddData(reinterpret_cast<const uint8_t*>(data), size);
}

void MD5Hasher::Calculate()
{
    esp_rom_md5_final(m_Buffer, &m_Context);
}

void MD5Hasher::GetHashAsBytes(uint8_t out[ESP_ROM_MD5_DIGEST_LEN]) const
{
    memcpy(out, m_Buffer, ESP_ROM_MD5_DIGEST_LEN);
}

std::string MD5Hasher::GetHashAsString() const
{
    char out_MD5Str[MD5_HASH_STR_SIZE];

    for(uint8_t i = 0; i < ESP_ROM_MD5_DIGEST_LEN; i++)
        sprintf(out_MD5Str + (i * 2), "%02x", m_Buffer[i]);

    return out_MD5Str;
}
