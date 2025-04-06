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

#pragma once

#include <string>   // For std::string
#include <string.h> // For memcpy, memset

#include <esp_system.h>
#include <esp_rom_md5.h>

namespace NSPrettyOTA
{
    class MD5Hasher
    {
    private:
        md5_context_t m_Context;
        uint8_t       m_Buffer[ESP_ROM_MD5_DIGEST_LEN] = {0};

    public:
        static const uint8_t MD5_HASH_STR_SIZE = (2 * ESP_ROM_MD5_DIGEST_LEN + 1);

        MD5Hasher() = default;

        void Begin();
        void AddData(const uint8_t* data, uint32_t size);
        void AddData(const char* data, uint32_t size);
        void Calculate();

        void GetHashAsBytes(uint8_t out[ESP_ROM_MD5_DIGEST_LEN]) const;
        std::string GetHashAsString() const;
    };
}
