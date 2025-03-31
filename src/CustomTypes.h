/*

zlib license

Copyright (c) 2025 Marc Schöndorf

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.


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
}
