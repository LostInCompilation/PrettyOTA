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
    Default callbacks for PrettyOTA.

*/

#include "PrettyOTA.h"

// ********************************************************
// OTA default callbacks
void PrettyOTA::OnOTAStart(NSPrettyOTA::UPDATE_MODE updateMode)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println("\n\n************************************************");

    if(m_DefaultCallbackPrintWithColor)
        m_SerialMonitorStream->println("*                 \033[1;7m OTA UPDATE \033[0m                 *");
    else
        m_SerialMonitorStream->println("*                  OTA UPDATE                  *");

    if(m_DefaultCallbackPrintWithColor)
    {
        if(updateMode == NSPrettyOTA::UPDATE_MODE::FIRMWARE)
            m_SerialMonitorStream->println("*                   \033[1mFirmware\033[0m                   *");
        else
            m_SerialMonitorStream->println("*                  \033[1mFilesystem\033[0m                  *");
    }
    else
    {
        if(updateMode == NSPrettyOTA::UPDATE_MODE::FIRMWARE)
            m_SerialMonitorStream->println("*                   Firmware                   *");
        else
            m_SerialMonitorStream->println("*                  Filesystem                  *");
    }

    m_SerialMonitorStream->println("************************************************\n");
    m_SerialMonitorStream->println("Starting OTA update...\n");
}

void PrettyOTA::OnOTAProgress(uint32_t currentSize, uint32_t totalSize)
{
    if (!m_SerialMonitorStream)
        return;

    static float lastPercentage = 0.0f;
    const float percentage = 100.0f * static_cast<float>(currentSize) / static_cast<float>(totalSize);
    const uint8_t numBarsToShow = static_cast<uint8_t>(percentage / 3.3333f);

    if(percentage - lastPercentage >= 1.0f)
    {
        // Print progress bar
        m_SerialMonitorStream->print("Updating... [");
        for(uint8_t i = 0; i < 30; i++)
        {
            if (i < numBarsToShow)
                m_SerialMonitorStream->print("=");
            else
                m_SerialMonitorStream->print(" ");
        }
        m_SerialMonitorStream->printf("] %02u%%\n", static_cast<uint8_t>(percentage));

        if(m_DefaultCallbackPrintWithColor)
            m_SerialMonitorStream->print("\033[1F"); // Move cursor to begining of previous line

        lastPercentage = percentage;
    }
}

void PrettyOTA::OnOTAEnd(bool successful)
{
    if (!m_SerialMonitorStream)
        return;

    if (successful)
        m_SerialMonitorStream->println("Updating... [==============================] 100%");

    m_SerialMonitorStream->println("\n************************************************");

    if(m_DefaultCallbackPrintWithColor)
    {
        if (successful)
            m_SerialMonitorStream->println("*           \033[1;92;7m OTA UPDATE SUCCESSFUL \033[0m            *");
        else
            m_SerialMonitorStream->println("*             \033[1;91;7m OTA UPDATE FAILED \033[0m              *");
    }
    else
    {
        if (successful)
            m_SerialMonitorStream->println("*            OTA UPDATE SUCCESSFUL             *");
        else
            m_SerialMonitorStream->println("*              OTA UPDATE FAILED               *");
    }

    m_SerialMonitorStream->println("************************************************\n\n");
}
