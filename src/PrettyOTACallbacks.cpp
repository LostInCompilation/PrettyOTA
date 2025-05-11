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
    Default callbacks for PrettyOTA that provide visual feedback
    during OTA update processes via the serial monitor.

*/

#include "PrettyOTA.h"

// Constant used for visual formatting in the serial output
const char* const ROW_OF_STARS = "************************************************";

/**
 * Default callback triggered when an OTA update begins.
 * Displays a formatted header in the serial monitor with update type information.
 *
 * @param updateMode Specifies whether this is a FIRMWARE or FILESYSTEM update
 */
void PrettyOTA::OnOTAStart(NSPrettyOTA::UPDATE_MODE updateMode)
{
    if (!m_SerialMonitorStream)
        return;

    m_SerialMonitorStream->println("\n");
    m_SerialMonitorStream->println(ROW_OF_STARS);

    // Display header with or without ANSI color formatting
    if(m_DefaultCallbackPrintWithColor)
        m_SerialMonitorStream->println("*                 \033[1;7m OTA UPDATE \033[0m                 *");
    else
        m_SerialMonitorStream->println("*                  OTA UPDATE                  *");

    // Display update type with or without ANSI color formatting
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

    m_SerialMonitorStream->println(ROW_OF_STARS);
    m_SerialMonitorStream->println("\n");
    m_SerialMonitorStream->println("Starting OTA update...");
}

/**
 * Default callback triggered during an OTA update to show progress.
 * Displays an ASCII progress bar that updates when progress changes by at least 2%.
 *
 * @param currentSize Number of bytes transferred so far
 * @param totalSize Total number of bytes to transfer
 */
void PrettyOTA::OnOTAProgress(uint32_t currentSize, uint32_t totalSize)
{
    if (!m_SerialMonitorStream)
        return;

    static float lastPercentage = 0.0f;
    const float percentage = 100.0f * static_cast<float>(currentSize) / static_cast<float>(totalSize);
    const uint8_t numBarsToShow = static_cast<uint8_t>(percentage / 3.3333f); // 30 bars for 100%

    // Only update the progress bar when there's at least 2% change
    if(percentage - lastPercentage >= 2.0f)
    {
        m_SerialMonitorStream->print("Updating... [");
        for(uint8_t i = 0; i < 30; i++)
        {
            if (i < numBarsToShow)
                m_SerialMonitorStream->print("=");
            else
                m_SerialMonitorStream->print(" ");
        }
        m_SerialMonitorStream->printf("] %02u%%\n", static_cast<uint8_t>(percentage));

        // When using color mode, move cursor up to overwrite the previous line
        if(m_DefaultCallbackPrintWithColor)
            m_SerialMonitorStream->print("\033[1F");

        lastPercentage = percentage;
    }
}

/**
 * Default callback triggered when an OTA update completes.
 * Displays a formatted footer in the serial monitor with the update result.
 *
 * @param successful Whether the update completed successfully
 */
void PrettyOTA::OnOTAEnd(bool successful)
{
    if (!m_SerialMonitorStream)
        return;

    // Show 100% completion for successful updates
    if (successful)
        m_SerialMonitorStream->println("Updating... [==============================] 100%");

    m_SerialMonitorStream->println("");
    m_SerialMonitorStream->println(ROW_OF_STARS);

    // Display result with or without ANSI color formatting
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

    m_SerialMonitorStream->println(ROW_OF_STARS);
    m_SerialMonitorStream->println("");
}
