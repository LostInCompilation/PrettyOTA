#include <Arduino.h>
#include <WiFi.h>
#include <PrettyOTA.h>

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

AsyncWebServer  server(80); // Server on port 80 (HTTP)
PrettyOTA       OTAUpdates;

// Gets called when update starts
// updateMode can be FILESYSTEM or FIRMWARE
void OnOTAStart(NSPrettyOTA::UPDATE_MODE updateMode)
{
    Serial.println("OTA update started");

    if(updateMode == NSPrettyOTA::UPDATE_MODE::FIRMWARE)
        Serial.println("Mode: Firmware");
    else if(updateMode == NSPrettyOTA::UPDATE_MODE::FILESYSTEM)
        Serial.println("Mode: Filesystem");
}

// Gets called while update is running
// currentSize: Number of bytes already processed
// totalSize: Total size of new firmware in bytes
void OnOTAProgress(uint32_t currentSize, uint32_t totalSize)
{
    Serial.printf("OTA Progress Current: %u bytes, Total: %u bytes\n", currentSize, totalSize);
}

// Gets called when update finishes
void OnOTAEnd(bool successful)
{
    if (successful)
        Serial.println("OTA update finished successfully");
    else
        Serial.println("OTA update failed");
}

void setup()
{
    Serial.begin(115200);

    // Initialize WiFi
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    // Wait for successful WiFi connection
    while (WiFi.waitForConnectResult() != WL_CONNECTED)
    {
        Serial.println("[WiFi] Connection failed! Rebooting...");
        delay(3000);
        ESP.restart();
    }

    // Print IP address
    Serial.println("PrettyOTA can be accessed at: http://" + WiFi.localIP().toString() + "/update");

    // Initialize PrettyOTA and set username and password for authentication
    OTAUpdates.Begin(&server, "admin", "123");

    // Set unique Hardware-ID for your hardware/board
    OTAUpdates.SetHardwareID("UniqueBoard1");
    
    // Set firmware version to 1.0.0
    OTAUpdates.SetAppVersion("1.0.0");

    // Set current build time and date
    PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE();
    
    // Set custom callbacks
    OTAUpdates.OnStart(OnOTAStart);
    OTAUpdates.OnProgress(OnOTAProgress);
    OTAUpdates.OnEnd(OnOTAEnd);

    // Start web server
    server.begin();
}

void loop()
{
    // Give CPU time to other running tasks
    delay(100);
}
