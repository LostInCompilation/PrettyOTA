#include <Arduino.h>
#include <WiFi.h>
#include <PrettyOTA.h>

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

AsyncWebServer  server(80);
PrettyOTA       OTAUpdates;

// updateMode is FILESYSTEM or FIRMWARE
void OnOTAStart(NSPrettyOTA::UPDATE_MODE updateMode)
{
    Serial.println("OTA update started");

    if(updateMode == NSPrettyOTA::UPDATE_MODE::FIRMWARE)
        Serial.println("Mode: Firmware");
    else if(updateMode == NSPrettyOTA::UPDATE_MODE::FILESYSTEM)
        Serial.println("Mode: Filesystem");
}

void OnOTAProgress(uint32_t currentSize, uint32_t totalSize)
{
    Serial.printf("OTA Progress Current: %u bytes, Total: %u bytes\n", currentSize, totalSize);
}

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

    // Initialize WiFi here
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    // Initialize PrettyOTA and set username and password authentication
    OTAUpdates.Begin(&server, "admin", "123");

    // Set callbacks
    OTAUpdates.OnStart(OnOTAStart);
    OTAUpdates.OnProgress(OnOTAProgress);
    OTAUpdates.OnEnd(OnOTAEnd);

    // Start web server
    server.begin();
}

void loop()
{
    delay(100);
}
