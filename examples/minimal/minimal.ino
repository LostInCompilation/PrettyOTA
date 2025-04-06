#include <Arduino.h>
#include <WiFi.h>
#include <PrettyOTA.h>

const char* const   WIFI_SSID             = "FRITZ!Box 6660 Cable IF";
const char* const   WIFI_PASSWORD         = "45680759868962370573";

AsyncWebServer  server(80); // Server on port 80 (HTTP)
PrettyOTA       OTAUpdates;

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

    // Initialize PrettyOTA
    OTAUpdates.Begin(&server);

    // Set unique Hardware-ID for your hardware/board
    OTAUpdates.SetHardwareID("UniqueBoard1");

    // Set firmware version to 1.0.0
    OTAUpdates.OverwriteAppVersion("1.0.0");

    // Set current build time and date
    PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE();

    // Start web server
    server.begin();
}

void loop()
{
    // Give CPU time to other running tasks
    delay(100);
}
