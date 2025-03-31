#include <Arduino.h>
#include <WiFi.h>
#include <PrettyOTA.h>

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

AsyncWebServer  server(80); // Server on port 80 (HTTP)
PrettyOTA       OTAUpdates;

void setup()
{
    // Initialize WiFi
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    // Initialize PrettyOTA
    OTAUpdates.Begin(&server);

    // Start web server
    server.begin();
}

void loop()
{
    // Give CPU time to other running tasks
    delay(100);
}
