#include <Arduino.h>
#include <WiFi.h>
#include "PrettyOTA.hpp"

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

AsyncWebServer  server(80);
PrettyOTA       OTA;

void setup()
{
    // Initialize WiFi
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    // Initialize OTA
    OTA.Begin(&server);

    // Start web server
    server.begin();
}

void loop()
{
    delay(100);
}
