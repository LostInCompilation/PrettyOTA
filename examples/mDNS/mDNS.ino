#include <Arduino.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include <PrettyOTA.h>

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* DNS_ADDRESS   = "myesp"; // http://myesp.local

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

    // Print address and IP
    Serial.println("PrettyOTA can be accessed at: http://" + String(DNS_ADDRESS) + ".local/update");
    Serial.println("And at: http://" + WiFi.localIP().toString() + "/update");

    // Setup mDNS
    // You must call "MDNS.begin()" BEFORE "OTAUpdates.Begin()"
    MDNS.begin(DNS_ADDRESS);

    // Initialize PrettyOTA
    OTAUpdates.Begin(&server);

    // Set unique Hardware-ID for your hardware/board
    OTAUpdates.SetHardwareID("UniqueBoard1");
    
    // Set firmware version to 1.0.0
    OTAUpdates.SetAppVersion("1.0.0");

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
