<p align="center">
<img src="img/logo.svg" alt="Screenshot" style="height:100px;"/>
</p>

### <center>A modern looking OTA update server for ESP32 with easy rollback</center>

## Features
- ***Drag and drop*** firmware or filesystem .bin file to start updating
- ***Rollback*** to previous firmware with one button click
- ***Show info*** about board (Firmware version, build time)
- Automatic ***reboot*** after update/rollback
- If needed enable **authentication** (username and password login)

## Usage
```cpp
#include <WiFi.h>
#include "PrettyOTA.hpp"

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

AsyncWebServer  server(80);
PrettyOTA       OTA;

void setup() {
    // Initialize WiFi
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    // Initialize OTA
    OTA.Begin(&server);
    
    // Start web server
    server.begin();
}

void loop() {
}
```

## Demo
![Screen Recording 2025-03-02 at 08 26 48](https://github.com/user-attachments/assets/191e4082-1d72-49ef-8e65-83700b7cf4a4)

## The Begin function
```cpp
PrettyOTA::Begin(Server, Username, Password, IsPasswordMD5Hash);
```
- Server: `AsyncWebServer*`
- Username: `const char*` *(Optional)*
- Password: `const char*` *(Optional)* - Can be normal text or an MD5 hash of the password
- IsPasswordMD5Hash: `bool` *(Optional) Default: false* - Set to `true` if the password is a MD5 hash

## Callbacks
You can define your own callbacks which get called by PrettyOTA:

```cpp
#include <WiFi.h>
#include "PrettyOTA.hpp"

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

AsyncWebServer  server(80);
PrettyOTA       OTA;

void OnOTAStart()
{
    Serial.println("OTA update started");
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

void setup() {
    Serial.begin(9600);
    
    // Initialize WiFi here
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    // Initialize OTA
    OTAUpdates.Begin(&server, "admin", "123");
    
    // Set callbacks
    OTAUpdates.OnStart(OnOTAStart);
    OTAUpdates.OnProgress(OnOTAProgress);
    OTAUpdates.OnEnd(OnOTAEnd);
    
    // Start web server
    server.begin();
}
```

