<p align="center">
<img src="img/logo.svg" alt="Screenshot" style="height:100px;"/>
</p>

### <center>A modern looking OTA update server for ESP32 with easy rollback</center>

## Contents
- [Features](#features)
- [Minimal example](#minimal-example)
- [Preview](#preview)
- [PlatformIO](#platformio)
- [Usage](#usage)
    - [The Begin function](#the-begin-function)
    - [Callbacks](#callbacks)
    - [Use default callbacks](#use-default-callbacks)

*See also: [License (zlib)](LICENSE.md)*

## Features
- ***Drag and drop*** firmware or filesystem .bin file to start updating
- ***Rollback*** to previous firmware with one button click
- ***Show info*** about board (Firmware version, build time)
- Automatic ***reboot*** after update/rollback
- If needed enable **authentication** (username and password login)
- Support for ArduinoOTA to directly upload OTA inside PlatformIO

## Minimal example
With the example code below you can access PrettyOTA at *http://192.168.x.x/update*
Replace the IP in the URL with the IP address of your ESP32.

```cpp
#include <Arduino.h>
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

## Preview
![Screen Recording 2025-03-02 at 08 26 48](https://github.com/user-attachments/assets/191e4082-1d72-49ef-8e65-83700b7cf4a4)

## PlatformIO

To use this library with PlatformIO, simply search for PrettyOTA inside PlatformIO Library Manager.

Additionally you must add this line to your `platformio.ini`:

```ini
lib_compat_mode = strict
```

### OTA upload directly inside PlatformIO

If you dont want to use the web interface of PrettyOTA, you can directly upload the firmware OTA with PlatformIO. Just change the `platformio.ini` file like usual for OTA uploads and add the following:

```ini
upload_protocol = espota
upload_port = 192.168.x.x
```

Replace the IP address with the IP address of your ESP32.

## Usage

### The Begin function
```cpp
PrettyOTA::Begin(Server, Username, Password, IsPasswordMD5Hash, otaPort);
```
- Server: `AsyncWebServer*`
- Username: `const char*` *(Optional)*
- Password: `const char*` *(Optional)* - Can be normal text or an MD5 hash of the password
- IsPasswordMD5Hash: `bool` *(Optional) Default: false* - Set to `true` if the password is a MD5 hash
- otaPort: `int` *(Optional) Default: 3232* The port for ArduinoOTA / PlatformIO OTA upload

### Callbacks
You can define your own callbacks which get called by PrettyOTA:

```cpp
#include <Arduino.h>
#include <WiFi.h>
#include "PrettyOTA.hpp"

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

AsyncWebServer  server(80);
PrettyOTA       OTA;

// UpdateMode is FILESYSTEM or FIRMWARE
void OnOTAStart(PrettyOTA::UPDATE_MODE updateMode)
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
    
    // Initialize OTA and set user and password
    OTAUpdates.Begin(&server, "admin", "123");
    
    // Set callbacks
    OTAUpdates.OnStart(OnOTAStart);
    OTAUpdates.OnProgress(OnOTAProgress);
    OTAUpdates.OnEnd(OnOTAEnd);
    
    // Start web server
    server.begin();
}
```

### Use default callbacks
PrettyOTA provides default callbacks, which just print the update status to the SerialMonitor (or any other Stream you specify with `PrettyOTA::SetSerialOutputStream(Stream*)` ).

```cpp
// Use default callbacks
OTAUpdates.UseDefaultCallbacks();
```

When using default callbacks you get this output on your serial monitor:

<img width="357" alt="Screenshot 2025-03-15 at 18 18 50" src="https://github.com/user-attachments/assets/4876388d-6543-46b7-a4c2-695acf0230d0" />
