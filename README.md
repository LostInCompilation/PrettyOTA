<p align="center">
<img src="img/logo.svg" alt="Screenshot" style="height:100px;"/>
</p>

![Version](https://img.shields.io/badge/Version-V1.0.2-brightgreen?style=flat&&logo=framework) ![CPU](https://img.shields.io/badge/CPU-ESP32-red?style=flat&&logo=espressif) ![Arduino](https://img.shields.io/badge/Arduino-Supported-blue?style=flat&&logo=arduino) ![PlatformIO](https://img.shields.io/badge/PlatformIO-Supported-blue?style=flat&&logo=platformio)

## <p align="center">A modern looking OTA web-update library for ESP32 with easy rollback - Completely free</p>

<!--❤️ <span style="color:lightblue;font-weight: bold;">Support me:</span> If you like this project and want to support a student, please consider donating ☺️-->

💬 *Support* this project by *telling other people* about PrettyOTA!

⚠️ This README will be updated the next days to be complete for the new release v1.0.2

## Contents

- [Changelog](#changelog)
- [Features](#features)
- [Demo](#demo)
- [Minimal example](#minimal-example)
- [Installation](#installation)
    - [PlatformIO](#platformio)
    - [Arduino](#arduino)
    - [GitHub](#github)
    - [Dependencies](#dependencies)
    - [OTA upload directly inside PlatformIO](#ota-upload-directly-inside-platformio)
- [Usage](#usage)
    - [Documentation of all functions](#documentation-of-all-functions)
        - [Begin()](#begin)
        - [SetAuthenticationDetails()](#setauthenticationdetails)
        - [UseDefaultCallbacks()](#usedefaultcallbacks)
        - [SetSerialOutputStream()](#setserialoutputstream)
        - [OnStart(), OnProgress(), OnEnd()](#onstart-onprogress-onend)
    - [Authentication (username and password)](#authentication-username-and-password)
    - [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date)
        - [PlatformIO (automatic)](#platformio-automatic)
        - [ArduinoIDE (manual)](#arduinoide-manual)
    - [Use mDNS](#use-mdns)
    - [Callbacks](#callbacks)
        - [Use default callbacks](#use-default-callbacks)
    - [Unmounting SPIFFS filesystem before update](#unmounting-spiffs-filesystem-before-update)
    - [Custom URLs](#custom-urls)
    - [Partitions](#partitions)
    - [Save logged in clients to NVS](#save-logged-in-clients-to-nvs)
- [Use PrettyOTA with ESP-IDF](#use-prettyota-with-esp-idf)
- [Help I got compilation errors](#help-i-got-compilation-errors)

*See also: [License (zlib)](LICENSE.md)*

## Changelog

You can view the changelog here: [Changelog](CHANGELOG.md)

## Features

- ***Easy to use*** (two lines of code)
- ***Drag and drop*** firmware or filesystem `.bin` file to start updating
- ***Rollback*** to previous firmware with a button click
- ***Reboot*** remotely with a button click
- ***Show info*** about installed firmware (Firmware version, SDK version, build time)
- ***Automatic reboot*** after update/rollback can be enabled
- Support for **authentication** (login with username and password) using server generated keys
- ***Asynchronous web server***
- Support for ***ArduinoOTA*** to directly upload firmware over WiFi inside Arduino IDE and PlatformIO (tutorial included)

## Demo

![Demo](https://github.com/user-attachments/assets/20d7871f-90cf-483a-9371-7e6df5ca2bbb)

## Minimal example

With the example code below you can access PrettyOTA at `http://IP_ADDRESS/update`, or upload via OTA inside ArduinoIDE and PlatformIO

Replace `IP_ADDRESS` in the URL with the IP address of your ESP32.

```cpp
#include <Arduino.h>
#include <WiFi.h>
#include <PrettyOTA.h>

const char* WIFI_SSID     = "YOUR_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

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

    // Start web server
    server.begin();
}

void loop()
{
    // Give CPU time to other running tasks
    delay(100);
}
```

## Installation

### PlatformIO

To use this library with PlatformIO, simply search for PrettyOTA inside PlatformIO Library Manager.

⚠️ **Important:** You must add this line to your `platformio.ini`:

```ini
lib_compat_mode = strict
```

### Arduino

You can download PrettyOTA from the Arduino Library Manager. Simply search for PrettyOTA inside ArduinoIDE.

Alternatively you can download the latest release / `.zip` file from GitHub and import it into the ArduinoIDE (Sketch->Include library->Add .ZIP library).

### GitHub

Clone the repository or download the latest release / `.zip` file.

```sh
git clone https://github.com/LostInCompilation/PrettyOTA
```

### Dependencies

You dont have to manually install the dependencies when using ArduinoIDE or PlatformIO. Simply search for *PrettyOTA* in the library manager and install it.

PrettyOTA needs the following libraries:

- AsyncTCP: https://github.com/ESP32Async/AsyncTCP
- ESPAsyncWebServer: https://github.com/ESP32Async/ESPAsyncWebServer
- ArduinoJson: https://github.com/bblanchon/ArduinoJson

### OTA upload directly inside PlatformIO

If you don't want to use the web interface of PrettyOTA, you can directly upload the firmware via OTA using PlatformIO. Just change the `platformio.ini` file like usual for OTA uploads and add the following:

```ini
upload_protocol = espota
upload_port = 192.168.x.x
```

Replace the IP address with the IP address of your ESP32.

## Usage

### Documentation of all functions

#### Begin()

```cpp
// Returns true on success, false on error or if already initialized
bool Begin(AsyncWebServer* const server,             // The AsyncWebServer instance
             const char* const   username = "",      // (Optional) Username for authentication
             const char* const   password = "",      // (Optional) Password for authentication
             bool                passwordIsMD5Hash = false, // (Optional) Is the password cleartext or a MD5 hash?
             const char* const   mainURL = "/update", // (Optional) Main URL for PrettyOTA
             const char* const   loginURL = "/login", // (Optional) Login page URL
             uint16_t            OTAport = 3232);     // (Optional) The port for OTA uploads inside ArduinoIDE/PlatformIO.
                                                      // Leave it set to `3232` for compatibility with ArduinoIDE OTA upload
```

#### SetAuthenticationDetails()

```cpp
void SetAuthenticationDetails(const char* const username,    // Username
                              const char* const password,    // Password
                              bool passwordIsMD5Hash = false); // (Optional) Is the password cleartext or a MD5 hash?
```

If `username` *and* `password` is empty, authentication will be disabled. The `/login` page then redirects automatically to the main `/update` page.

See [Authentication](#authentication-username-and-password) below for details and examples.

#### UseDefaultCallbacks()

Call this function to use the built-in default callbacks. The default callbacks only print the update status to the Serial-Monitor (or any other Stream you specified).
See [Use default callbacks](#use-default-callbacks) for more details.

```cpp
void UseDefaultCallbacks();
```

#### SetSerialOutputStream()

PrettyOTA outputs log messages when an error occurs. You can specify where these log messages should be printed. The default is printing to `Serial` (you must have `Serial.begin(115200);` inside `setup()` for this to work).

If you want to print to a different output, use the following function:

```cpp
// Set the Stream to write log messages too (Example: Use &Serial as argument)
void SetSerialOutputStream(Stream* const serialStream);
```

Example:
```cpp
// Print to Serial1 instead of default Serial
OTAUpdates.SetSerialOutputStream(&Serial1);
```

#### OnStart(), OnProgress(), OnEnd()

Set custom user defined callbacks. See [callbacks example](/examples/callbacks/callbacks.ino).

```cpp
// Set custom callback functions
void OnStart(std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> func);
void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func);
void OnEnd(std::function<void(bool successful)> func);
```

#### OverwriteAppVersion()

See [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date).

```cpp
static void OverwriteAppVersion(const char* const appVersion);
```

#### OverwriteAppBuildTimeAndDate()

See [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date).

```cpp
static void OverwriteAppBuildTimeAndDate(const char* const appBuildTime, const char* const appBuildDate);
```

#### Macro - PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE()

See [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date).

```cpp
#define PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE() PrettyOTA::OverwriteAppBuildTimeAndDate(__TIME__, __DATE__)
```

### Authentication (username and password)

To enable authentication with username and password, simply pass the username and password to the `Begin()` function.

You can always change the username or password after PrettyOTA has been initialized using:

```cpp
void SetAuthenticationDetails(const char* const username, const char* const password, bool passwordIsMD5Hash = false);
```

To disable authentication after it has been enabled previously, pass empty values for `username` and `password` to `SetAuthenticationDetails()`:

```cpp
// This will disable authentication
SetAuthenticationDetails("", "");
```

It is also possible to only have an username but no password (and vice versa). Simply leave one of the parameters (username *or* password) empty.

Authentication is disabled by default if you don't pass any values to `username` and `password` inside `Begin()`.

### Set firmware version number, build time and date

You can manually set the version number and build time/date (must be done when using ArduinoIDE). Or if you use PlatformIO, PrettyOTA can automatically detect the version number and build time/date for you.

#### PlatformIO (automatic)

#### Firmware version number

In PlatformIO simply create a text file called `version.txt` in your projects root folder. The content of the textfile must be one line containing the firmware version:

```text
1.0.0
```

PlatformIO will automatically find the `version.txt` file and set the version of your firmware, which gets displayed by PrettyOTA in the browser.

#### Build time and date

The build time and date will be automatically set. You don't have to do anything. PrettyOTA reads the time and date of the build from the firmware partition using `esp_ota_get_app_description()`.

#### ArduinoIDE (manual)

When using the ArduinoIDE you must manually set the version number and build time/date.

#### Firmware version number

To set the firmware version inside ArduinoIDE (or setting it manually if you use PlatformIO) use the following function inside `setup()`:

```cpp
void OverwriteAppVersion(const char* const appVersion);
```

#### Build time and date

To set the *current* build time and date you can use the macro `PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE();` inside `setup().

The macro will call `OverwriteAppBuildTimeAndDate(const char* const appBuildTime, const char* const appBuildDate)` with the current build time and date already filled in for you.

If you want to set a specific build time or date, just call `OverwriteAppBuildTimeAndDate(...)` manually inside `setup()`:

```cpp
OTAUpdates.OverwriteAppBuildTimeAndDate("17:10:00", "Mar 31 2025");
```

You don't have to follow any specific formatting for the time or date. Both parameters are strings and can be set to any value you like.

#### Example

```cpp
void setup()
{
    // ...

    // Initialize PrettyOTA
    OTAUpdates.Begin(&server);

    // Set firmware version to 1.0.0
    OTAUpdates.OverwriteAppVersion("1.0.0");

    // Set current build time and date
    PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE();

    // Or manually set a specific build time and date
    //OTAUpdates.OverwriteAppBuildTimeAndDate("17:10:00", "Mar 31 2025");

    // ...
}
```

### Use mDNS

You can use mDNS to display the hostname for the OTA upload target inside ArduinoIDE. You can also use it to access the ESP32 using a normal URL like `http://myesp.local/update` in your local network instead of the IP address.

```cpp
void setup()
{
    // ...
    
    // Setup mDNS
    // You must call "MDNS.begin()" BEFORE "OTAUpdates.Begin()"
    MDNS.begin("myesp"); // http://myesp.local/
    
    // Initialize PrettyOTA
    OTAUpdates.Begin(&server);
    
    // ...
}
```

For a full example see [mDNS example](/examples/mDNS/mDNS.ino).

### Callbacks

You can define your own callbacks which get called by PrettyOTA during the update.

Example:

```cpp
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
```

### Use default callbacks

PrettyOTA provides built-in default callbacks, which just print the update status to the SerialMonitor (or any other Stream you specified with `PrettyOTA::SetSerialOutputStream(Stream*)`).

To use the built-in default callbacks:

```cpp
// Use built-in default callbacks.
// Do not call OnStart, OnProgress or OnEnd anymore, since they would override the built-in default callbacks
OTAUpdates.UseDefaultCallbacks();
```

When using the default callbacks you will get the following output on your Serial-Monitor during an OTA update:
<img width="385" alt="Screenshot 2025-03-31 at 03 35 45" src="https://github.com/user-attachments/assets/40f76183-3f94-469b-bb25-b01dd89e8606" />

### Unmounting SPIFFS filesystem before update

If you want to upload a filesystem image, the filesystem must be unmounted before the update begins (not necessary for firmware updates).

You can use a custom callback for `OnStart`, and unmount the filesystem (i.e. SPIFFS/LittleFS) inside the `OnStart` callback:

TODO: Example

```cpp
TODO
```

### Custom URLs

PrettyOTA uses these URLs by default:

- Customizable URLs:
    - `/login`: Login page if authentication is enabled. Redirects to `/update` if authentication is disabled
    - `/update`: PrettyOTA's main website. Redirects to `/login` if authentication is enabled and client is not logged in
- Fixed URLs used internally (cannot be changed):
    - `/prettyota/start`:
    - `/prettyota/upload`:
    - `/prettyota/doRollback`:
    - `/prettyota/queryInfo`:
    - `/prettyota/queryPrettyOTAInfo`:
    - `/prettyota/rebootCheck`:
    - `/prettyota/doManualReboot`:
    - `/prettyota/logout`:

If you want to change the `/login` and / or `/update` URLs, specify them in the `Begin()` function:

```cpp
// Use custom URLs and enable authentication (username and password)
OTAUpdates.Begin(&server, "admin", "123", false, "/myCustomUpdateURL", "/myCustomLoginURL");
```

With the code above you can reach PrettyOTA under `http://YOUR_IP/myCustomUpdateURL`.

### Partitions

TODO

### Save logged in clients to NVS

PrettyOTA automatically saves logged in clients (sessionIDs) to the NVS partition and loads them during initialization. This enables clients to stay logged in after a reboot or firmware update of the ESP32.

For this to work you must have a NVS partition (for example inside the partitions.csv file for PlatformIO).
Without a NVS partition saving will not work and you have to log in again after a reboot or firmware update of the ESP32.

## Use PrettyOTA with ESP-IDF

TODO

## Help I got compilation errors

If you get the following error when compiling with PlatformIO:

```text
'ip_addr_t' {aka 'struct ip_addr'} has no member named 'addr'; did you mean 'u_addr'?
```

You must add this line to your `platformio.ini`:

```ini
lib_compat_mode = strict
```
