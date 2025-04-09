<p align="center">
<img src="https://github.com/user-attachments/assets/0efbf883-8ecd-4a2a-af7b-b6620b43138b" alt="Screenshot" style="height:100px;"/>
</p>

![Version](https://img.shields.io/badge/Version-V1.2.0-brightgreen?style=flat&&logo=framework) ![CPU](https://img.shields.io/badge/CPU-ESP32-red?style=flat&&logo=espressif) ![Arduino](https://img.shields.io/badge/Arduino-Supported-blue?style=flat&&logo=arduino) ![PlatformIO](https://img.shields.io/badge/PlatformIO-Supported-blue?style=flat&&logo=platformio)

# <p align="center">PrettyOTA</p>
### <p align="center">Over the air (OTA) update library for ESP32 series chips - (RaspberryPi Pico W coming soon)</p>

#### <p align="center">Simple to use, modern design - Install updates on your ESP32 over WiFi inside the browser with easy rollback feature</p>

### ❤️💰 Donation - Please support my work

<a href="https://buymeacoffee.com/lostincompilation" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

[or donate Bitcoin for PrettyOTA](#donation)

## Contents

- **[Features](#features)**
- **[Supported MCUs](#supported-mcus)**
- **[Demo](#demo)**
- **[Minimal example](#minimal-example)**
- **[Installation](#installation)**
  - [PlatformIO](#platformio)
  - [ArduinoIDE](#arduinoide)
  - [GitHub](#github)
  - [Dependencies](#dependencies)
- **[Usage](#usage)**
  - [Authentication (username and password)](#authentication-username-and-password)
      - [Password as MD5 hash](#password-as-md5-hash)
  - [OTA upload directly inside PlatformIO or ArduinoIDE](#ota-upload-directly-inside-platformio-or-arduinoide)
  - [Set HardwareID](#set-hardwareid)
  - [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date)
    - [ArduinoIDE (manual)](#arduinoide-manual)
    - [PlatformIO with ESP-IDF (automatic)](#platformio-with-esp-idf-automatic)
  - [Use mDNS](#use-mdns)
  - [Callbacks](#callbacks)
    - [Use default callbacks](#use-default-callbacks)
  - [Unmounting SPIFFS filesystem before an update](#unmounting-spiffs-filesystem-before-an-update)
  - [Custom URLs](#custom-urls)
  - [Partitions](#partitions)
  - [Save logged in clients to NVS](#save-logged-in-clients-to-nvs)
- **[Documentation of all functions](#documentation-of-all-functions)**
  - [Begin()](#begin)
  - [SetAuthenticationDetails()](#setauthenticationdetails)
  - [UseDefaultCallbacks()](#usedefaultcallbacks)
  - [SetSerialOutputStream()](#setserialoutputstream)
  - [OnStart(), OnProgress(), OnEnd()](#onstart-onprogress-onend)
  - [SetHardwareID()](#sethardwareid)
  - [SetAppVersion()](#setappversion)
  - [SetAppBuildTimeAndDate()](#setappbuildtimeanddate)
  - [Macro - PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE()](#macro---pretty_ota_set_current_build_time_and_date)
- **[Use PrettyOTA with ESP-IDF](#use-prettyota-with-esp-idf)**
- **[Is Ethernet supported?](#is-ethernet-supported)**
- **[Help I got compilation errors](#help-i-got-compilation-errors)**
- **[Usage in commercial applications and white labeling](#usage-in-commercial-applications-and-white-labeling)**
  - [White-labeling](#white-labeling)
- **[Donation](#donation)**

*See also: **[License](LICENSE.md)***

## Changelog <div id="changelog"/>

You can view the changelog here: [Changelog](CHANGELOG.md)

## Features <div id="features"/>

- ***Easy to use*** (two lines of code)
- ***Drag and drop*** firmware or filesystem `.bin` file to start updating
- ***Rollback*** to previous firmware with a button click
- ***Reboot*** remotely with a button click
- ***Show info*** about installed firmware (Firmware version, SDK version, build time)
- ***Automatic reboot*** after update/rollback can be enabled
- Support for **authentication** (login with username and password) using server generated keys
- ***Asynchronous web server***
- Support for ***ArduinoOTA*** to directly upload firmware over WiFi inside Arduino IDE and PlatformIO (tutorial included)

### What's planned for the future?

- Optional **firmware pulling from server**: Configure PrettyOTA to automatically check a server for a new firmware version and install it. This is useful for many devices which all need updates at the same time. No manual firmware upload required anymore
- Show/hide specific board infos
- Disable/enable filesystem updates in code

## Supported MCUs <div id="supported-mcus"/>

- **ESP32** (all variants)
- **RP2040** and **RP2350** (**RaspberryPi Pico W**) - *coming soon!*
- **ESP8266** - Support is planned but is not the highest priority now since the ESP8266 is end of life

## Demo <div id="demo"/>

<p align="center">
<img src="https://github.com/user-attachments/assets/cd5b869b-26ec-4d18-aa3c-554c78ec7306" alt="Screenshot" />
</p>

## Minimal example <div id="minimal-example"/>

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
```

## Installation <div id="installation"/>

### PlatformIO <div id="platformio"/>

To use this library with PlatformIO, simply search for PrettyOTA inside PlatformIO Library Manager.

⚠️ **Important:** You must add this line to your `platformio.ini`:

```ini
lib_compat_mode = strict
```

### ArduinoIDE <div id="arduinoIDE"/>

You can download PrettyOTA from the Arduino Library Manager. Simply search for PrettyOTA inside ArduinoIDE.

Alternatively you can download the latest release / `.zip` file from GitHub and import it into the ArduinoIDE (Sketch->Include library->Add .ZIP library).

### GitHub <div id="github"/>

Download the latest release / `.zip` file from releases.

### Dependencies <div id="dependencies"/>

You don't have to install the dependencies manually when using ArduinoIDE or PlatformIO. Simply search for *PrettyOTA* in the library manager and install it.

PrettyOTA needs the following libraries:

- [AsyncTCP](https://github.com/ESP32Async/AsyncTCP)
- [ESPAsyncWebServer](https://github.com/ESP32Async/ESPAsyncWebServer)
- [ArduinoJson](https://github.com/bblanchon/ArduinoJson)

## Usage <div id="usage"/>

### Authentication (username and password) <div id="authentication-username-and-password"/>

To enable authentication with username and password, simply pass the username and password to the `Begin(...)` function:

```cpp
OTAUpdates.Begin(&server, "username", "password");
```

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

#### Password as MD5 hash <div id="password-as-md5-hash"/>

It's better not to store the password as clear text. PrettyOTA supports setting the password as a MD5 hash.
Simply pass the hash string to `Begin(...)` as the password argument and set `passwordIsMD5Hash` to `true`:

```cpp
// The password is "123" (without quotes)
// The MD5 hash of "123" is "202cb962ac59075b964b07152d234b70"
OTAUpdates.Begin(&server, "username", "202cb962ac59075b964b07152d234b70", true);
```

### OTA upload directly inside PlatformIO or ArduinoIDE <div id="ota-upload-directly-inside-platformio-or-arduinoide"/>

If you don't want to use the web interface of PrettyOTA, you can directly upload the firmware via OTA using PlatformIO or ArduinoIDE.

For ArduinoIDE you don't have to change anything. The ESP32 will show up under boards as an WiFi OTA target.

For PlatformIO you have to change the `platformio.ini` file like usual for OTA uploads and add the following:

```ini
upload_protocol = espota
upload_port = 192.168.x.x
```

Replace the IP address with the IP address of your ESP32.

### Set HardwareID <div id="set-hardwareid"/>

The Hardware ID should be a unique identifier for your hardware/board.
You can set it using:

```cpp
void SetHardwareID(const char* const hardwareID);
```

If you don't set a Hardware ID, the default `"MyBoard1"` will be used. It is not recommended to leave the Hardware ID unchanged, as every board would get the same default value.

### Set firmware version number, build time and date <div id="set-firmware-version-number-build-time-and-date"/>

You can manually set the version number and build time/date (must be done when using ArduinoIDE or PlatformIO without ESP-IDF framework).
If you use PlatformIO with the ESP-IDF framework (you can use both, ESP-IDF and the Arduino Framework at the same time), PrettyOTA can automatically detect the version number and build time/date for you.

#### ArduinoIDE (manual) <div id="arduinoide-manual"/>

When using the ArduinoIDE you must manually set the version number and build time/date.

#### Firmware version number

To set the firmware version inside ArduinoIDE (or setting it manually if you use PlatformIO) use the following function inside `setup()`:

```cpp
void SetAppVersion(const char* const appVersion);
```

#### Build time and date

To set the *current* build time and date you can use the macro `PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE();` inside `setup().

The macro will call `SetAppBuildTimeAndDate(const char* const appBuildTime, const char* const appBuildDate)` with the current build time and date already filled in for you.

If you want to set a specific build time or date, just call `SetAppBuildTimeAndDate(...)` manually inside `setup()`:

```cpp
OTAUpdates.SetAppBuildTimeAndDate("17:10:00", "Mar 31 2025");
```

You don't have to follow any specific formatting for the time or date. Both parameters are strings and can be set to any value you like.

#### Example

```cpp
void setup()
{
    // ...

    // Initialize PrettyOTA
    OTAUpdates.Begin(&server);

    // Set hardware id
    OTAUpdates.SetHardwareID("MyUniqueBoard");

    // Set firmware version to 1.0.0
    OTAUpdates.SetAppVersion("1.0.0");

    // Set current build time and date
    PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE();

    // Or manually set a specific build time and date
    //OTAUpdates.SetAppBuildTimeAndDate("17:10:00", "Mar 31 2025");

    // ...
}
```

#### PlatformIO with ESP-IDF (automatic) <div id="platformio-with-esp-idf-automatic"/>

⚠️ The automatic way will only work if you use the ESP-IDF framework *with* the Arduino framework. If you only use the Arduino framework inside PlatformIO you must set the version and build time / date manually like described above for ArduinoIDE.

#### Firmware version number

In PlatformIO simply create a text file called `version.txt` in your projects root folder. The content of the textfile must be one line containing the firmware version:

```text
1.0.0
```

PlatformIO will automatically find the `version.txt` file and set the version of your firmware, which gets displayed by PrettyOTA in the browser.

See [Use PrettyOTA with ESP-IDF](#use-prettyota-with-esp-idf) below for details and examples.

#### Build time and date

The build time and date will be automatically set. You don't have to do anything. PrettyOTA reads the time and date of the build from the firmware partition using `esp_ota_get_app_description()`.

You can set it manually too with:

```cpp
OTAUpdates.SetAppBuildTimeAndDate("17:10:00", "Mar 31 2025");
```

### Use mDNS <div id="use-mdns"/>

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

The ArduinoIDE will now show the ESP32 as "myesp" like specified in the code above:

<p align="center">
<img width="475" alt="Screenshot 2025-03-31 at 21 17 08" src="https://github.com/user-attachments/assets/c97c1196-c6da-42e0-bcbf-66895dd0bdee" />
</p>

For a full example see [mDNS example](/examples/mDNS/mDNS.ino).

### Callbacks <div id="callbacks"/>

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
```

For the full example see [Callbacks example](/examples/callbacks/callbacks.ino).

### Use default callbacks <div id="use-default-callbacks"/>

PrettyOTA provides built-in default callbacks, which just print the update status to the SerialMonitor (or any other Stream you specified with `PrettyOTA::SetSerialOutputStream(Stream*)`).

To use the built-in default callbacks:

```cpp
// Use built-in default callbacks.
// Do not call OnStart, OnProgress or OnEnd anymore, since they would override the built-in default callbacks
OTAUpdates.UseDefaultCallbacks();
```

The default callbacks also support color formatted printing. Every terminal and serial monitor supports that feature, except ArduinoIDE's serial monitor.
To enable color formatted printing, set the `printWithColor` parameter to `true`:

```cpp
// Use built-in default callbacks with color formatted printing
OTAUpdates.UseDefaultCallbacks(true);
```

When using the default callbacks you will get the following output on your Serial-Monitor during an OTA update (colors are not supported by ArduinoIDE):

<p align="center">
<img width="380" alt="Screenshot 2025-03-31 at 03 35 45" src="https://github.com/user-attachments/assets/40f76183-3f94-469b-bb25-b01dd89e8606" />
</p>

### Unmounting SPIFFS filesystem before an update <div id="unmounting-spiffs-filesystem-before-an-update"/>

If you want to upload a filesystem image, the filesystem must be unmounted before the update begins (not necessary for firmware updates).

You can use a custom callback for `OnStart(...)`, and unmount the filesystem (i.e. SPIFFS/LittleFS) inside the `OnStart(...)` callback:

```cpp
void CustomOnStart(NSPrettyOTA::UPDATE_MODE updateMode)
{
    // Is the filesystem going to be updated?
    if(updateMode == NSPrettyOTA::UPDATE_MODE::FILESYSTEM)
    {
        // Unmount SPIFFS filesystem here
        SPIFFS.end();
    }
}

void setup()
{
    // ...

    OTAUpdates.Begin(&server);

    // Set callback
    OTAUpdates.OnStart(CustomOnStart);

    // ...
}
```

### Custom URLs <div id="custom-urls"/>

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

### Partitions <div id="partitions"/>

#### ArduinoIDE

Inside the ArduinoIDE make sure you select a partition scheme *with OTA*. For example you can use `Minimal SPIFFS (APP with OTA)`. However having a separate SPIFFS is not a requirement.

#### PlatformIO

To be able to use OTA updates you need (at least) two app partitions (for the firmware) and one ota_data partition (for configuration).

You also need a NVS partition where PrettyOTA can store the logged in clients. If you don't have a NVS partition, logged in clients won't be remembered after reboot/update and PrettyOTA will print an error message (but everything else will work without issues).

SPIFFS is not a requirement.

Example `partitions.csv` (4MB flash) for PlatformIO including an optional SPIFFS partition:

```scala
# Name, Type, SubType, Offset, Size, Flags
nvs,data,nvs,0x9000,0x13000,
phy,data,phy,0x1C000,0x2000,
otadata,data,ota,0x1E000,0x2000,
app0,app,ota_0,0x20000,0x1D0000,
app1,app,ota_1,0x1F0000,0x1D0000,
spiff,data,spiffs,0x3C0000,0x40000,
```

I can recommend [the ESP Partition Builder Website](https://thelastoutpostworkshop.github.io/microcontroller_devkit/esp32partitionbuilder) for an easy way to manage partitions.

### Save logged in clients to NVS <div id="save-logged-in-clients-to-nvs"/>

PrettyOTA automatically saves logged in clients (sessionIDs) to the NVS partition and loads them during initialization. This enables clients to stay logged in after a reboot or firmware update of the ESP32.

For this to work you must have a NVS partition (for example inside the `partitions.csv` file for PlatformIO).
Without a NVS partition saving will not work and you have to log in again after a reboot or firmware update of the ESP32.

## Documentation of all functions <div id="documentation-of-all-functions"/>

### Begin() <div id="begin"/>

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

#### SetAuthenticationDetails() <div id="setauthenticationdetails"/>

```cpp
void SetAuthenticationDetails(const char* const username,    // Username
                              const char* const password,    // Password
                              bool passwordIsMD5Hash = false); // (Optional) Is the password cleartext or a MD5 hash?
```

If `username` *and* `password` is empty, authentication will be disabled. The `/login` page then redirects automatically to the main `/update` page.

See [Authentication](#authentication-username-and-password) below for details and examples.

#### UseDefaultCallbacks() <div id="usedefaultcallbacks"/>

Call this function to use the built-in default callbacks. The default callbacks only print the update status to the Serial-Monitor (or any other Stream you specified).

See [Use default callbacks](#use-default-callbacks) for more details.

```cpp
void UseDefaultCallbacks(bool printWithColor = false);
```

#### SetSerialOutputStream() <div id="setserialoutputstream"/>

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

#### OnStart(), OnProgress(), OnEnd() <div id="onstart-onprogress-onend"/>

Set custom user defined callbacks. See [callbacks example](/examples/callbacks/callbacks.ino).

```cpp
// Set custom callback functions
void OnStart(std::function<void(NSPrettyOTA::UPDATE_MODE updateMode)> func);
void OnProgress(std::function<void(uint32_t currentSize, uint32_t totalSize)> func);
void OnEnd(std::function<void(bool successful)> func);
```

#### SetHardwareID() <div id="sethardwareid"/>

See [Set HardwareID](#set-hardwareid).

```cpp
void SetHardwareID(const char* const hardwareID);
```

#### SetAppVersion() <div id="setappversion"/>

See [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date).

```cpp
static void SetAppVersion(const char* const appVersion);
```

#### SetAppBuildTimeAndDate() <div id="setappbuildtimeanddate"/>

See [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date).

```cpp
static void SetAppBuildTimeAndDate(const char* const appBuildTime, const char* const appBuildDate);
```

#### Macro - PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE() <div id="macro---pretty_ota_set_current_build_time_and_date"/>

See [Set firmware version number, build time and date](#set-firmware-version-number-build-time-and-date).

```cpp
#define PRETTY_OTA_SET_CURRENT_BUILD_TIME_AND_DATE() PrettyOTA::SetAppBuildTimeAndDate(__TIME__, __DATE__)
```

## Use PrettyOTA with ESP-IDF <div id="use-prettyota-with-esp-idf"/>

PrettyOTA relies on ESPAsyncWebServer which is an Arduino library. However you can include the Arduino dependencies as a package inside your ESP-IDF project. No changes are required to your code base and the Arduino stuff is not interfering with anything in the background.

*Instructions on how to use ESP-IDF and Arduino framework at the same time will follow soon.*

## Is Ethernet supported? <div id="is-ethernet-supported"/>

Yes, Ethernet is supported with PrettyOTA and AsyncWebServer. You don't have to change anything regarding PrettyOTA's usage.

## Help I got compilation errors <div id="help-i-got-compilation-errors"/>

If you get the following error when compiling with PlatformIO:

```text
'ip_addr_t' {aka 'struct ip_addr'} has no member named 'addr'; did you mean 'u_addr'?
```

You must add this line to your `platformio.ini`:

```ini
lib_compat_mode = strict
```

## Usage in commercial applications and white labeling <div id="usage-in-commercial-applications-and-white-labeling"/>

You are allowed to use PrettyOTA for commercial purposes. An acknowledgement is required.
However you are not allowed to modify the source code and then claim that you wrote it.

It is also not permitted to change the name or logo of PrettyOTA, even when redistributing changed source code versions. If you want to change the logo and/or name, you must acquire a commercial license.

A commercial license also includes technical support for companies, who need reliable and fast solutions.

*See also: [License](LICENSE.md)*

### White-labeling <div id="white-labeling"/>

If you want to white-label PrettyOTA (use a custom name and logo for commercial or private application), please **[contact me via E-Mail](mailto:marc.public.mail@gmail.com)** for inquiries.
White-labeling is the only use case which is not free.

## Donation <div id="donation"/>

❤️ If you want to help out a student with paying rent, a donation for PrettyOTA and my work would be greatly appreciated!

💬 If you don't want to donate, please support by telling other people about PrettyOTA!

### Support me on *Buy me a coffee*

<a href="https://buymeacoffee.com/lostincompilation" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

### Bitcoin

<img width="150" alt="Bitcoin" src="https://github.com/user-attachments/assets/7c78d93f-60ef-45a0-afe3-e51e71e98edc" />

<br>

Wallet address (**Bitcoin**):

```text
32nkLAWGsAtn3SNo1vb7RSQKLP93YJCwke
```
