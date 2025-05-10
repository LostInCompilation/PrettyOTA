# Utils

To use any of the scripts, it's recommended to create a virtual environment and install all dependencies inside it.

`cd` into the script folder and create a virtual environment:

```sh
cd firmwareUploadScript
python3 -m venv venv
```

Activate it:

```sh
source venv/bin/activate
```

Install the dependencies listed in `requirements.txt`:

```sh
pip install -r requirements.txt
```

Run the script:
```sh
python3 firmwareUploadScript.py -target 192.168.0.42 -firmware firmware.bin
```

## Firmware Upload Script

A small python script to upload a firmware via Terminal/CLI. You can easily upload fimrware/filesystem images or rollback to previous firmware version.

Help text:

```
usage: firmwareUploadScript.py [-h] -target TARGET [-port PORT] [-username USERNAME] [-password PASSWORD] [--no-reboot]
                               [--dry-run] [-firmware | -filesystem | -rollback]
                               [filename]

Upload firmware or filesystem to a device running PrettyOTA.

This script allows you to update your devices directly from the command line, without using the PrettyOTA web interface.
It supports both firmware and filesystem updates, as well as rollback, with authentication if enabled.
The script will verify the update process and can automatically reboot the device when complete.

positional arguments:
  filename            Path to the firmware or filesystem file (.bin) to upload. Required if -firmware or -filesystem is
                      specified (or by default, which is firmware update). Ignored if -rollback is specified.

options:
  -h, --help          show this help message and exit
  -target TARGET      Device address where PrettyOTA is running. Can be an IP address (e.g., 192.168.0.42) or hostname (e.g.,
                      esp32.local).
  -port PORT          Port number where PrettyOTA is running. Default is 80, but can be changed if PrettyOTA is configured to
                      use a different port.
  -username USERNAME  Username for authentication. Required only if PrettyOTA has authentication enabled. Leave empty if
                      authentication is disabled.
  -password PASSWORD  Password for authentication. Required only if PrettyOTA has authentication enabled. Leave empty if
                      authentication is disabled.
  --no-reboot         Skip automatic reboot after update/rollback. By default, the device will reboot automatically. Use this
                      option if you want to reboot manually later.
  --dry-run           Show device information without making any changes. Useful for checking device status and compatibility
                      before performing an actual update or rollback.
  -firmware           Upload firmware file. This is the default operation if no mode (-firmware, -filesystem, -rollback) is
                      specified.
  -filesystem         Upload filesystem file. Use this mode to update the device's filesystem (e.g., SPIFFS, LittleFS).
  -rollback           Rollback to previous firmware (if possible). Filename argument is ignored if provided.

Examples:
  python firmwareUploadScript.py -target 192.168.0.42 firmware.bin
  python firmwareUploadScript.py -target esp32.local -port 8080 -username admin -password secret firmware.bin
  python firmwareUploadScript.py -target 192.168.0.42 -filesystem filesystem.bin --no-reboot
  python firmwareUploadScript.py -target 192.168.0.42 -rollback
```

## Website Compressor

A small python script to compress and convert the HTML sites for PrettyOTA into the C++ array to paste it into the PrettyOTA sourcecode.

Help text:
```
usage: websiteCompressor.py [-h] (-login | -main) htmlFilename

Compresses a HTML file with gzip and converts the result into a C++ array for direct embedding into the source code. The
result is saved as a .txt file and is copied to the clipboard automatically.

positional arguments:
  htmlFilename  The HTML file to compress

options:
  -h, --help    show this help message and exit
  -login        For the log in website
  -main         For the main website
```
