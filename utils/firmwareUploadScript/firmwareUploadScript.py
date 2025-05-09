#!/usr/bin/env python3

#######################################################################################
#                                                                                     #
#  Copyright (c) 2025 Marc Schöndorf                                                  #
#                                                                                     #
#  Permission is granted to anyone to use this software for private and               #
#  commercial applications, to alter it and redistribute it, subject to               #
#  the following conditions:                                                          #
#                                                                                     #
#  1. The origin of this software must not be misrepresented. You must not            #
#     claim that you wrote the original software. If you use this Software            #
#     in a product, acknowledgment in the product documentation or credits is         #
#     required.                                                                       #
#                                                                                     #
#  2. Altered source versions must be plainly marked as such, and must not            #
#     be misrepresented as being the original software.                               #
#                                                                                     #
#  3. You are not permitted to modify, replace or remove the name "PrettyOTA"         #
#     or the original logo displayed within the Software's default user interface     #
#     (if applicable), unless you have obtained a separate commercial license         #
#     granting you such rights. This restriction applies even when redistributing     #
#     modified versions of the source code.                                           #
#                                                                                     #
#  4. This license notice must not be removed or altered from any source              #
#     code distribution.                                                              #
#                                                                                     #
#  Disclaimer:                                                                        #
#  The software is provided "as is", without warranty of any kind, express            #
#  or implied, including but not limited to the warranties of merchantability,        #
#  fitness for a particular purpose and non-infringement. In no event shall the       #
#  authors or copyright holders be liable for any claim, damages or other             #
#  liability, whether in an action of contract, tort or otherwise, arising from,      #
#  out of or in connection with the software or the use or other dealings             #
#  in the software.                                                                   #
#                                                                                     #
#######################################################################################

#######################################################################################
#                                                                                     #
#   -- PRETTY OTA --                                                                  #
#                                                                                     #
#   Upload Firmware Script                                                            #
#                                                                                     #
#   Desc                                                                              #
#                                                                                     #
#   Usage:                                                                            #
#       python uploadFirmwareScript.py <html_filename> -login                         #
#       python uploadFirmwareScript.py <html_filename> -main                          #
#                                                                                     #
#######################################################################################

import os
import sys
import time
import signal
import argparse
import hashlib
import json
import requests
from requests_toolbelt import MultipartEncoder, MultipartEncoderMonitor
from urllib.parse import urljoin, urlparse, urlunparse

from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.control import Control
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, SpinnerColumn

# --- Initialize Rich console ---
console = Console(width=70)


# --- Handle interrupt signals ---
def signal_handler(signum, frame):
    console.print("\n[bold yellow]Operation cancelled by user[/bold yellow]")
    sys.exit(1)


# --- Register signal handlers ---
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# --- Get MD5 hash from string ---
def getMD5Hash(input):
    md5_hash = hashlib.md5()

    # Handle string vs bytes input
    if isinstance(input, str):
        input_bytes = input.encode("utf-8")
    else:
        input_bytes = input

    md5_hash.update(input_bytes)

    # Return the hexadecimal representation of the hash
    return md5_hash.hexdigest()


# --- Helper function for status messages ---
def printStatusMessage(message: str, success: bool):
    # Pad message to minimum 25 chars
    padded_message = message.ljust(25)
    status_text = "[bold green]OK[/bold green]" if success else "[bold red]FAILED[/bold red]"
    console.print(f"[bold white]{padded_message} [[/bold white]{status_text}[bold white]][/bold white]")


# --- Helper Function for printing an error panel ---
def printErrorPanel(errorMsg: str):
    console.print("")
    console.print(
        Panel(
            f"[bold red]ERROR[/bold red]\n\n{errorMsg}",
            border_style="red",
            padding=(1),
        )
    )


# --- Makes an HTTP request using session or requests directly with given method (GET / POST) ---
# --- Handles exceptions from requests and returns None on error ---
def makeRequest(method, url, session=None, showErrorPanel=True, **kwargs):
    try:
        requester = session or requests
        timeout = kwargs.pop("timeout", 10)  # Default timeout of 10 seconds, remove from kwargs
        response = requester.request(method, url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response

    except requests.exceptions.Timeout:
        if showErrorPanel:
            printErrorPanel(f"[highlight]Request timed out after {timeout} seconds[/highlight]")
        return None
    except requests.exceptions.HTTPError as e:
        if showErrorPanel:
            errorMsg = f"[highlight]An HTTP error occurred[/highlight]"
            if e.response is not None:
                errorMsg = f"[bold red]HTTP error:[/bold red] [highlight]'{e.response.text} ({e.response.status_code})'[/highlight]"
            printErrorPanel(errorMsg)
        return None
    except requests.exceptions.ConnectionError:
        if showErrorPanel:
            printErrorPanel(f"[highlight]Failed to connect to the server[/highlight]")
        return None
    except requests.exceptions.RequestException as e:
        if showErrorPanel:
            printErrorPanel(f"[bold red]Sending request failed:[/bold red] [highlight]{str(e)}[/highlight]")
        return None


# --- Authenticate with the current session ---
def authenticate(loginURL, session, username, password):
    # Get MD5 hash of password
    password = getMD5Hash(password)

    payload = {"userId": username, "password": password}
    headers = {"Content-Type": "application/json", "Accept": "*/*", "Connection": "keep-alive"}

    console.print("")

    # Make request
    with console.status("[bold white]Authenticating...[/bold white]", spinner="dots"):
        response = makeRequest("POST", loginURL, session=session, data=json.dumps(payload), headers=headers)

    printStatusMessage("Authenticating...", response is not None)
    return response is not None


# --- Logout to remove this session ID from server ---
def logout(logoutURL, session):
    headers = {"Connection": "close"}

    # Make request
    with console.status("[bold white]Logging out...[/bold white]", spinner="dots"):
        response = makeRequest("POST", logoutURL, session=session, headers=headers)

    printStatusMessage("Logging out...", response is not None)
    return response is not None


# --- Get information about running PrettyOTA instance (version, authentication required, URLs) ---
def getPrettyOTAInfo(infoURL):
    headers = {"Accept": "*/*", "Connection": "keep-alive"}

    # Make request
    with console.status(f"[bold white]Connecting to [italic]{urlparse(infoURL).netloc}[/italic]...[/bold white]", spinner="dots"):
        response = makeRequest("GET", infoURL, headers=headers)

    printStatusMessage(f"Connecting to [italic]{urlparse(infoURL).netloc}[/italic]...", response is not None)
    if response is None:
        return {}

    try:
        # Parse JSON response
        data = response.json()
        return {
            "prettyotaVersion": data.get("prettyotaVersion", "N/A"),
            "authenticationEnabled": data.get("authenticationEnabled", False),
            "loginURL": data.get("loginURL", ""),
            "mainURL": data.get("mainURL", ""),
        }

    except json.JSONDecodeError as e:
        printErrorPanel(f"[bold red]Invalid JSON response:[/bold red] [highlight]{str(e)}[/highlight]")
        return {}


# --- Get information about firmware and board ---
def getFirmwareInfo(infoURL, session):
    headers = {"Accept": "*/*", "Connection": "keep-alive"}

    # Make request
    with console.status("[bold white]Fetching board info...[/bold white]", spinner="dots"):
        response = makeRequest("GET", infoURL, session=session, headers=headers)

    printStatusMessage("Fetching board info...", response is not None)
    if response is None:
        return {}

    try:
        # Parse JSON response
        data = response.json()
        return {
            "hardwareID": data.get("hardwareID", "N/A"),
            "rollbackPossible": data.get("rollbackPossible", False),
            "firmwareVersion": data.get("firmwareVersion", "N/A"),
            "buildDate": data.get("buildDate", "N/A"),
            "buildTime": data.get("buildTime", "N/A"),
        }

    except json.JSONDecodeError as e:
        printErrorPanel(f"[bold red]Invalid JSON response:[/bold red] [highlight]{str(e)}[/highlight]")
        return {}


# --- Reboot device remotely ---
def doReboot(doRebootURL, rebootCheckURL, session):
    with console.status("[bold white]Rebooting device...[/bold white]", spinner="dots") as status:
        padded_message = ("Rebooting device...").ljust(25)

        # Make request to trigger reboot
        response = makeRequest("POST", doRebootURL, session=session)
        if response is None:
            console.print(f"[bold white]{padded_message} [[/bold white][bold red]FAILED[/bold red][bold white]][/bold white]")
            return False

        status.update(f"[bold white]{("Rebooting device...").ljust(23)} [[/bold white][bold blue]WAITING[/bold blue][bold white]][/bold white]")

        # Wait for server to come back online
        MAX_ATTEMPTS = 6
        attempt = 0

        while attempt < MAX_ATTEMPTS:
            # Try to connect to reboot check endpoint
            response = makeRequest("GET", rebootCheckURL, timeout=5, showErrorPanel=False)
            if response is not None:
                console.print(f"[bold white]{padded_message} [[/bold white][bold green]OK[/bold green][bold white]][/bold white]")
                return True

            time.sleep(0.5)  # Small sleep to prevent CPU load
            attempt += 1

        console.print(f"[bold white]{padded_message} [[/bold white][bold red]FAILED[/bold red][bold white]][/bold white]")
        printErrorPanel("[highlight]Device did not come back online within the expected time[/highlight]")
        return False


# --- Upload firmware ---
def uploadFirmware(startURL, uploadURL, mode, session, filename):
    startHeaders = {"Accept": "*/*", "Connection": "keep-alive"}
    postHeaders = {
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Content-Type": "application/octet-stream",
        "Content-Length": str(os.path.getsize(filename)),
    }

    with open(filename, "rb") as file:
        # Construct start URL
        md5Hash = getMD5Hash(file.read())
        startURL = urljoin(startURL, f"?mode={mode}&reboot=false&hash={md5Hash}")

        # --- Start update ---
        with console.status("[bold white]Starting update...[/bold white]", spinner="dots"):
            response = makeRequest("GET", startURL, session=session, headers=startHeaders)

        printStatusMessage("Starting update...", response is not None)
        if response is None:
            return False

        # --- Upload firmware ---
        file.seek(0)
        encoder = MultipartEncoder(fields={"MD5": md5Hash, "file": ("file", file, "application/octet-stream")})
        monitor = MultipartEncoderMonitor(encoder, lambda m: progress.update(task, completed=m.bytes_read))

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold white]Uploading firmware...[/bold white]"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("", total=os.path.getsize(filename))
            response = makeRequest("POST", uploadURL, session=session, headers=postHeaders, data=monitor)

        printStatusMessage("Uploading firmware...", response is not None)
        if response is None:
            return False

        return True


# --- Helper to consistently format the passed target argument into "http://ADDRESS" ---
def formatTargetURL(url, port):
    # Add http:// if no scheme is provided
    if not url.startswith("http://"):
        url = f"http://{url}"

    try:
        parsed = urlparse(url)

        # Check if netloc (domain or IP) is present
        if not parsed.netloc:
            raise ValueError("Invalid URL provided. No domain or IP address found")

        # Add port
        netloc = f"{parsed.netloc}:{port}"

        # Reconstruct URL with http://, keeping only scheme and netloc
        return urlunparse(("http", netloc, "", "", "", ""))

    except Exception as e:
        printErrorPanel(f"[highlight]{str(e)}[/highlight]")
        sys.exit(1)


# --- Setup and parse command line arguments ---
def parseCommandLine():
    parser = argparse.ArgumentParser(
        description="Directly uploads a firmware or filesystem (.bin) file to PrettyOTA.\
        You can update your devices with this script, without the need for the web interface.",
        epilog="Example: python firmwareUploadScript.py -target 192.168.0.42 -firmware <filename>",
    )
    parser.add_argument("filename", help="The firmware or filesystem (.bin) file to upload")
    parser.add_argument(
        "-target",
        help="The address or IP of the target running PrettyOTA (Example: '192.168.0.42', 'myesp.local')",
        required=True,
    )
    parser.add_argument("-port", help="The port where PrettyOTA is running. Default is 80", type=int, default=80)
    parser.add_argument("-username", help="The username for authentication (if enabled)", type=str)
    parser.add_argument("-password", help="The password for authentication (if enabled)", type=str)

    # parser.add_argument("-rollback", action="store_true", help="Rollback to previous firmware (if possible)")
    parser.add_argument("--no-reboot", action="store_true", help="Don't automatically reboot after update or rollback. Default is to reboot")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't actually upload the firmware or do a rollback, just print information about the firmware and the device",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-firmware", action="store_true", help="Upload firmware (.bin) - Default", default=True)
    group.add_argument("-filesystem", action="store_true", help="Upload filesystem (.bin))")

    return parser.parse_args()


# --- Main function ---
def main():
    try:
        console.set_window_title("PrettyOTA firmware upload")

        # Parse command line arguments
        args = parseCommandLine()

        # Validate that the input file exists
        if not os.path.isfile(args.filename):
            printErrorPanel(f"[highlight]The file '{args.filename}' does not exist.[/highlight]")
            sys.exit(1)

        # --- Format URL ---
        TARGET = formatTargetURL(args.target, args.port)

        MODE = "fw" if args.firmware else "fs"
        GENERAL_INFO_URL = TARGET + "/prettyota/queryPrettyOTAInfo"
        FIRMWARE_INFO_URL = TARGET + "/prettyota/queryInfo"
        LOGOUT_URL = TARGET + "/prettyota/logout"
        REBOOT_URL = TARGET + "/prettyota/doManualReboot"
        REBOOT_CHECK_URL = TARGET + "/prettyota/rebootCheck"
        ROLLBACK_URL = TARGET + "/prettyota/doRollback"
        UPDATE_START_URL = TARGET + "/prettyota/start"
        UPLOAD_URL = TARGET + "/prettyota/upload"

        console.print("")

        # --- Fetch PrettyOTA information ---
        prettyOTAInfo = getPrettyOTAInfo(GENERAL_INFO_URL)
        if not prettyOTAInfo:
            sys.exit(1)

        AUTH_ENABLED = prettyOTAInfo["authenticationEnabled"]
        LOGIN_URL = TARGET + prettyOTAInfo["loginURL"]

        console.print(
            Panel(
                Align.center(
                    Text.from_markup(
                        "[bold cyan]         PrettyOTA[/bold cyan]\n\n"
                        + f"[dim]PrettyOTA version:[/dim] [highlight]{prettyOTAInfo["prettyotaVersion"]}[/highlight]\n"
                        + f"[dim]Authentication:[/dim]    [highlight]{'Enabled' if AUTH_ENABLED else 'Disabled'}[/highlight]"
                    )
                ),
                border_style="blue",
                padding=(1),
            )
        )

        # Create a session to persist cookies (needed for authentication)
        session = requests.Session()

        # --- Authenticate ---
        if AUTH_ENABLED:
            if args.username is None and args.password is None:
                printErrorPanel("[highlight]Authentication is required but no username and password has been given[/highlight]")
                sys.exit(1)

            # Get username and password
            username = args.username if args.username is not None else ""
            password = args.password if args.password is not None else ""

            if not authenticate(LOGIN_URL, session, username, password):
                sys.exit(1)

        # --- Fetch firmware information and print it ---
        firmwareInfo = getFirmwareInfo(FIRMWARE_INFO_URL, session)
        if not firmwareInfo:
            sys.exit(1)

        console.print(
            Panel(
                Align.center(
                    Text.from_markup(
                        "[bold cyan]               Board[/bold cyan]\n\n"
                        + f" [dim]Hardware ID:[/dim]       [highlight]{firmwareInfo["hardwareID"]}[/highlight]\n\n"
                        + f" [dim]Firmware version:[/dim]  [highlight]{firmwareInfo["firmwareVersion"]}[/highlight]\n"
                        + f" [dim]Build date:[/dim]        [highlight]{firmwareInfo["buildDate"]}[/highlight]\n"
                        + f" [dim]Build time:[/dim]        [highlight]{firmwareInfo["buildTime"]}[/highlight]\n\n"
                        + f" [dim]Rollback possible:[/dim] [highlight]{'[bold green]Yes[/bold green]' if firmwareInfo["rollbackPossible"] else '[bold red]No[/bold red]'}[/highlight]"
                    )
                ),
                border_style="blue",
                padding=(1),
            )
        )

        console.print("")

        # --- Stop here if dry run is enabled ---
        if args.dry_run:
            console.print("[bold white]Dry run mode enabled. No changes have been made.[/bold white]")
            if AUTH_ENABLED:
                logout(LOGOUT_URL, session)
            sys.exit(0)

        # --- Upload firmware ---
        if args.firmware:
            if not uploadFirmware(UPDATE_START_URL, UPLOAD_URL, MODE, session, args.filename):
                sys.exit(1)

        # --- Reboot device ---
        if not args.no_reboot:
            if not doReboot(REBOOT_URL, REBOOT_CHECK_URL, session):
                sys.exit(1)
        else:
            console.print("[bold white]Device reboot has been skipped. Please reboot the device manually to apply the changes.[/bold white]")

        # --- Log out ---
        if AUTH_ENABLED:
            if not logout(LOGOUT_URL, session):
                sys.exit(1)

    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
