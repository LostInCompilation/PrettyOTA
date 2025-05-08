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

import sys

# import os
import argparse
import hashlib
import requests
import json
from urllib.parse import urlparse, urlunparse

from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.control import Control

# Initialize Rich console
console = Console(width=70)


# Get MD5 hash from string
def getMD5FromString(input_string):
    # Convert the input string to bytes using utf-8 encoding
    input_bytes = input_string.encode("utf-8")

    # Create MD5 hash
    md5_hash = hashlib.md5()
    md5_hash.update(input_bytes)

    # Return the hexadecimal representation of the hash
    return md5_hash.hexdigest()


# --- Helper Function for printing an error panel ---
def printErrorPanel(errorMsg: str):
    console.print(
        Panel(
            f"[bold red]ERROR[/bold red]\n\n{errorMsg}",
            border_style="red",
            padding=(1),
        )
    )


# Makes an HTTP request using session or requests directly with given method (GET / POST)
# Handles exceptions from requests and returns None on error
def makeRequest(method, url, session=None, **kwargs):
    try:
        requester = session or requests
        timeout = kwargs.pop("timeout", 10)  # Default timeout of 10 seconds, remove from kwargs
        response = requester.request(method, url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response

    except requests.exceptions.Timeout:
        printErrorPanel(f"[highlight]Request timed out after 10 seconds[/highlight]")
        return None
    except requests.exceptions.HTTPError as e:
        errorMsg = f"[highlight]An HTTP error occurred[/highlight]"
        if e.response is not None:
            errorMsg = f"[bold red]HTTP error:[/bold red] [highlight]'{e.response.text} ({e.response.status_code})'[/highlight]"
        printErrorPanel(errorMsg)
        return None
    except requests.exceptions.ConnectionError:
        printErrorPanel(f"[highlight]Failed to connect to the server[/highlight]")
        return None
    except requests.exceptions.RequestException as e:
        printErrorPanel(f"[bold red]Sending request failed:[/bold red] [highlight]{str(e)}[/highlight]")
        return None


# Authenticate with the current session
def authenticate(loginURL, session, username, password):
    # Get MD5 hash of password
    password = getMD5FromString(password)

    # Create JSON payload
    payload = {"userId": username, "password": password}

    # Set header
    headers = {
        "Content-Type": "application/json"
        # "Accept": "*/*",
        # "Connection": "keep-alive"
    }

    # Make request
    response = makeRequest("POST", loginURL, session=session, data=json.dumps(payload), headers=headers)

    if response is not None:
        return True
    else:
        return False


# Get information about running PrettyOTA instance (version, authentication required, URLs)
def getPrettyOTAInfo(infoURL):
    # Make request
    response = makeRequest("GET", infoURL)

    if response is not None:
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
    else:
        return {}


# Helper to consistently format the passed target argument into "http://ADDRESS"
def formatTargetURL(url):
    # Add http:// if no scheme is provided
    if not url.startswith("http://"):
        url = f"http://{url}"

    try:
        parsed = urlparse(url)

        # Check if netloc (domain or IP) is present
        if not parsed.netloc:
            raise ValueError("Invalid URL provided. No domain or IP address found")

        # Reconstruct URL with http://, keeping only scheme and netloc
        return urlunparse(("http", parsed.netloc, "", "", "", ""))

    except Exception as e:
        printErrorPanel(f"[highlight]{str(e)}[/highlight]")
        sys.exit(1)


# Setup and parse command line arguments
def parseCommandLine():
    parser = argparse.ArgumentParser(
        description="Directly uploads a firmware or filesystem (.bin) file to PrettyOTA.\
        You can update your devices with this script, without the need for the web interface.",
        epilog="Example: python firmwareUploadScript.py -target 192.168.0.42 -firmware <filename>",
    )
    # parser.add_argument("filename", help="The firmware or filesystem (.bin) file to upload", required=True)
    parser.add_argument(
        "-target",
        help="The address or IP of the target running PrettyOTA (Example: '192.168.0.42', 'myesp.local')",
        required=True,
    )
    parser.add_argument("-port", help="The port where PrettyOTA is running. Default is 80", type=int, default=80)
    parser.add_argument("-username", help="The username for authentication (if enabled)", type=str)
    parser.add_argument("-password", help="The password for authentication (if enabled)", type=str)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-firmware", action="store_true", help="Upload firmware (.bin) - DEFAULT", default=True)
    group.add_argument("-filesystem", action="store_true", help="Upload filesystem (.bin))")

    return parser.parse_args()


def main():
    # Parse command line arguments
    args = parseCommandLine()

    console.set_window_title("PrettyOTA firmware upload")

    # Validate that the input file exists
    # if not os.path.isfile(args.filename):
    #     print(f"Error: The file '{args.filename}' does not exist.")
    #     return

    # Format URL
    TARGET = formatTargetURL(args.target)
    INFO_URL = TARGET + "/prettyota/queryPrettyOTAInfo"

    # Fetch PrettyOTA information
    console.print(f"\n[bold white]Connecting to [italic]{TARGET}[/italic]...[/bold white]")
    prettyOTAInfo = getPrettyOTAInfo(INFO_URL)

    if not prettyOTAInfo:
        sys.exit(1)

    # Extract PrettyOTA information and print it
    PRETTYOTA_VERSION = prettyOTAInfo["prettyotaVersion"]
    AUTH_ENABLED = prettyOTAInfo["authenticationEnabled"]
    LOGIN_URL = TARGET + prettyOTAInfo["loginURL"]

    console.print(
        Panel(
            Align.center(
                Text.from_markup(
                    "[bold cyan]   PrettyOTA information[/bold cyan]\n\n"
                    + f"[dim]PrettyOTA version:[/dim] [highlight]{PRETTYOTA_VERSION}[/highlight]\n"
                    + f"[dim]Authentication:[/dim]    [highlight]{'Enabled' if AUTH_ENABLED else 'Disabled'}[/highlight]"
                )
            ),
            border_style="blue",
            padding=(1),
        )
    )

    # Create a session to persist cookies (needed for authentication)
    session = requests.Session()

    # Authenticate
    if AUTH_ENABLED:
        if args.username == None and args.password == None:
            printErrorPanel("[highlight]Authentication is required but no username and password has been given[/highlight]")
            sys.exit(1)

        # Get username and password
        username = args.username if args.username != None else ""
        password = args.password if args.password != None else ""

        console.print("\n[bold white]Authenticating...[/bold white]")
        if not authenticate(LOGIN_URL, session, username, password):
            sys.exit(1)

        console.print("[bold green]Authentication successful[/bold green]")


if __name__ == "__main__":
    main()
