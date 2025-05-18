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
#   Website compressor                                                                #
#                                                                                     #
#   Compresses a HTML file with gzip and saves the result as an uint8_t C++ array     #
#   containing the compressed data. The result is saved into a .txt file              #
#   and is copied to the clipboard automatically.                                     #
#                                                                                     #
#   Usage:                                                                            #
#       python websiteCompressor.py <htmlFilename> -login                             #
#       python websiteCompressor.py <htmlFilename> -main                              #
#                                                                                     #
#######################################################################################

import sys
import gzip
import argparse
import pyperclip
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

# Initialize Rich console
console = Console(width=70)


def formatAsCppArray(compressedContent, arrayName, valuesPerLine=35):
    result = []

    # Array declaration
    arrayDecl = f"const uint8_t PrettyOTA::{arrayName}[{len(compressedContent)}] = {{"
    result.append(arrayDecl)

    # Array content
    linesCount = (len(compressedContent) + valuesPerLine - 1) // valuesPerLine
    for i in range(linesCount):
        startIdx = i * valuesPerLine
        endIdx = min(startIdx + valuesPerLine, len(compressedContent))
        chunk = compressedContent[startIdx:endIdx]

        line = ", ".join([str(b) for b in chunk])

        # Add trailing comma for all lines except the last one
        if i < linesCount - 1:
            line += ","

        line = "    " + line
        result.append(line)

    result.append("};")

    return "\n".join(result)


def compressHTML(inputFilename, outputFilename, isMainMode):
    try:
        # Read the HTML file
        with open(inputFilename, "rb") as f:
            htmlContent = f.read()

        # Compress the content with gzip
        compressedContent = gzip.compress(htmlContent)

        # Convert compressed bytes to comma-separated integers
        arrayName = "PRETTY_OTA_WEBSITE_DATA" if isMainMode else "PRETTY_OTA_LOGIN_DATA"
        result = formatAsCppArray(compressedContent, arrayName)

        # Save to output file
        with open(outputFilename, "w") as f:
            f.write(result)

        # Copy to clipboard
        pyperclip.copy(result)

        # Calculate compression ratio
        compressionRatio = (1 - len(compressedContent) / len(htmlContent)) * 100

        # Print success message
        console.print(
            Panel(
                Align.center(
                    Text.from_markup(
                        f"[green]     ✅ Successfully compressed[/green]\n\n"
                        + f"[highlight]  Result has been copied to clipboard[/highlight]\n\n"
                        + f"[cyan]    Original size:[/cyan] [green]{len(htmlContent)}[/green] [dim]bytes[/dim]\n"
                        + f"[cyan]  Compressed size:[/cyan] [green]{len(compressedContent)}[/green] [dim]bytes[/dim]\n\n"
                        + f"[cyan]Compression ratio:[/cyan] [green]{compressionRatio:.2f}[/green] [dim]%[/dim]"
                    )
                ),
                border_style="green",
                padding=(1),
            )
        )

    except FileNotFoundError:
        console.print(
            Panel(
                f"[bold red]ERROR[/bold red]\n\n" + f"[bold red]File not found:[/bold red] [highlight]'{inputFilename}'[/highlight]",
                border_style="red",
                padding=(1),
            )
        )
        sys.exit(1)
    except Exception as e:
        console.print(
            Panel(
                f"[bold red]ERROR[/bold red]\n\n" + f"[bold red]Exception:[/bold red] [highlight]'{e}'[/highlight]",
                border_style="red",
                padding=(1),
            )
        )
        sys.exit(1)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Compresses a HTML file with gzip and converts the result into a C++ array for direct embedding into the source code. The result is saved as a .txt file and is copied to the clipboard automatically."
    )
    parser.add_argument("htmlFilename", help="The HTML file to compress")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-login", action="store_true", help="For the log in website")
    group.add_argument("-main", action="store_true", help="For the main website")
    args = parser.parse_args()

    # Prepare parameters
    outputFilename = "mainCompressed.txt" if args.main else "loginCompressed.txt"
    mode = "Main page" if args.main else "Log-In page"

    # Print header
    console.print(
        Panel(
            Align.center(
                Text.from_markup(
                    f"[bold cyan] PrettyOTA Website Compression Tool[/bold cyan]\n\n"
                    + f"     [dim] Input:[/dim] [highlight]{args.htmlFilename}[/highlight]\n"
                    + f"     [dim]Output:[/dim] [highlight]{outputFilename}[/highlight]\n\n"
                    f"     [dim]  Mode:[/dim] [highlight]{mode}[/highlight]"
                )
            ),
            border_style="blue",
            padding=(1),
        )
    )

    # Compress the HTML file
    compressHTML(args.htmlFilename, outputFilename, args.main)


if __name__ == "__main__":
    main()
