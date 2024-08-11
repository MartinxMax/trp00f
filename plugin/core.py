#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

from pwn import *


class core:

    def send_command(client, command):
        """Send a command to the client with proper exception handling."""
        try:
            client.sendline(command.encode('utf-8'))
        except (EOFError, ConnectionResetError) as e:
            print(f"Error sending command: {e}")
        except Exception as e:
            print(f"Unexpected error sending command: {e}")


    def recv_response(client, timeout=2):
        """Receive the full response from the client with a specified timeout."""
        response = b''
        client.settimeout(timeout)
        try:
            while True:
                part = client.recv(4096)
                if not part:
                    break
                response += part
        except EOFError:
            print("[-] Timeout")
        except Exception as e:
            print(f"{e}")
        return response.decode('utf-8', errors='replace')
