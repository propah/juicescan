import argparse
import ipaddress
from enum import Enum

from termcolor import colored, cprint


def is_valid_ip_address(ip_string) -> bool:
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


class PortType(Enum):
    LIST = 1
    MIN_MAX = 2


class CommandInfo:
    def __init__(self, ipv4: str, threads: int) -> None:
        self.ipv4 = ipv4
        self.threads = threads

    def fromPortList(self, ports: list[int]) -> None:
        self.port_type = PortType.LIST
        self.ports = ports

    def fromPortRange(self, port_min: int, port_max: int) -> None:
        self.port_type = PortType.MIN_MAX
        self.ports = [port_min, port_max]


class Parser:
    def __init__(self) -> None:
        self.parser = argparse.ArgumentParser(
            prog="juicescan",
            usage="%(prog)s ipv4 -p ports -t threads",
            description=colored(
                "🧃 JuiceScan, the juiciest information gathering tool",
                "green",
                attrs=["bold"],
            ),
        )
        self.parser.add_argument(
            "ipv4",
            metavar="ipv4",
            type=str,
            help=colored("🎯 target's ipv4 address e.g 192.168.0.1", "grey"),
        )

        self.parser.add_argument(
            "--port",
            "-p",
            type=str,
            action="store",
            help=colored(
                "🎯 target's port(s), if none provided will scan all (0 < port < 65535)",
                "grey",
            ),
        )

        self.parser.add_argument(
            "--thread",
            "-t",
            type=int,
            action="store",
            help=colored(
                "🤖 amount of simultaneous connections on the target, default is 5 (0 < threads < 500)",
                "grey",
            ),
            default="5",
        )

    def validate(self) -> CommandInfo:
        port_min: int = 1
        port_max: int = 65535
        ports: list[int] = []
        self.args: argparse.Namespace = self.parser.parse_args()

        if not is_valid_ip_address(self.args.ipv4):
            cprint("❌ Invalid ip address", "red", "on_yellow")
            exit()
        if self.args.port is not None:
            self.args.port = self.args.port.replace(" ", "")
            if "," in self.args.port:
                ports_str = self.args.port.split(",")
                try:
                    ports = [int(x) for x in ports_str]
                except Exception:
                    cprint("❌ Invalid list of ports", "red", "on_yellow")
                    exit()
            elif "-" in self.args.port:
                ports_str = self.args.port.split("-")
                try:
                    match len(ports_str):
                        case 0:
                            pass
                        case 2:
                            port_min = min(int(ports_str[0]), int(ports_str[1]))
                            if port_min < 1 or port_min > 65535:
                                cprint(
                                    f"❌ Invalid minimum port {port_min}",
                                    "red",
                                    "on_yellow",
                                )
                                exit()
                            port_max = max(int(ports_str[0]), int(ports_str[1]))
                            if port_max < 1 or port_max > 65535:
                                cprint(
                                    f"❌ Invalid maximum port {port_max}",
                                    "red",
                                    "on_yellow",
                                )
                                exit()
                        case _:
                            cprint(
                                "❌ Invalid usage of port range, e.g -p 40-800 or -p-",
                                "red",
                                "on_yellow",
                            )
                            exit()
                except Exception:
                    cprint("❌ Invalid range of ports", "red", "on_yellow")
                    exit()
            else:
                try:
                    port_min = int(self.args.port)
                    port_max = port_min
                except Exception:
                    cprint("❌ Invalid port", "red", "on_yellow")
                    exit()
        if self.args.thread is not None:
            if self.args.thread <= 0 or self.args.thread > 500:
                cprint(
                    f"❌ Invalid number of threads (0 < {self.args.thread} < 500) ",
                    "red",
                    "on_yellow",
                )
                exit()
        cprint("✅ Valid arguments", "green", "on_cyan")
        command_info = CommandInfo(ipv4=self.args.ipv4, threads=self.args.thread)
        if ports != []:
            command_info.fromPortList(ports=ports)
        else:
            command_info.fromPortRange(port_min=port_min, port_max=port_max)
        return command_info
