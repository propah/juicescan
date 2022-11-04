from concurrent.futures import ThreadPoolExecutor
from socket import AF_INET, SOCK_STREAM, socket
from sys import stdout

from alive_progress import alive_bar
from termcolor import colored, cprint

from juicescan.parser import CommandInfo, PortType


class ManualPortAnalyzer:
    def __init__(self, command_info: CommandInfo) -> None:
        self.command_info = command_info
        self.open_ports: list[int] = []

    def scan(self):
        cprint(
            f"🔎 Scanning {self.command_info.ipv4}...",
            "white",
            "on_cyan",
            attrs=["bold"],
        )
        stdout.flush()
        match self.command_info.port_type:
            case PortType.LIST:
                with alive_bar(
                    len(self.command_info.ports), enrich_print=False, dual_line=True
                ) as bar:
                    bar.text = colored("😖 Juiced 0 port 😖")
                    with ThreadPoolExecutor(
                        max_workers=self.command_info.threads
                    ) as executor:
                        for port in self.command_info.ports:
                            executor.submit(self.is_port_open, port, bar)

            case PortType.RANGE:
                with alive_bar(
                    self.command_info.ports[1] - self.command_info.ports[0],
                    enrich_print=False,
                    dual_line=True,
                ) as bar:
                    bar.text = colored("😖 Juiced 0 port 😖")
                    with ThreadPoolExecutor(
                        max_workers=self.command_info.threads
                    ) as executor:
                        for port in range(
                            self.command_info.ports[0], self.command_info.ports[1]
                        ):
                            executor.submit(self.is_port_open, port, bar)
        cprint("Juiced ports:", "cyan", "on_white", attrs=["dark"])
        for open_port in self.open_ports:
            cprint(f"📦 {open_port}", "white", "on_green")

    def is_port_open(self, port: int, bar):
        try:
            sock = socket(AF_INET, SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.command_info.ipv4, port))
            self.open_ports.append(port)
            sock.close()
            bar.text = colored(f"💦 Juiced {len(self.open_ports)} ports 💦")

        except Exception:
            pass
        bar()
