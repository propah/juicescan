from juicescan.juicescan import ManualPortAnalyzer
from juicescan.parser import CommandInfo, Parser

if __name__ == "__main__":
    parser = Parser()
    command_info: CommandInfo = parser.validate()
    analyzer = ManualPortAnalyzer(command_info)
    analyzer.scan()
