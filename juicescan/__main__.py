from juicescan.parser import CommandInfo, Parser

if __name__ == "__main__":
    parser = Parser()
    command_info: CommandInfo = parser.validate()
    print(vars(command_info))
