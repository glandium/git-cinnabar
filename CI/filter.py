# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys


class DataCommand:
    def __init__(self, data):
        self.data = data

    def write_to(self, out):
        out.write(b"data %d\n" % len(self.data))
        out.write(self.data)


def iter_commands(input=sys.stdin.buffer):
    for line in input:
        if line.startswith(b"data "):
            _, length = line.split()
            length = int(length)
            data = input.read(length)
            assert len(data) == length
            yield DataCommand(data)
        else:
            yield line


def write_command(command, out=sys.stdout.buffer):
    if isinstance(command, DataCommand):
        command.write_to(out)
    else:
        out.write(command)


if __name__ == "__main__":
    args = sys.argv[1:]
    for arg in args:
        if arg not in ["--commits", "--roots"]:
            print(f"Unsupported options: {args}")
            sys.exit(1)

    commands = iter_commands()
    for command in commands:
        if isinstance(command, DataCommand):
            if "--commits" in args:
                command.data += b"\n"
            if "--roots" in args:
                write_command(command)
                while True:
                    command = next(commands)
                    # No "from" command, so this is a root, remove all the
                    # files from it.
                    if not command.startswith((b"deleteall", b"M ")):
                        break

        elif command.startswith((b"author  <", b"committer  <")):
            cmd, email = command.split(b"<", 1)
            command = cmd[:-1] + email.split(b"@", 1)[0] + b" <" + email
        write_command(command)
