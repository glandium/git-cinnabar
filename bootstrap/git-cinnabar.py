# Accomodate with ArgumentParser using sys.argv[0]
sys.argv.pop(0)
from cinnabar.cmd import CLI
from cinnabar.util import run


if __name__ == '__main__':
    func, args = CLI.prepare(sys.argv[1:])
    run(func, args)
