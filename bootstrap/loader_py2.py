import types
import __builtin__
real_import = __builtin__.__import__


class DummyModule(object):
    pass


def get_module(name_path):
    if len(name_path) > 1:
        parent_module = get_module(name_path[:-1])
    else:
        parent_module = DummyModule()
    name = '.'.join(name_path)
    module = sys.modules.get(name)
    if module:
        return module
    path = '/'.join(name_path) + '.py'
    if path not in modules:
        path = path[:-3] + '/__init__.py'
    code = modules[path]
    module = types.ModuleType(name)
    sys.modules[name] = module
    setattr(parent_module, name_path[-1], module)
    compiled = compile(code, '/git-cinnabar::' + path, 'exec')
    exec(compiled, module.__dict__)
    return module


def import_hook(name, globals=None, locals=None, fromlist=None, level=-1):
    if name.startswith('cinnabar'):
        assert level <= 0
        module = get_module(name.split('.'))
        if fromlist or name == 'cinnabar':
            return module
        return sys.modules['cinnabar']

    return real_import(name, globals, locals, fromlist, level)


__builtin__.__import__ = import_hook
