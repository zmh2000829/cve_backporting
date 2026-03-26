"""CLI 命令注册入口。"""


def register_all(subparsers, parent):
    from . import analyze, checks, maintenance, server, validate

    dispatch = {}
    for module in (analyze, checks, validate, maintenance, server):
        dispatch.update(module.register(subparsers, parent))
    return dispatch
