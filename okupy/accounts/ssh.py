# vim:fileencoding=utf8:et:ts=4:sts=4:sw=4:ft=python

ssh_handlers = {}


def ssh_handler(f):
    ssh_handlers[f.__name__] = f
    return f
