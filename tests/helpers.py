"""Shared test helpers."""
import os


def bind_unix_socket(sock, directory, name, case):
    """Bind sock to directory/name by a relative path.

    Unix socket paths are limited to about 108 bytes, so binding by an absolute
    path fails inside long temporary directories. Skips the test when the
    platform cannot create the socket at all.
    """
    previous = os.getcwd()
    try:
        os.chdir(directory)
        sock.bind(name)
    except OSError:
        case.skipTest("cannot bind a unix socket here")
    finally:
        os.chdir(previous)
