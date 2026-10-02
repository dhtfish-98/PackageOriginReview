"""Descriptor-relative, bounded ordinary-file input on POSIX hosts."""

import os
from pathlib import Path
import stat


class InputError(ValueError):
    pass


def read_regular_file(path, byte_limit):
    if type(byte_limit) is not int or not 1 <= byte_limit <= 128 * 1024 * 1024:
        raise InputError("invalid byte budget")
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
    if (
        os.name != "posix"
        or not all(hasattr(os, flag) for flag in required)
        or os.open not in os.supports_dir_fd
    ):
        raise InputError("this reader requires POSIX no-follow descriptors")
    raw_path = os.fspath(path)
    if not isinstance(raw_path, str):
        raise InputError("input path must be text")
    if ".." in raw_path.split("/"):
        # Lexical normalization could otherwise erase a symbolic-link component
        # and select different bytes from the path the caller supplied.
        raise InputError("parent path components are not supported")
    absolute = Path(os.path.abspath(raw_path))
    parts = absolute.parts[1:]
    if not parts:
        raise InputError("input must be an ordinary file")
    directory = None
    descriptor = None
    try:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for component in parts[:-1]:
            following = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory,
            )
            os.close(directory)
            directory = following
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise InputError("input must be an ordinary file")
        if before.st_size > byte_limit:
            raise InputError("input byte budget exceeded")
        data = bytearray()
        while len(data) <= byte_limit:
            piece = os.read(descriptor, min(65536, byte_limit + 1 - len(data)))
            if not piece:
                break
            data.extend(piece)
        if len(data) > byte_limit:
            raise InputError("input byte budget exceeded")
        after = os.fstat(descriptor)

        def identity(s):
            return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

        if identity(before) != identity(after) or len(data) != after.st_size:
            raise InputError("input changed while being read")
        return bytes(data)
    except OSError as error:
        # Do not expose paths or file contents in error messages.
        raise InputError("ordinary-file read failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
