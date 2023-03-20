import sys


def filename(stl: bool = False) -> str:
    return "cacert.pem" if not stl else "authroot.stl"


if sys.version_info >= (3, 11):

    from importlib.resources import as_file, files

    _CACERT_CTX = None
    _CACERT_PATH = None
    _STL_CTX = None
    _STL_PATH = None

    def where(*, stl: bool = False) -> str:
        # This is slightly terrible, but we want to delay extracting the file
        # in cases where we're inside of a zipimport situation until someone
        # actually calls where(), but we don't want to re-extract the file
        # on every call of where(), so we'll do it once then store it in a
        # global variable.
        global _CACERT_CTX
        global _CACERT_PATH
        global _STL_CTX
        global _STL_PATH

        if not stl:
            # This is slightly janky, the importlib.resources API wants you to
            # manage the cleanup of this file, so it doesn't actually return a
            # path, it returns a context manager that will give you the path
            # when you enter it and will do any cleanup when you leave it. In
            # the common case of not needing a temporary file, it will just
            # return the file system location and the __exit__() is a no-op.
            #
            # We also have to hold onto the actual context manager, because
            # it will do the cleanup whenever it gets garbage collected, so
            # we will also store that at the global level as well.
            if _CACERT_PATH is None:
                _CACERT_CTX = as_file(files("mscerts").joinpath(filename(stl)))
                _CACERT_PATH = str(_CACERT_CTX.__enter__())

            return _CACERT_PATH
        else:
            if _STL_PATH is None:
                _STL_CTX = as_file(files("mscerts").joinpath(filename(stl)))
                _STL_PATH = str(_STL_CTX.__enter__())

            return _STL_PATH

    def contents() -> str:
        return files("mscerts").joinpath(filename()).read_text(encoding="ascii")

elif sys.version_info >= (3, 7):

    from importlib.resources import path as get_path, read_text

    _CACERT_CTX = None
    _CACERT_PATH = None
    _STL_CTX = None
    _STL_PATH = None

    def where(*, stl: bool = False) -> str:
        # This is slightly terrible, but we want to delay extracting the
        # file in cases where we're inside of a zipimport situation until
        # someone actually calls where(), but we don't want to re-extract
        # the file on every call of where(), so we'll do it once then store
        # it in a global variable.
        global _CACERT_CTX
        global _CACERT_PATH
        global _STL_CTX
        global _STL_PATH

        if not stl:
            # This is slightly janky, the importlib.resources API wants you
            # to manage the cleanup of this file, so it doesn't actually
            # return a path, it returns a context manager that will give
            # you the path when you enter it and will do any cleanup when
            # you leave it. In the common case of not needing a temporary
            # file, it will just return the file system location and the
            # __exit__() is a no-op.
            #
            # We also have to hold onto the actual context manager, because
            # it will do the cleanup whenever it gets garbage collected, so
            # we will also store that at the global level as well.
            if _CACERT_PATH is None:
                _CACERT_CTX = get_path("mscerts", filename(stl))
                _CACERT_PATH = str(_CACERT_CTX.__enter__())

            return _CACERT_PATH
        else:
            if _STL_PATH is None:
                _STL_CTX = get_path("mscerts", filename(stl))
                _STL_PATH = str(_STL_CTX.__enter__())

            return _STL_PATH

    def contents() -> str:
        return read_text("mscerts", filename(), encoding="ascii")

else:
    import os
    import types
    from typing import Union

    Package = Union[types.ModuleType, str]
    Resource = Union[str, "os.PathLike"]

    # This fallback will work for Python versions prior to 3.7 that lack the
    # importlib.resources module but relies on the existing `where` function
    # so won't address issues with environments like PyOxidizer that don't set
    # __file__ on modules.
    def read_text(
        package: Package,
        resource: Resource,
        encoding: str = 'utf-8',
        errors: str = 'strict'
    ) -> str:
        with open(where(), encoding=encoding) as data:
            return data.read()

    # If we don't have importlib.resources, then we will just do the old logic
    # of assuming we're on the filesystem and munge the path directly.
    def where(*, stl: bool = False) -> str:
        f = os.path.dirname(__file__)

        return os.path.join(f, filename(stl))

    def contents() -> str:
        return read_text("certifi", filename(), encoding="ascii")
