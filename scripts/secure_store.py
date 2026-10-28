"""Protected, atomic JSON storage for MeowPush credentials and authorization state.

Callers hold ``store.lock()`` around read-modify-write transactions. Existing
unsafe files are rejected, never silently repaired. Windows uses native ACLs;
POSIX uses owner-only modes and directory-relative, no-follow file operations.
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import stat
import uuid


MAX_JSON_BYTES = 4 * 1024 * 1024
LOCK_NAME = ".credentials.lock"


class StoreError(Exception):
    """A safe error suitable for display without exception interpolation."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def _invalid_json() -> StoreError:
    return StoreError("invalid_store", "The protected JSON file is malformed or is not an object.")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("Non-finite JSON value")


class _WindowsSecurity:
    """Small Win32 adapter. Native Windows execution is required to test this path."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD),
                        ("lpSecurityDescriptor", wintypes.LPVOID),
                        ("bInheritHandle", wintypes.BOOL)]

        class Acl(ctypes.Structure):
            _fields_ = [("AclRevision", wintypes.BYTE), ("Sbz1", wintypes.BYTE),
                        ("AclSize", wintypes.WORD), ("AceCount", wintypes.WORD),
                        ("Sbz2", wintypes.WORD)]

        class AttributeTagInfo(ctypes.Structure):
            _fields_ = [("FileAttributes", wintypes.DWORD),
                        ("ReparseTag", wintypes.DWORD)]

        self.SecurityAttributes = SecurityAttributes
        self.Acl = Acl
        self.AttributeTagInfo = AttributeTagInfo
        ptr = wintypes.LPVOID
        pptr = ctypes.POINTER(ptr)
        signatures = [
            (self.kernel.GetCurrentProcess, [], wintypes.HANDLE),
            (self.kernel.CloseHandle, [wintypes.HANDLE], wintypes.BOOL),
            (self.kernel.LocalFree, [ptr], ptr),
            (self.kernel.CreateDirectoryW,
             [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)], wintypes.BOOL),
            (self.kernel.CreateFileW,
             [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
              ctypes.POINTER(SecurityAttributes), wintypes.DWORD,
              wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
            (self.kernel.GetFileInformationByHandleEx,
             [wintypes.HANDLE, ctypes.c_int, ptr, wintypes.DWORD], wintypes.BOOL),
            (self.advapi.OpenProcessToken,
             [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)], wintypes.BOOL),
            (self.advapi.GetTokenInformation,
             [wintypes.HANDLE, ctypes.c_int, ptr, wintypes.DWORD,
              ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.advapi.ConvertSidToStringSidW, [ptr, pptr], wintypes.BOOL),
            (self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW,
             [wintypes.LPCWSTR, wintypes.DWORD, pptr,
              ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.advapi.GetSecurityInfo,
             [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
              pptr, pptr, pptr, pptr, pptr], wintypes.DWORD),
            (self.advapi.GetSecurityDescriptorControl,
             [ptr, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (self.advapi.GetAce, [ptr, wintypes.DWORD, pptr], wintypes.BOOL),
            (self.advapi.EqualSid, [ptr, ptr], wintypes.BOOL),
        ]
        for function, args, restype in signatures:
            function.argtypes = args
            function.restype = restype

        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            self._fail()
        try:
            size = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if not size.value:
                self._fail()
            self.token_user = ctypes.create_string_buffer(size.value)
            if not self.advapi.GetTokenInformation(token, 1, self.token_user,
                                                  size.value, ctypes.byref(size)):
                self._fail()
            self.sid = ctypes.cast(self.token_user, ctypes.POINTER(wintypes.LPVOID))[0]
            text = wintypes.LPVOID()
            if not self.advapi.ConvertSidToStringSidW(self.sid, ctypes.byref(text)):
                self._fail()
            try:
                self.sid_text = ctypes.wstring_at(text)
            finally:
                self.kernel.LocalFree(text)
        finally:
            self.kernel.CloseHandle(token)

    @staticmethod
    def _fail():
        raise StoreError("windows_security_error", "Windows could not verify or apply current-user-only file access.")

    @contextlib.contextmanager
    def _attributes(self, directory=False):
        c = self.ctypes
        descriptor = self.wintypes.LPVOID()
        # Protected DACL, a single full-control ACE, and the current user as owner.
        flags = "OICI" if directory else ""
        sddl = f"O:{self.sid_text}D:P(A;{flags};FA;;;{self.sid_text})"
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, c.byref(descriptor), None):
            self._fail()
        try:
            yield self.SecurityAttributes(c.sizeof(self.SecurityAttributes), descriptor, False)
        finally:
            self.kernel.LocalFree(descriptor)

    def _verify(self, handle, directory=False):
        c, w = self.ctypes, self.wintypes
        info = self.AttributeTagInfo()
        if not self.kernel.GetFileInformationByHandleEx(handle, 9, c.byref(info), c.sizeof(info)):
            self._fail()
        if info.FileAttributes & 0x0400 or bool(info.FileAttributes & 0x0010) != directory:
            raise StoreError("unsafe_path", "The protected path is a link or has an unexpected file type.")
        owner, dacl, descriptor = w.LPVOID(), w.LPVOID(), w.LPVOID()
        if self.advapi.GetSecurityInfo(handle, 1, 0x0001 | 0x0004,
                                      c.byref(owner), None, c.byref(dacl), None,
                                      c.byref(descriptor)):
            self._fail()
        try:
            control, revision = w.WORD(), w.DWORD()
            if not self.advapi.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)):
                self._fail()
            if not owner or not dacl or not self.advapi.EqualSid(owner, self.sid) or not control.value & 0x1000:
                self._fail()
            acl = c.cast(dacl, c.POINTER(self.Acl)).contents
            if acl.AceCount != 1:
                self._fail()
            ace = w.LPVOID()
            if not self.advapi.GetAce(dacl, 0, c.byref(ace)):
                self._fail()
            ace_type = c.c_ubyte.from_address(ace.value).value
            mask = w.DWORD.from_address(ace.value + 4).value
            if ace_type != 0 or mask not in (0x001F01FF, 0x10000000):
                self._fail()
            if not self.advapi.EqualSid(w.LPVOID(ace.value + 8), self.sid):
                self._fail()
        finally:
            self.kernel.LocalFree(descriptor)

    def _open_handle(self, path, directory=False, create=False):
        c = self.ctypes
        attributes = self._attributes(directory) if create else contextlib.nullcontext(None)
        with attributes as security:
            handle = self.kernel.CreateFileW(
                str(path), 0x80000000 | 0x00020000 | (0x40000000 if create else 0),
                0x0001 | 0x0002 | 0x0004,
                c.byref(security) if security else None,
                1 if create else 3,
                0x00200000 | (0x02000000 if directory else 0x0080), None)
        if handle == c.c_void_p(-1).value:
            error = c.get_last_error()
            if error in (2, 3):
                raise FileNotFoundError()
            if error in (80, 183):
                raise FileExistsError()
            self._fail()
        try:
            self._verify(handle, directory)
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        return handle

    def ensure_directory(self, path):
        with self._attributes(directory=True) as security:
            if not self.kernel.CreateDirectoryW(str(path), self.ctypes.byref(security)):
                if self.ctypes.get_last_error() != 183:
                    self._fail()
        handle = self._open_handle(path, directory=True)
        self.kernel.CloseHandle(handle)

    def open_file(self, path, create=False):
        import msvcrt

        handle = self._open_handle(path, create=create)
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if create else os.O_RDONLY))
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        try:
            # A concurrent atomic replacement can unlink this already-open
            # inode. It remains private; only additional hard links are unsafe.
            if os.fstat(fd).st_nlink > 1:
                raise StoreError("unsafe_path", "A protected file must not have multiple hard links.")
            return fd
        except BaseException:
            os.close(fd)
            raise


class SecureStore:
    """A directory containing protected JSON files, with explicit transactions."""

    def __init__(self, directory: Path):
        self.directory = Path(directory).absolute()
        self._windows = _WindowsSecurity() if os.name == "nt" else None

    @staticmethod
    def _name(name):
        if (not isinstance(name, str) or not name or name in (".", "..")
                or any(char in name for char in ("/", "\\", "\x00", ":"))
                or name.endswith((".", " "))):
            raise StoreError("invalid_filename", "A protected filename must be a simple filename.")
        return name

    @staticmethod
    def _verify_posix(fd, directory=False):
        info = os.fstat(fd)
        expected = 0o700 if directory else 0o600
        valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (not valid_type or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != expected
                # An already-open inode can have zero links after another
                # writer atomically replaces the directory entry.
                or (not directory and info.st_nlink > 1)):
            raise StoreError("unsafe_permissions", "Protected storage must be owned by the current user with directory mode 0700 and file mode 0600, without links.")
        return info

    def ensure(self):
        try:
            self.directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self._windows:
                self._windows.ensure_directory(self.directory)
            else:
                try:
                    self.directory.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                with self._directory_fd():
                    pass
        except StoreError:
            raise
        except OSError:
            raise StoreError("storage_unavailable", "The protected storage directory could not be created or opened.") from None

    @contextlib.contextmanager
    def _directory_fd(self):
        fd = None
        try:
            if self._windows:
                # Ensure also verifies an existing directory's owner and ACL.
                self._windows.ensure_directory(self.directory)
            else:
                fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                self._verify_posix(fd, directory=True)
            yield fd
        finally:
            if fd is not None:
                os.close(fd)

    def _open(self, name, directory_fd, create=False):
        if self._windows:
            return self._windows.open_file(self.directory / name, create)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory_fd)
        try:
            if create:
                os.fchmod(fd, 0o600)
            self._verify_posix(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _unlink(self, name, directory_fd):
        if self._windows:
            os.unlink(self.directory / name)
        else:
            os.unlink(name, dir_fd=directory_fd)

    def _check_existing(self, name, directory_fd):
        try:
            fd = self._open(name, directory_fd)
        except FileNotFoundError:
            return
        os.close(fd)

    def read_json(self, name: str) -> dict | None:
        name = self._name(name)
        self.ensure()
        try:
            with self._directory_fd() as directory_fd:
                try:
                    fd = self._open(name, directory_fd)
                except FileNotFoundError:
                    return None
                with os.fdopen(fd, "rb") as source:
                    raw = source.read(MAX_JSON_BYTES + 1)
            if len(raw) > MAX_JSON_BYTES:
                raise _invalid_json()
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                              parse_constant=_reject_constant)
            if not isinstance(data, dict):
                raise _invalid_json()
            return data
        except StoreError:
            raise
        except (ValueError, UnicodeError, RecursionError):
            raise _invalid_json() from None
        except OSError:
            raise StoreError("storage_read_failed", "The protected file could not be read safely.") from None

    def write_json(self, name: str, data: dict) -> None:
        name = self._name(name)
        if not isinstance(data, dict):
            raise _invalid_json()
        try:
            raw = (json.dumps(data, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
            if len(raw) > MAX_JSON_BYTES:
                raise _invalid_json()
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise _invalid_json() from None
        self.ensure()
        temporary = ".staging-" + uuid.uuid4().hex + ".json"
        try:
            with self._directory_fd() as directory_fd:
                created = False
                try:
                    self._check_existing(name, directory_fd)
                    fd = self._open(temporary, directory_fd, create=True)
                    created = True
                    with os.fdopen(fd, "wb") as target:
                        target.write(raw)
                        target.flush()
                        os.fsync(target.fileno())
                    self._check_existing(name, directory_fd)
                    if self._windows:
                        os.replace(self.directory / temporary, self.directory / name)
                    else:
                        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    created = False
                    self._check_existing(name, directory_fd)
                    if directory_fd is not None:
                        os.fsync(directory_fd)
                finally:
                    if created:
                        self._unlink(temporary, directory_fd)
        except StoreError:
            raise
        except OSError:
            raise StoreError("storage_write_failed", "The protected file could not be saved and verified safely.") from None

    def remove(self, name: str) -> None:
        name = self._name(name)
        self.ensure()
        try:
            with self._directory_fd() as directory_fd:
                self._check_existing(name, directory_fd)
                try:
                    self._unlink(name, directory_fd)
                except FileNotFoundError:
                    pass
        except StoreError:
            raise
        except OSError:
            raise StoreError("storage_remove_failed", "The protected file could not be removed safely.") from None

    @contextlib.contextmanager
    def lock(self):
        """Exclude concurrent writers without deleting or stealing existing locks."""
        self.ensure()
        try:
            with self._directory_fd() as directory_fd:
                try:
                    fd = self._open(LOCK_NAME, directory_fd, create=True)
                except FileExistsError:
                    raise StoreError("store_busy", "Another operation holds the credential lock. Wait for it to finish; do not delete an active lock.") from None
                identity = os.fstat(fd)
                try:
                    os.write(fd, (json.dumps({"pid": os.getpid()}) + "\n").encode("ascii"))
                    yield
                finally:
                    os.close(fd)
                    try:
                        if self._windows:
                            current = os.stat(self.directory / LOCK_NAME, follow_symlinks=False)
                        else:
                            current = os.stat(LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                            self._unlink(LOCK_NAME, directory_fd)
                    except FileNotFoundError:
                        pass
        except StoreError:
            raise
        except OSError:
            raise StoreError("storage_lock_failed", "The protected credential lock could not be managed safely.") from None
