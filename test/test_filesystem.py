"""The fsspec contract, exercised against a real federation."""

from __future__ import annotations

import pytest

from pelicanfs_native import PelicanClientError


def test_version_is_reported(native_fs):
    from pelicanfs_native import version

    assert version()


def test_info_on_a_file(native_fs, federation):
    info = native_fs.info(federation.path("hello_world.txt"))
    assert info["type"] == "file"
    assert info["size"] == len(b"Hello, World!")
    assert info["name"] == federation.path("hello_world.txt")


def test_info_on_a_collection(native_fs, federation):
    info = native_fs.info(federation.path("subdir"))
    assert info["type"] == "directory"


def test_info_on_a_missing_object_raises(native_fs, federation):
    with pytest.raises(FileNotFoundError):
        native_fs.info(federation.path("no-such-object"))


def test_exists(native_fs, federation):
    assert native_fs.exists(federation.path("hello_world.txt"))
    assert not native_fs.exists(federation.path("no-such-object"))


def test_ls_detail(native_fs, federation):
    entries = native_fs.ls(federation.namespace, detail=True)
    by_name = {e["name"]: e for e in entries}
    assert federation.path("hello_world.txt") in by_name
    assert by_name[federation.path("subdir")]["type"] == "directory"
    # A listing must not include the collection itself, or find/walk
    # recurse forever.
    assert federation.namespace not in by_name


def test_ls_names_only(native_fs, federation):
    names = native_fs.ls(federation.namespace, detail=False)
    assert all(isinstance(n, str) for n in names)
    assert federation.path("hello_world.txt") in names


def test_cat_file_whole(native_fs, federation):
    assert native_fs.cat_file(federation.path("hello_world.txt")) == b"Hello, World!"


def test_cat_file_empty_object(native_fs, federation):
    assert native_fs.cat_file(federation.path("empty.txt")) == b""


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [
        (0, 5, b"Hello"),
        (7, 12, b"World"),
        (7, None, b"World!"),
        (None, 5, b"Hello"),
        (0, 0, b""),
        # Past the end of a 13-byte object: a short read, not an error.
        (0, 1000, b"Hello, World!"),
        (1000, 1010, b""),
    ],
)
def test_cat_file_ranges(native_fs, federation, start, end, expected):
    assert native_fs.cat_file(federation.path("hello_world.txt"), start, end) == expected


def test_open_and_read(native_fs, federation):
    with native_fs.open(federation.path("hello_world.txt"), "rb") as fh:
        assert fh.read() == b"Hello, World!"


def test_open_seek_and_partial_read(native_fs, federation):
    with native_fs.open(federation.path("hello_world.txt"), "rb") as fh:
        fh.seek(7)
        assert fh.read(5) == b"World"


def test_open_binary_object_round_trips(native_fs, federation):
    expected = (federation.export_dir / "binary.bin").read_bytes()
    with native_fs.open(federation.path("binary.bin"), "rb") as fh:
        assert fh.read() == expected


def test_get_file(native_fs, federation, tmp_path):
    target = tmp_path / "downloaded.txt"
    native_fs.get_file(federation.path("hello_world.txt"), str(target))
    assert target.read_bytes() == b"Hello, World!"


def test_put_file_and_read_back(native_fs, federation, tmp_path):
    source = tmp_path / "upload.txt"
    source.write_bytes(b"uploaded payload")
    remote = federation.path("uploaded.txt")
    native_fs.put_file(str(source), remote)
    assert native_fs.cat_file(remote) == b"uploaded payload"


def test_pipe_file_and_remove(native_fs, federation):
    remote = federation.path("piped.txt")
    native_fs.pipe_file(remote, b"piped payload")
    assert native_fs.cat_file(remote) == b"piped payload"
    native_fs.rm_file(remote)
    assert not native_fs.exists(remote)


def test_write_through_open(native_fs, federation):
    remote = federation.path("written.txt")
    with native_fs.open(remote, "wb") as fh:
        fh.write(b"written payload")
    assert native_fs.cat_file(remote) == b"written payload"


def test_find_walks_the_namespace(native_fs, federation):
    found = native_fs.find(federation.namespace)
    assert federation.path("hello_world.txt") in found
    assert federation.path("subdir/nested.txt") in found


def test_mkdir_is_refused(native_fs, federation):
    with pytest.raises(NotImplementedError):
        native_fs.mkdir(federation.path("newdir"))


def test_a_foreign_federation_is_refused(native_fs):
    with pytest.raises(ValueError, match="bound to"):
        native_fs.info("pelican://not-this-federation.example/ns/obj")


def test_errors_carry_the_pelican_code(native_fs, federation):
    with pytest.raises(PelicanClientError) as excinfo:
        native_fs.info(federation.path("no-such-object"))
    assert excinfo.value.code
