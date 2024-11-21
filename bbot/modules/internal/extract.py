import zipfile

import bz2
import lzma

# import expak
import tarfile

# import rarfile
import py7zr
import zstandard as zstd
import lz4.frame

# import shutil

from pathlib import Path
from bbot.modules.internal.base import BaseInternalModule


class extract(BaseInternalModule):
    watched_events = ["FILESYSTEM"]
    produced_events = ["FILESYSTEM"]
    flags = ["passive"]
    meta = {
        "description": "Extract different types of files into folders on the filesystem",
        "created_date": "2024-11-04",
        "author": "@domwhewell-sage",
    }
    # deps_pip = ["rarfile", "py7zr", "zstandard", "lz4"]

    async def setup(self):
        self.compression_methods = {
            "zip": self.extract_zip_file,
            "bzip2": lambda path, output_dir: self.extract_bz2_file(path, output_dir / "content.txt"),
            "xz": lambda path, output_dir: self.extract_xz_file(path, output_dir / "content.txt"),
            "7z": self.extract_7z_file,
            # "rar": self.extract_rar_file,
            "lzma": lambda path, output_dir: self.extract_lzma_file(path, output_dir / "content.txt"),
            #     "compress": lambda path, output_dir: self.extract_compress_file(path, output_dir / "content.txt"),
            "zstd": lambda path, output_dir: self.extract_zstd_file(path, output_dir / "content.txt"),
            "lz4": lambda path, output_dir: self.extract_lz4_file(path, output_dir / "content.txt"),
            "tar": self.extract_tar_file,
            #     "pak": self.extract_pak_file,
            #     "lha": self.extract_lha_file,
            #     "arj": self.extract_arj_file,
            #     "cab": self.extract_cab_file,
            #     "sit": self.extract_sit_file,
            #     "binhex": lambda path, output_dir: self.extract_binhex_file(path, output_dir / "content.txt"),
            #     "lrzip": lambda path, output_dir: self.extract_lrzip_file(path, output_dir / "content.txt"),
            #     "alz": self.extract_alz_file,
            "tgz": self.extract_gzip_file,
            "gzip": self.extract_gzip_file,
            #     "lzip": lambda path, output_dir: self.extract_lzip_file(path, output_dir / "content.txt"),
            #     "palm": lambda path, output_dir: self.extract_palm_file(path, output_dir / "content.txt"),
            #     "cpio": self.extract_cpio_file,
            #     "pack200": lambda path, output_dir: self.extract_pack200_file(path, output_dir / "content.txt"),
            #     "par2": lambda path, output_dir: self.extract_par2_file(path, output_dir / "content.txt"),
            #     "ar": self.extract_ar_file,
            #     "qpress": self.extract_qpress_file,
            #     "xar": self.extract_xar_file,
            #     "ace": self.extract_ace_file,
            #     "zoo": self.extract_zoo_file,
            #     "arc": self.extract_arc_file,
        }
        return True

    async def filter_event(self, event):
        if "file" in event.tags:
            if not event.data["compression"] in self.compression_methods:
                return False, f"Extract unable to handle file type: {event.data['compression']}, {event.data['path']}"
        else:
            return False, "Event is not a file"
        return True

    async def handle_event(self, event):
        compression_format = event.data["compression"]
        path = Path(event.data["path"])
        output_dir = path.parent / path.name.replace(".", "_")
        self.helpers.mkdir(output_dir)

        # Use the appropriate extraction method based on the file type
        self.info(f"Extracting {path} to {output_dir}")
        extract_method = self.compression_methods.get(compression_format)
        success = extract_method(path, output_dir)

        # If the extraction was successful, emit the event
        if success:
            await self.emit_event(
                {"path": str(output_dir)},
                "FILESYSTEM",
                tags="folder",
                parent=event,
                context=f'extracted "{path}" to: {output_dir}',
            )
        else:
            output_dir.rmdir()

    def extract_zip_file(self, path, output_dir):
        try:
            with zipfile.ZipFile(path, "r") as zip_ref:
                zip_ref.extractall(output_dir)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    def extract_bz2_file(self, path, output_file):
        try:
            with bz2.BZ2File(path, "rb") as file:
                content = file.read()
                with open(output_file, "wb") as f:
                    f.write(content)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    def extract_xz_file(self, path, output_file):
        try:
            with lzma.open(path, "rb") as file:
                content = file.read()
                with open(output_file, "wb") as f:
                    f.write(content)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    def extract_7z_file(self, path, output_dir):
        try:
            with py7zr.SevenZipFile(path, mode="r") as z:
                z.extractall(path=output_dir)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    # def extract_rar_file(self, path, output_dir):
    #     try:
    #         with rarfile.RarFile(path, "r") as rar_ref:
    #             rar_ref.extractall(output_dir)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True

    def extract_lzma_file(self, path, output_file):
        try:
            with lzma.open(path, "rb") as file:
                content = file.read()
                with open(output_file, "wb") as f:
                    f.write(content)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    #
    # def extract_compress_file(self, path, output_file):
    #     try:
    #         with open(path, "rb") as file:
    #             content = file.read()
    #             with open(output_file, "wb") as f:
    #                 f.write(content)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    def extract_zstd_file(self, path, output_file):
        try:
            with open(path, "rb") as file:
                dctx = zstd.ZstdDecompressor()
                content = dctx.decompress(file.read())
                with open(output_file, "wb") as f:
                    f.write(content)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    def extract_lz4_file(self, path, output_file):
        try:
            with lz4.frame.open(path, "rb") as file:
                content = file.read()
                with open(output_file, "wb") as f:
                    f.write(content)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    def extract_tar_file(self, path, output_dir):
        try:
            with tarfile.open(path, "r") as tar_ref:
                tar_ref.extractall(output_dir)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True

    #
    # def extract_pak_file(self, path, output_dir):
    #     try:
    #         expak.extract_resources(path, output_dir)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    # def extract_lha_file(self, path, output_dir):
    #     try:
    #         shutil.unpack_archive(path, output_dir)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    # def extract_arj_file(self, path, output_dir):
    #     try:
    #         shutil.unpack_archive(path, output_dir)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    # def extract_cab_file(self, path, output_dir):
    #     try:
    #         shutil.unpack_archive(path, output_dir)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    # def extract_sit_file(self, path, output_dir):
    #     try:
    #         shutil.unpack_archive(path, output_dir)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    # def extract_binhex_file(self, path, output_file):
    #     try:
    #         with open(path, "rb") as file:
    #             content = file.read()
    #             with open(output_file, "wb") as f:
    #                 f.write(content)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    # def extract_lrzip_file(self, path, output_file):
    #     try:
    #         with open(path, "rb") as file:
    #             content = file.read()
    #             with open(output_file, "wb") as f:
    #                 f.write(content)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    # def extract_alz_file(self, path, output_dir):
    #     try:
    #         shutil.unpack_archive(path, output_dir)
    #     except Exception as e:
    #         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
    #         return False
    #     return True
    #
    def extract_gzip_file(self, path, output_dir):
        try:
            with tarfile.open(path, "r:gz") as tar_ref:
                tar_ref.extractall(output_dir)
        except Exception as e:
            self.warning(f"Error extracting {path}. Exception: {repr(e)}")
            return False
        return True


#
# def extract_lzip_file(self, path, output_file):
#     try:
#         with open(path, "rb") as file:
#             content = file.read()
#             with open(output_file, "wb") as f:
#                 f.write(content)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_palm_file(self, path, output_file):
#     try:
#         with open(path, "rb") as file:
#             content = file.read()
#             with open(output_file, "wb") as f:
#                 f.write(content)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_cpio_file(self, path, output_dir):
#     try:
#         shutil.unpack_archive(path, output_dir)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_pack200_file(self, path, output_file):
#     try:
#         with open(path, "rb") as file:
#             content = file.read()
#             with open(output_file, "wb") as f:
#                 f.write(content)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_par2_file(self, path, output_file):
#     try:
#         with open(path, "rb") as file:
#             content = file.read()
#             with open(output_file, "wb") as f:
#                 f.write(content)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_ar_file(self, path, output_dir):
#     try:
#         shutil.unpack_archive(path, output_dir)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_qpress_file(self, path, output_dir):
#     try:
#         shutil.unpack_archive(path, output_dir)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_xar_file(self, path, output_dir):
#     try:
#         shutil.unpack_archive(path, output_dir)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_ace_file(self, path, output_dir):
#     try:
#         shutil.unpack_archive(path, output_dir)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_zoo_file(self, path, output_dir):
#     try:
#         shutil.unpack_archive(path, output_dir)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
#
# def extract_arc_file(self, path, output_dir):
#     try:
#         shutil.unpack_archive(path, output_dir)
#     except Exception as e:
#         self.warning(f"Error extracting {path}. Exception: {repr(e)}")
#         return False
#     return True
