# Author: elCapitan
import bz2
import zipfile
import io
import lzma
import gzip

zip_extracted = 0
for i in range(1, 1000):
    if not zip_extracted:
        data = open(f"rabbit\{i - 1}.zip", 'rb').read()
    else:
        data = open(f"rabbit\{i - 1}\flag.txt", 'rb').read()

    if data.startswith(b"BZ"):
        bzip_file = bz2.BZ2File(io.BytesIO(data))
        open(f"rabbit\{i}.zip", 'wb').write(bzip_file.read())
        zip_extracted = 0
    elif data.startswith(b"PK"):
        zip_file = zipfile.ZipFile(io.BytesIO(data))
        zip_file.extractall(f"rabbit\{i}")
        zip_extracted = 1
    elif data.startswith(b"\xfd7z"):
        data = lzma.decompress(data)
        open(f"rabbit\{i}.zip", 'wb').write(data)
        zip_extracted = 0
    elif data.startswith(b"\x1f\x8b"):
        data = gzip.decompress(data)
        open(f"rabbit\{i}.zip", 'wb').write(data)
        zip_extracted = 0
    else:
        print("SHITTTTTTTTTTTTTTTTTTTTTTTTTTTT")