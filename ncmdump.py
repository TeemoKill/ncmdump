# coding = utf-8

import binascii
import struct
import base64
import json
import sys
import os

from concurrent.futures import ThreadPoolExecutor

from Crypto.Cipher import AES

__author__ = 'TeemoKill'
__date__ = '2023/03/17'


# hex to string
# core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
# meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
CORE_KEY = b"hzHRAmso5kInbaxW"
META_KEY = b"#14ljk_!\\]&0U<'("


def unpad(s):
    return s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]


def getkey(index, key_box):
    j = (index + 1) & 0xff
    return key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]


class ExtractTask:
    def __init__(self, ncm_directory, file_name, output_path):
        self.ncm_directory = ncm_directory
        self.file_name = file_name
        self.output_path = output_path

    def dump(self):
        file_path = os.path.join(self.ncm_directory, self.file_name)
        ncm_file = open(file_path, 'rb')
        ncm_header = ncm_file.read(8)

        # string to hex
        assert binascii.b2a_hex(ncm_header) == b'4354454e4644414d'

        ncm_file.seek(2, 1)
        key_length = ncm_file.read(4)
        key_length = struct.unpack('<I', bytes(key_length))[0]

        # TODO: optimize
        # key_data = ncm_file.read(key_length)
        # key_data_array = bytearray(key_data)
        # for i in range(0, len(key_data_array)):
        #     key_data_array[i] ^= 0x64
        # key_data = bytes(key_data_array)

        key_data = bytes(map(lambda byte: byte ^ 0x64, bytearray(ncm_file.read(key_length))))

        cryptor = AES.new(CORE_KEY, AES.MODE_ECB)
        key_data = unpad(cryptor.decrypt(key_data))[17:]
        key_length = len(key_data)
        key_data = bytearray(key_data)
        key_box = bytearray(range(256))
        c = 0
        last_byte = 0
        key_offset = 0
        for i in range(256):
            swap = key_box[i]
            c = (swap + last_byte + key_data[key_offset]) & 0xff
            key_offset += 1
            if key_offset >= key_length:
                key_offset = 0
            key_box[i] = key_box[c]
            key_box[c] = swap
            last_byte = c
        meta_length = ncm_file.read(4)
        meta_length = struct.unpack('<I', bytes(meta_length))[0]
        # meta_data = ncm_file.read(meta_length)
        # meta_data_array = bytearray(meta_data)
        # for i in range(0, len(meta_data_array)):
        #     meta_data_array[i] ^= 0x63
        # meta_data = bytes(meta_data_array)
        # meta_data = base64.b64decode(meta_data[22:])
        meta_data = base64.b64decode(
            bytes(map(lambda byte: byte ^ 0x63, bytearray(ncm_file.read(meta_length))))[22:],
        )

        cryptor = AES.new(META_KEY, AES.MODE_ECB)
        meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
        meta_data = json.loads(meta_data)
        crc32 = ncm_file.read(4)
        crc32 = struct.unpack('<I', bytes(crc32))[0]
        ncm_file.seek(5, 1)
        image_size = ncm_file.read(4)
        image_size = struct.unpack('<I', bytes(image_size))[0]
        image_data = ncm_file.read(image_size)

        output_filename = '.'.join((self.file_name.rstrip(".ncm"), meta_data['format']))
        output_file = open(os.path.join(self.output_path, output_filename), 'wb')
        while True:
            raw_bytes = bytearray(ncm_file.read(0x8000))
            # chunk_length = len(chunk)
            if not raw_bytes:
                break
            # for i in range(1, chunk_length+1):
            #     j = i & 0xff
            #     chunk[i-1] ^= key_box[(key_box[j] + key_box[(key_box[j] + j) & 0xff]) & 0xff]
            chunk = bytearray(map(lambda i: i[1] ^ getkey(i[0], key_box), enumerate(raw_bytes)))
            output_file.write(chunk)
        output_file.close()
        ncm_file.close()

        return self.file_name


if __name__ == '__main__':
    ncm_dir = sys.argv[1]
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    else:
        output_dir = os.path.join(os.getcwd(), "output")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    task_list = [ExtractTask(ncm_dir, filename, output_dir) for filename in os.listdir(ncm_dir) if filename.endswith(".ncm")]
    for i, task in enumerate(task_list):
        print(f"{i}: {task.file_name}")

    print(f"-------- start extracting {len(task_list)} files --------")

    executor = ThreadPoolExecutor(max_workers=4)
    for result in executor.map(lambda t: t.dump(), task_list):
        print(f"[success]: {result}")

