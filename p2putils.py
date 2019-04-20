import ctypes
import struct
import sys
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Project depends on PyCrypto
# https://pycryptodome.readthedocs.io/en/latest/src/installation.html

# data portion is not included in header
# |   unsigned   |      unsigned     |  unsigned  |    signed     |  unsigned   | binary data
# |   4 bytes    |       4 bytes     |   4 bytes  |   4 bytes     |   2 bytes   | ? bytes
# | source_port  | destination_port  | checksum   | sequence_num  | packet_size |  data
packet_ack_format = "i"
packet_header_format = "3I{}I".format(packet_ack_format)

# header length in bytes
packet_header_size = struct.calcsize(packet_header_format)

# amount of time in seconds for packet loss detection
packet_transfer_timeout = 4

# ONLY change if needed
cipher_block_size = 32  # in bytes

# use for testing small packets (slower + longer transfer time)
use_mtu_read_size = False

# can set to timeout from util (4) if needed
transfer_timeout = 6

if use_mtu_read_size:
    # file read size
    udp_mtu_size = 128
    packet_read_size = 81
    receive_buffer = udp_mtu_size
else:
    udp_mtu_size = 2**11
    packet_read_size = 2**11
    receive_buffer = 2**12

# if changed to custom val, need to be careful of not exceeding receive_buffer size
# if exceeded, receiver will throw an exception
file_read_size = udp_mtu_size


# Cite: https://gist.github.com/oysstu/68072c44c02879a2abf94ef350d1c7c6
def checksum2(data):
    return (ctypes.c_ushort(int(zlib.crc32(data) % 2**32))).value


def aes_read_file(session_key, file_path, source_port, destination_port):
    input_file = None
    file_packets = []

    seq_num = 0
    block_size = cipher_block_size

    iv = get_random_bytes(16)

    try:
        input_file = open(file_path, 'rb')

        while True:
            if use_mtu_read_size:
                file_bytes_read = input_file.read(udp_mtu_size - block_size - 24)
            else:
                file_bytes_read = input_file.read(file_read_size)

            if not file_bytes_read:
                break

            # encryption
            encryption_suite = AES.new(session_key, AES.MODE_CBC, iv)
            cipher_text = encryption_suite.encrypt(pad(file_bytes_read, block_size))

            cipher_text_len = len(cipher_text)
            iv_len = len(iv)

            str_format = "LL{}s{}s".format(cipher_text_len, iv_len)
            str_pack = struct.pack(str_format, cipher_text_len, iv_len, cipher_text, iv)

            packet = create_packet(source_port, destination_port, seq_num, str_pack)
            file_packets.append(packet)
            seq_num += 1

    except() as e:
        print("Failed to open file: {}; err: {}".format(file_path, e))
        sys.exit(-1)

    finally:
        if input_file is not None:
            input_file.close()

    return file_packets


def create_packet(source_port, destination_port, sequence_num, data):
    data_size = len(data)

    data_format = "{}s".format(data_size)

    packet_struct_format = packet_header_format + data_format

    packet_size_bytes = struct.calcsize(packet_struct_format)

    packet_data_bytes = data

    packet_data_struct = struct.pack(data_format, packet_data_bytes)

    packet_chksum = checksum2(packet_data_struct)

    packet_struct = struct.pack(packet_struct_format, source_port, destination_port, packet_chksum,
                                sequence_num, packet_size_bytes, packet_data_bytes)

    return packet_struct


def unpack_packet(packet):
    unpack_header = struct.unpack(packet_header_format, packet[:packet_header_size])
    # unpack_header = struct.unpack(packet_header_format, packet[:20])
    # unpack_header = struct.unpack(packet_header_format, packet[:14])

    unpack_packet_size = unpack_header[-1]

    unpack_data_size = unpack_packet_size - packet_header_size

    unpack_packet = struct.unpack("{}{}s".format(packet_header_format, unpack_data_size), packet)

    return unpack_packet


def pack_ack(packet):
    return struct.pack(packet_ack_format, packet[-3])


def unpack_ack(ack_bytes):
    return struct.unpack(packet_ack_format, ack_bytes)[0]
