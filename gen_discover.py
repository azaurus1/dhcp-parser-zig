import struct, random

xid = random.randint(0, 0xFFFFFFFF)

header = struct.pack(
    '!BBBBIHH4s4s4s4s16s64s128s',
    1,
    1,
    6,
    0,
    xid,
    0,
    0x8000,
    b'\x00'*4,
    b'\x00'*4,
    b'\x00'*4,
    b'\x00'*4,
    b'\x84\x47\x09\x4b\xfe\x48' + b'\x00'*10,
    b'\x00'*64,
    b'\x00'*128
)

options = (
    b'\x63\x82\x53\x63'
    b'\x35\x01\x01'
    b'\x3d\x07\x01\x84\x47\x09\x4b\xfe\x48'
    b'\x37\x04\x01\x03\x06\x2a'
    b'\xff'
)

open('discover.bin', 'wb').write(header + options)
print(f'wrote {len(header + options)} bytes')
