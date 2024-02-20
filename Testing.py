### Testing file, will be deleted


import struct


HDR_DELIM = 0xCA11AB1E
# HDR_DELIM = 0xAB1E
FTR_DELIM = 0xba5eba11
STATUS_DELIM = 0x33
STATUS_NOT_NOACT = 0b11
# STATUS_NOT_NOACT = 0b01
STATUS_TX = 0b10
# STATUS_TX = 0b1111
STATUS_RX = 0b01
# STATUS_RX = 0b1100
STATUS_BAD = 0x70


DISPLAY_FORMAT_CHOICES = {
    'Hex': 'Hex',
    'Binary': 'Binary'
}
SRC_CHOICES = {
    'Peripheral': 'Peripheral',
    'Host': 'Host'
}

STATES = ['HDR_STATE', 'DATA_STATE', 'FTR_STATE', 'NO_STATE', 'BAD_STATUS']

sts_delim = struct.pack('H', STATUS_DELIM)[0:1]
hdr_delim = struct.pack('I', HDR_DELIM)
ftr_delim = struct.pack('I', FTR_DELIM)
sts_not_noact = struct.pack('b', STATUS_NOT_NOACT)[0]
sts_tx = struct.pack('b', STATUS_TX)[0]
sts_rx = struct.pack('b', STATUS_RX)[0]

print("Status Delimiter: 0x", sts_delim.hex())
print("Footer Delimiter: 0x", ftr_delim.hex())
print("Header Delimiter: 0x", hdr_delim.hex())
print(sts_rx)
