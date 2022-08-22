from loguru import logger

import json
import struct

BT_MONITOR_NEW_INDEX = 0 
BT_MONITOR_DEL_INDEX = 1 
BT_MONITOR_COMMAND_PKT = 2 
BT_MONITOR_EVENT_PKT = 3 
BT_MONITOR_ACL_TX_PKT = 4 
BT_MONITOR_ACL_RX_PKT = 5 
BT_MONITOR_SCO_TX_PKT = 6 
BT_MONITOR_SCO_RX_PKT = 7 
BT_MONITOR_OPEN_INDEX = 8 
BT_MONITOR_CLOSE_INDEX = 9 
BT_MONITOR_INDEX_INFO = 10 
BT_MONITOR_VENDOR_DIAG = 11 
BT_MONITOR_SYSTEM_NOTE = 12 
BT_MONITOR_USER_LOGGING = 13 
BT_MONITOR_ISO_TX_PKT = 18 
BT_MONITOR_ISO_RX_PKT = 19 
BT_MONITOR_NOP = 255


OPCODE={
    0:"BT_MONITOR_NEW_INDEX", 
    1:"BT_MONITOR_DEL_INDEX", 
    2:"BT_MONITOR_COMMAND_PKT", 
    3:"BT_MONITOR_EVENT_PKT", 
    4:"BT_MONITOR_ACL_TX_PKT", 
    5:"BT_MONITOR_ACL_RX_PKT", 
    6:"BT_MONITOR_SCO_TX_PKT", 
    7:"BT_MONITOR_SCO_RX_PKT", 
    8:"BT_MONITOR_OPEN_INDEX", 
    9:"BT_MONITOR_CLOSE_INDEX", 
    10:"BT_MONITOR_INDEX_INFO", 
    11:"BT_MONITOR_VENDOR_DIAG", 
    12:"BT_MONITOR_SYSTEM_NOTE", 
    13:"BT_MONITOR_USER_LOGGING", 
    18:"BT_MONITOR_ISO_TX_PKT", 
    19:"BT_MONITOR_ISO_RX_PKT", 
    255:"BT_MONITOR_NOP",
}

HCI_Command_packet = 1
HCI_ACL_Data_packet = 2
HCI_Synchronous_Data_packet = 3
HCI_Event_packet = 4
HCI_ISO_Data_packet = 5

Snoop_send_data = 0
Snoop_recv_data = 1
Snoop_send_cmd = 2
Snoop_recv_evt = 3

BTSNOOP_FLAG_MAP = {
        BT_MONITOR_ACL_RX_PKT: Snoop_recv_data ,
        BT_MONITOR_ACL_TX_PKT: Snoop_send_data,
        BT_MONITOR_COMMAND_PKT: Snoop_send_cmd,
        BT_MONITOR_EVENT_PKT: Snoop_recv_evt,
        }

HCI_FLAG_MAP = {
        BT_MONITOR_ACL_RX_PKT: HCI_ACL_Data_packet,
        BT_MONITOR_ACL_TX_PKT: HCI_ACL_Data_packet,
        BT_MONITOR_COMMAND_PKT: HCI_Command_packet,
        BT_MONITOR_EVENT_PKT: HCI_Event_packet,
        }

BTSNOOP_FILE_HDR=bytes([ 0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xea ])

BTSNOOP_PKT_TYPE = set([2,3])

class BtPkt:
    def __init__(self, data_len, opcode, flag, hdr_len, timestamp, ext_hdr_data, data):
        self.data_len = data_len
        self.opcode = opcode
        self.flag = flag
        self.hdr_len = hdr_len
        self.timestamp = timestamp
        self.ext_hdr_data = ext_hdr_data
        self.data = data

    def __str__(self):
        return f"BtPkt {OPCODE[self.opcode]} at {self.timestamp} {len(self.data)} {self.data}"

    def is_btsnoop(self):
        return self.opcode in BTSNOOP_PKT_TYPE

    def get_snoop_flag(self):
        return BTSNOOP_FLAG_MAP[self.opcode]

    def get_hci_flag(self):
        return HCI_FLAG_MAP[self.opcode]

    def to_btsnoop(self):
        if not self.is_btsnoop():
            raise Exception(f"Not a btsnoop compatiable record  {OPCODE[self.opcode]}")

        ret = struct.pack( ">iiiiqb", len(self.data)+1, len(self.data)+1, self.get_snoop_flag(), 0, self.timestamp, self.get_hci_flag() )
        return ret+self.data
            


class Parser:
    def __init__(self):
        self.bytes = None 
        self.bytes_list = []
        self.offset = 0
        self.state = self._parse()

    def push_bytes(self, *datas):
        self.bytes_list.extend(datas)

    def _load_bytes(self):
        #Make bytes is not none if possible
        self.bytes = None
        self.offset = 0
        while not self.bytes_list:
            #logger.debug("empty bytes_list")
            yield None

        if self.bytes_list:
            self.bytes = self.bytes_list.pop(0)

    def is_buffer_empty(self):
        return ( self.bytes == None ) or ( self.offset >= len(self.bytes) )

    def _next_char(self):
        while self.is_buffer_empty():
            #logger.debug("buffer is empty")
            yield from self._load_bytes()

        if self.bytes is not None:
            if self.offset < len(self.bytes):
                #logger.debug("offset 0x%x " % self.offset)
                ret = self.bytes[self.offset]
                self.offset += 1
                return ret

    def next(self, *data):
        self.push_bytes(*data)
        ret = next(self.state)
        return ret

    def _parse(self):
        while True:
            #logger.debug("in _parse")
            pkt = yield from self._pkt()
            yield pkt

    def _short(self):
        low_byte = yield from self._next_char()
        high_byte = yield from self._next_char()
        return low_byte + high_byte * 256

    def _int32(self):
        b1 = yield from self._next_char()
        b2 = yield from self._next_char()
        b3 = yield from self._next_char()
        b4 = yield from self._next_char()

        return ((( b4 * 256  + b3)*256)+b2)*256+b1

    def _pkt_hdr_ext(self,hdr_len):
        type_field = yield from self._next_char()
        if type_field != 8:
            raise Exception(f"Invalid ext hdr field, expect 8 (ts_field), but got ${type_field}")

        ts = yield from self._int32()


        if hdr_len > 5:
            ext_data = yield from self._raw_data( hdr_len - 5 )
        else: 
            ext_data = bytearray()

        return (type_field, ts, ext_data)

        

        

    def _pkt(self):
        # parse bt_monitor_hdr
        data_len = yield from self._short()
        opcode = yield from self._short()
        
        if opcode >= 20:
            raise Exception(f"Invalid opcode {opcode}")

        flag = yield from self._next_char()
        hdr_len = yield from self._next_char()
        (ext_type_field, ts, ext_hdr_data) = yield from self._pkt_hdr_ext(hdr_len)
        
        # parse bt_monitor_data
        data = yield from self._raw_data(data_len-4-hdr_len)

        return BtPkt( data_len, opcode, flag, hdr_len, ts, ext_hdr_data, data )

    def _raw_data(self,length):
        #logger.debug(f"load raw data len {length}")
        data = bytearray(length)
        i = 0
        while i < length:
            data[i] = yield from self._next_char()
            i += 1

        return data


import sys

parser = Parser()

with open("bt.log", "wb") as btlog:
    btlog.write(BTSNOOP_FILE_HDR)

    with open(sys.argv[1], "rb") as fb:
        data = fb.read()
        pkt = parser.next(data)
        while pkt is not None:
            if pkt.is_btsnoop():
                btlog.write(pkt.to_btsnoop())
            else:
                logger.warn(f"Unhandled packet {pkt}")

            pkt = parser.next()

