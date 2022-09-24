from loguru import logger

import json
import struct

from datetime import datetime

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

ELL_HCI_COMMAND = 0x01
ELL_HCI_TX_DATA = 0x02
ELL_HCI_RX_DATA = 0x82
ELL_HCI_EVENT = 0x84

BTSNOOP_FLAG_MAP = {
        BT_MONITOR_ACL_RX_PKT: Snoop_recv_data ,
        BT_MONITOR_ACL_TX_PKT: Snoop_send_data,
        BT_MONITOR_COMMAND_PKT: Snoop_send_cmd,
        BT_MONITOR_EVENT_PKT: Snoop_recv_evt,
        }

ELL_FLAG_MAP = {
        BT_MONITOR_ACL_RX_PKT: ELL_HCI_RX_DATA ,
        BT_MONITOR_ACL_TX_PKT: ELL_HCI_TX_DATA ,
        BT_MONITOR_COMMAND_PKT: ELL_HCI_COMMAND,
        BT_MONITOR_EVENT_PKT: ELL_HCI_EVENT,
        }

HCI_FLAG_MAP = {
        BT_MONITOR_ACL_RX_PKT: HCI_ACL_Data_packet,
        BT_MONITOR_ACL_TX_PKT: HCI_ACL_Data_packet,
        BT_MONITOR_COMMAND_PKT: HCI_Command_packet,
        BT_MONITOR_EVENT_PKT: HCI_Event_packet,
        }

BTSNOOP_FILE_HDR=bytes([ 0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xea ])

BTSNOOP_PKT_TYPE = set([2,3])

ELL_ServiceId = bytes( [ 0x02, 0x00, 0x01 ] )
ELL_BitRate = bytes( [ 0x80, 0x00, 0x1b, 0x37, 0x4b ] )

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

    def get_ell_flag(self):
        return ELL_FLAG_MAP[self.opcode]

    def to_btsnoop(self):
        if not self.is_btsnoop():
            raise Exception(f"Not a btsnoop compatiable record  {OPCODE[self.opcode]}")

        ret = struct.pack( ">iiiiqb", len(self.data)+1, len(self.data)+1, self.get_snoop_flag(), 0, self.timestamp, self.get_hci_flag() )
        return ret+self.data


    def to_ellisys(self):
        if not self.is_btsnoop():
            raise Exception(f"Not a btsnoop compatiable record  {OPCODE[self.opcode]}")

        ts = datetime.now()

        ts_nano = (( ( ts.hour * 60 + ts.minute ) * 60 + ts.second ) * 1000000 + ts.microsecond ) * 1000
        
        date_ts = struct.pack( "<bhbb", 0x02, ts.year, ts.month, ts.day ) + struct.pack("<q", ts_nano)[0:6]

        hci_packet_type_obj = bytes([ 0x81, self.get_ell_flag(), 0x82 ])

        return ELL_ServiceId + date_ts + ELL_BitRate + hci_packet_type_obj + self.data

class Parser:
    def __init__(self):
        self.bytes_list = []
        self.offset = 0
        self.prev_offset = 0
        self.start_offset = 0
        self.state = self._parse()

    @property
    def bytes(self):
        return self.bytes_list[0]

    def push_bytes(self, *datas):
        self.bytes_list.extend(datas)

    def _load_next_buf(self):
        #Make bytes is not none if possible
        self.bytes_list.pop()

        self.offset = 0
        while not self.bytes_list:
            #logger.debug("empty bytes_list")
            yield None

    def is_top_buffer_empty(self):
        return not( ( self.bytes_list ) and ( self.offset < len(self.bytes) ) )

    def _next_char(self):
        while self.is_top_buffer_empty():
            #logger.debug("buffer is empty")
            yield from self._load_next_buf()

        if self.bytes is not None:
            if self.offset < len(self.bytes):
                ret = self.bytes[self.offset]
                #logger.debug("offset 0x%x : 0x%x " % ( self.offset, ret ))
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

    def _int16(self):
        b1 = yield from self._next_char()
        b2 = yield from self._next_char()

        return b2*256+b1


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


    def _try_recover(self):
        logger.warning("try recover at 0x%x" % self.offset )
        while True:
            b = yield from self._next_char()
            if 0x41 == b:
                b = yield from self._next_char()
                if 0x59 == b:
                    logger.warning("recover successful at 0x%x" % self.offset )
                    return;

    def _peek(self, offset, length):
        while True:
            init_offset = self.offset
            current_length = length
            current_offset = offset
            find_start_buf = True
            result = []
            for buf in self.bytes_list:
                #print(buf)
                if find_start_buf:
                    if init_offset + current_offset > len(buf):
                        current_offset -= len(buf) - init_offset
                        init_offset = 0
                    else:
                        find_start_buf = False

                #print( f"<<{find_start_buf}  {current_offset} {init_offset} {current_length}")

                if not find_start_buf:
                    if init_offset + current_offset + current_length >= len(buf):
                        result.append( buf[init_offset+current_offset:] )
                        current_length -= len(buf) - init_offset - current_offset
                        init_offset = 0
                        current_offset = 0
                    else:
                        result.append( buf[init_offset+current_offset:init_offset+current_offset+current_length] )
                        current_length = 0
                        break


            #print(f"clen {current_length} : {result}")

            if current_length == 0:
                return b''.join(result)
            else:
                yield None

    def _peek_short(self, offset):
        data = yield from self._peek(offset, 2)
        return 256 * data[1] + data[0] 

    def _peek_int32(self, offset):
        data = yield from self._peek(offset, 4)
        return 256 * ( 256 * ( 256 * data[3] + data[2] ) + data[1] ) + data[0] 
        
    def _peek_int16(self, offset):
        data = yield from self._peek(offset, 2)
        return 256 * data[1] + data[0] 

    def _pkt(self):
        # parse bt_monitor_hdr
        self.prev_offset = self.start_offset
        self.start_offset = self.offset
        magic = yield from self._int16()
        if magic != 0x5941:
            #4e47:
            logger.error("Invalid magic 0x%x should be 0x%x at start offset 0x%x, prev offset 0x%x" % ( magic, 0x5941, self.start_offset, self.prev_offset ) )
            yield from self._try_recover()

        valid_pkt = False
        
        while not valid_pkt:
             data_len = yield from self._peek_short(0)
             next_magic = yield from self._peek_int16(data_len+2)

             if next_magic is None or next_magic == 0x4e47:
                 valid_pkt = True
             else:
                 logger.error("Invalid magic 0x%x should be 0x%x at offset 0x%x, at end of pkt start at offset 0x%x" % ( magic, 0x4e47, self.offset, self.start_offset ) )
                 yield from self._try_recover()

        data_len = yield from self._short()
        opcode = yield from self._short()
            
        if opcode >= 20:
            raise Exception("Invalid opcode 0x%x" % opcode )

        flag = yield from self._next_char()
        hdr_len = yield from self._next_char()
        (ext_type_field, ts, ext_hdr_data) = yield from self._pkt_hdr_ext(hdr_len)
            
        # parse bt_monitor_data
        data = yield from self._raw_data(data_len-4-hdr_len)

        magic2 = yield from self._int16()

        #logger.info( "Pkt at 0x%x len %d" % ( self.start_offset, data_len ) )

        return BtPkt( data_len, opcode, flag, hdr_len, ts, ext_hdr_data, data )

    def _raw_data(self,length):
        #logger.debug(f"load raw data len {length}")
        data = bytearray(length)
        i = 0
        while i < length:
            data[i] = yield from self._next_char()
            i += 1

        return data

#  import sys

#  parser = Parser()

#  with open("bt.log", "wb") as btlog:
    #  btlog.write(BTSNOOP_FILE_HDR)

    #  with open(sys.argv[1], "rb") as fb:
        #  data = fb.read()
        #  pkt = parser.next(data)
        #  while pkt is not None:
            #  if pkt.is_btsnoop():
                #  btlog.write(pkt.to_btsnoop())
            #  elif pkt.opcode == BT_MONITOR_ISO_TX_PKT:
                #  #TODO write log iso later
                #  pass
            #  elif pkt.opcode == BT_MONITOR_NEW_INDEX:
                #  #TODO write log iso later
                #  pass
            #  elif pkt.opcode == BT_MONITOR_OPEN_INDEX:
                #TODO write log iso later
            #    pass
            #  else:
                #  logger.warning(f"Unhandled packet {pkt}")

            #  pkt = parser.next()
