#!/usr/bin/env python3

import pylink
import time
import _thread
from datetime import datetime
from btmonitor_parser.parser import Parser
import socket
from btmonitor_parser import parser
import multiprocessing as mp
from loguru import logger

def do_parse(udp_stream, p ,data):
    pkt = p.next(data)
    while pkt is not None:
        if pkt.is_btsnoop():
            #print(pkt.to_btsnoop())
            #print(''.join(['\\x%02x' % b for b in pkt.to_ellisys()]))
            udp_stream.sendto(pkt.to_ellisys(), ( "192.168.0.199", 24352 ) )

        elif pkt.opcode == parser.BT_MONITOR_ISO_TX_PKT:
            #TODO write log iso later
            pass
        elif pkt.opcode == parser.BT_MONITOR_NEW_INDEX:
            #TODO write log iso later
            pass
        elif pkt.opcode == parser.BT_MONITOR_OPEN_INDEX:
            #TODO write log iso later
            pass
        else:
            logger.warning(f"Unhandled packet {pkt}")

        pkt = p.next()


def parser_proc(q):
    logger.info( "Parser Process started" )
    udp_stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

    p = Parser()
    
    while True:
        if not p.is_top_buffer_empty():
            print("Reset parser")
            p = Parser()

        data = q.get()
        do_parse(udp_stream, p, data)

    logger.info( "Parser Process Exited" )

class JLinkSession:
    def __init__(self,queue):
        self.client = None
        self.jlink = pylink.JLink()
        self.queue = queue

    def set_client(self,clt):
        self.client = clt

    def start(self):
        self.jlink.open()
        self.jlink.set_tif(pylink.enums.JLinkInterfaces.SWD) 
        self.jlink.connect('NRF5340_XXAA_APP') 
        self.running = True

        print(self.jlink.connected())
        print(self.jlink.core_id())
        print(self.jlink.core_name())

    def start_rtt(self):
        self.running = True
        
        self.jlink.rtt_start()

#print('Please enter rtt write data and click ENTER:')
#writedata = input()
#jlink.rtt_write(0, [ord(x) for x in list(writedata)])

        while True:
            try:
                print( f"up {self.jlink.rtt_get_num_up_buffers()}" )
                break
            except pylink.errors.JLinkRTTException:
                time.sleep(0.1)

        print(self.jlink.rtt_get_buf_descriptor(1, True))

        try:
            while self.running:
                readdata = self.jlink.rtt_read(1, 1024)
                if len(readdata) == 0:
                    time.sleep(0.001)
                else:
                    readdata=bytes(readdata)
                    print( f"Read data len {len(readdata)} {type(readdata[0])}" )
                    #print(''.join(['\\x%02x' % b for b in readdata]))
                    #wr.write(bytes(readdata))
                    #wr.flush()
                    self.queue.put(readdata)

        except Exception:
            print( "Got key in tread, exit it" )

        print( "stop rtt" )
        self.jlink.rtt_stop()

    def stop(self):
        self.jlink.close()

    def interrput(self):
        self.running = False


BTSNOOP_FILE_HDR=bytes([ 0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xea ])



def fwd_proc(js):
    bind_ip = "0.0.0.0"
    bind_port = 27700
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((bind_ip, bind_port))
    server.listen(5)
    print( "[*] Listening on %s:%d" % (bind_ip, bind_port) )
# This is the thread we handle the data from  the client
    while True:
        client, addr = server.accept()
        client.send(BTSNOOP_FILE_HDR)
        js.set_client(client)

def rtt_thread_proc(j):
    while True:
        j.start()
        j.start_rtt()
        j.stop()
        time.sleep(2)

DataQueue = mp.Queue()

js = JLinkSession(DataQueue)

#_thread.start_new_thread(fwd_proc, (js,))
_thread.start_new_thread(rtt_thread_proc, ( js, ))

parser_process = mp.Process(target=parser_proc, args=(DataQueue,))
parser_process.start()

while True:
    input()
    js.interrput()

