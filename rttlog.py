#!/usr/bin/env python3

import pylink
import time
import _thread
from datetime import datetime

class JLinkSession:
    def start(self):
        self.jlink = pylink.JLink()
        self.jlink.open()
        self.jlink.set_tif(pylink.enums.JLinkInterfaces.SWD) 
        self.jlink.connect('NRF5340_XXAA_APP') 

        print(self.jlink.connected())
        print(self.jlink.core_id())
        print(self.jlink.core_name())

    def start_rtt(self):
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

        with open( datetime.now().strftime("%Y%m%d_%H%M%S") + ".log", "wb" ) as wr: 
            while True:
                readdata = self.jlink.rtt_read(1, 1024)
                if len(readdata) == 0:
                    time.sleep(0.1)
                else:
                    readdata=bytes(readdata)
                    print( f"Read data len {len(readdata)} {type(readdata[0])} {readdata}" )
                    wr.write(bytes(readdata))
                    wr.flush()

        self.jlink.rtt_stop()

    def stop(self):
        self.jlink.close()



def thread_proc(j):
    j.start_rtt()


while True:
    js = JLinkSession()

    js.start()

    _thread.start_new_thread(thread_proc, ( js, ))

    input()

    js.stop()


