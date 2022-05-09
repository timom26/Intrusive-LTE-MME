from typing import Tuple
import unittest
from time import sleep
from EPC import *
import threading
#before runnning the tests, run the EPC

class EPCTesting(unittest.TestCase):

    def attachToServer(self):
        sleep(1)
        sctp_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        sctp_socket.connect(("127.0.0.42",36412))
        sctp_socket.close()
    def attachToServerAndSendS1AP(self):
        sleep(1)
        sctp_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        sctp_socket.connect(("127.0.0.42",36412))
        "s1 init"
        sctp_socket.sctp_send(bytes.fromhex("0011002d000004003b00080000f110000019b0003c400a0380737273656e62303100400007000001c000f1100089400140"), ppid=socket.htonl(18))
        fromaddr, flags, msgret, notif = sctp_socket.sctp_recv(2048)
        sctp_socket.close()
        self.assertTrue(msgret == "")
    def test_init_server_1(self):
        sleep(1)
        server_thread = threading.Thread(target=self.attachToServer)
        server_thread.start()
        s = EPCServer()
        s.init_server()
        self.assertTrue(s.fd != None)
        self.assertTrue(s.addr != None)
        s.close_server()
    def test_init_server_2(self):
        sleep(1)
        server_thread = threading.Thread(target=self.attachToServer)
        server_thread.start()
        s = EPCServer()
        s.init_server()
        s.close_server()
        self.assertTrue(s.fd == None)
        self.assertTrue(s.addr == None)
    def test_init_server_3(self):
        server_thread = threading.Thread(target=self.attachToServerAndSendS1AP)
        server_thread.start()
        s = EPCServer()
        s.init_server()
        tmp = s.get_packet()
        self.assertTrue(tmp != None)
        self.assertTrue(tmp.__class__ == tuple().__class__)
        self.assertTrue(len(tmp) == 2)
if __name__ == '__main__':
    unittest.main()