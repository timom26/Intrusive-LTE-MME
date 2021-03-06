from datetime import datetime
import socket
import string
import sctp
import binascii
from state_machine import EPC_state_machine
from pycrate_asn1dir import S1AP


class EPCServer:
    sctp_socket = None
    fd = None
    addr = None
    state = EPC_state_machine()
    IMSI_output = None
    omit = None
    target = None
    listenAddress = "127.0.0.42"
    attach_reject_reason = 8
    def init_server(self) -> None:
        """Creates server socket and saves the socket in the EPCServer obj"""
        sctp_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        sctp_socket.bind((self.listenAddress,36412))
        try:
            sctp_socket.listen(5)
            fd,addr = sctp_socket.accept()
        except KeyboardInterrupt:
            print("\nThe program was interrupted while awaiting a connection. Exiting ..")
            exit()
        self.fd = fd
        self.addr = addr
        if self.IMSI_output == None:
            self.IMSI_output = open("IMSI_output.txt","w")
        return 
    def close_server(self) -> None:
        """Closes the saved socket connections in EPCServer"""
        if self.fd != None:
            self.fd.close()
        self.sctp_socket = None
        self.fd = None
        self.addr = None
        self.state.set_current_state("null_state")
    def get_packet(self) -> tuple:
        """Receive a packet on the initialised socket in the EPCServer"""
        try:
            fromaddr, flags, msgret, notif = self.fd.sctp_recv(2048)
        except ConnectionResetError:
            print("Connection reset while receiving packet. Closing connection ..")
            self.close_server()
            return (None,False)
        if len(msgret) == 0:
            return None,False
        s1ap_hex = msgret.hex()
        try:
            # decode using pycrate
            s1ap = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
            s1ap.from_aper(binascii.unhexlify(s1ap_hex))
            return s1ap, (True if flags == sctp.FLAG_EOR else False)
        except Exception as err:
            print("Error during S1AP dissection. Skipping..")
    def send_packet(self,value: string):
        """The function wants the input hexlified. Function is better not used directly, use encode_and_send_packet()"""
        self.fd.sctp_send(bytes.fromhex(value), ppid=socket.htonl(18))

    def encode_and_send_packet(self,s1ap_decoded):
        """encode a message and send it on the preset socket in the EPCServer"""
        s1ap = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
        s1ap.set_val(s1ap_decoded)
        s1ap_hex_out = binascii.hexlify(s1ap.to_aper()).decode('ascii')
        self.send_packet(s1ap_hex_out)
    def write_imsi(self,imsi: string) -> None:
        "prints IMSI information to an opened file"
        if self.IMSI_output == None:
            return
        self.IMSI_output.write(f"{datetime.now()}")
        self.IMSI_output.write("    ")
        self.IMSI_output.write(imsi)
        self.IMSI_output.write("\n")