from lib2to3.pgen2.pgen import DFAState
import socket
import string
import sctp
import binascii
from pycrate_asn1dir import S1AP
# Global options to control the script behavior
option_print_verbose = True       # print verbose decoding output
option_fuzzing_messages = False    # fuzz messages before pycrate decoding
option_reencode = True             # re-encode into hex and compare with the hex input
class EPCServer:
    
    sctp_socket = None
    fd = None
    addr = None


    def init_server():
        """Creates server socket and saves the socket in the EPCServer obj"""
        sctp_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        sctp_socket.bind(("127.0.0.42",36412))
        sctp_socket.listen(5)
        fd,addr = sctp_socket.accept()
        EPCServer.fd = fd
        EPCServer.addr = addr
        EPCServer.sctp_socket = sctp_socket
        EPC_state_machine.set_next_state("initialised_socket_state")
        return 
    def close_server():
        """Closes the saved socket connections in EPCServer"""
        EPCServer.sctp_socket.close()
        EPC_state_machine.set_next_state("null_state")
        # EPCServer.sctp_socket = None
        # EPCServer.fd = None
        # EPCServer.addr = None
    def get_packet():
        """Receive a packet on the initialised socket in the EPCServer"""
        try:
            fromaddr, flags, msgret, notif = EPCServer.fd.sctp_recv(2048)
        except ConnectionResetError:
            print("hahahah")
            EPCServer.close_server()
        if len(msgret) == 0:
            return None,False
        s1ap_hex = msgret.hex()
        try:
            # decode using pycrate
            s1ap = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
            s1ap.from_aper(binascii.unhexlify(s1ap_hex))
            return s1ap, (True if flags == sctp.FLAG_EOR else False)
        except Exception as err:
            raise(err) 
    def send_packet(value: string):
        """The function wants the input hexlified. Function is better not used directly, use encode_and_send_packet()"""
        EPCServer.fd.sctp_send(bytes.fromhex(value), ppid=socket.htonl(18))

    def encode_and_send_packet(s1ap_decoded):
        """encode a message and send it on the preset socket in the EPCServer"""
        s1ap = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
        s1ap.set_val(s1ap_decoded)
        s1ap_hex_out = binascii.hexlify(s1ap.to_aper()).decode('ascii')
        EPCServer.send_packet(s1ap_hex_out)
class EPC_state_machine:
    current_state = "null_state"
    next_state = None
    states = [
        ("null_state",("initialised_socket_state")),
        ("initialised_socket_state",("connected_state", "null_state")),
        ("connected_state",("initiated_socket_state",)),
    ]
    def get_current_state():
        return EPC_state_machine.current_state
    def get_next_state():
        return EPC_state_machine.next_state
    def step():
        EPC_state_machine.current_state = EPC_state_machine.next_state
    def get_possible_next_states():
        """returns tuple of next states"""
        return([i[1] for i in EPC_state_machine.states if i[0] == EPC_state_machine.current_state][0])
    def set_next_state(wanted_next_state: string):
        if wanted_next_state not in EPC_state_machine.get_possible_next_states():
            raise Exception("there is no such nextstate")
        EPC_state_machine.next_state = wanted_next_state



