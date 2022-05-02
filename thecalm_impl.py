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
        """@brief creates server socket and saves the socket in the EPCServer obj"""
        sctp_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        sctp_socket.bind(("127.0.0.42",36412))
        sctp_socket.listen(5)
        fd,addr = sctp_socket.accept()
        EPCServer.fd = fd
        EPCServer.addr = addr
        EPCServer.sctp_socket = sctp_socket
        return 
    def close_server():
        """@brief closes the saved socket connections in EPCServer"""
        EPCServer.sctp_socket.close()
        return
    def get_packet():
        fromaddr, flags, msgret, notif = EPCServer.fd.sctp_recv(2048)
        if len(msgret) == 0:
            return None,False
        print("msgret is: ",msgret.hex())
        s1ap_hex = msgret.hex()
        #print("HEX  IN: " +  s1ap_hex)
        try:
            # decode using pycrate
            s1ap = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
            s1ap.from_aper(binascii.unhexlify(s1ap_hex))
            #s1ap_decoded = s1ap.get_val()
            #return s1ap.get_val(), (True if flags == sctp.FLAG_EOR else False)
            return s1ap, (True if flags == sctp.FLAG_EOR else False)
            
            # re-encode using pycrate
            if (option_reencode == True):
                s1ap.set_val(s1ap_decoded)
                s1ap_hex_out = str(binascii.hexlify(s1ap.to_aper()))
                #print("HEX OUT:" + s1ap_hex_out)
                # decode again and try to check diff
                s1ap_reencoded = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
                s1ap_reencoded.from_aper(binascii.unhexlify(s1ap_hex))
                s1ap_decoded = str(s1ap.get_val())
                s1ap_reencoded_decoded = str(s1ap.get_val())
                if (s1ap_decoded != s1ap_reencoded_decoded):
                    print("!!!!!!! Re-encoding error begin !!!!!!!")
                    print("ENCODED  IN: " + s1ap_hex)
                    print("RE-RENCODED: " + s1ap_hex_out)
                    print(s1ap_decoded)
                    print(s1ap_reencoded_decoded)
                    print("!!!!!!! Re-encoding error end !!!!!!!")
        except Exception as err:
            raise(err) 
    def send_packet(value: string):
        """want the input hexlified"""
        print("SEND PACKET: received value",value)
        print("it is of type ",type(value))
        #EPCServer.fd.sctp_send(bytes.fromhex("201140170000020069000b000000f11000000100001a00574001ff"), ppid=socket.htonl(18))
        EPCServer.fd.sctp_send(bytes.fromhex(value), ppid=socket.htonl(18))

    def encode_and_send_packet(s1ap_decoded):
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
        ("connected_state",("initiated_socket_state","received_packet_state")),
        ("received_packet_state",("connected_state"))
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



