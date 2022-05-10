from os import wait
from re import S
import socket
import time
import sctp

#s1 setup response ref

def send_S1_request(sock):
    sock.sctp_send(bytes.fromhex("0011002d000004003b00080000f110000019b0003c400a0380737273656e62303100400007000001c000f1100089400140"), ppid=socket.htonl(18))
def send_InitialUEMessage(sock):
    sock.sctp_send(bytes.fromhex("000c4079000005000800020001001a00515007417208291330002132916305f070c04018002a0241d011d127238080211001000010810600000000830600000000000d00000a000005000010000011005c0a01310365e0349011035758a65d0102c1004300060000f1100007006440080000f1100019b0100086400130"), ppid=socket.htonl(18))
def send_TAURequest(sock):
    sock.sctp_send(bytes.fromhex("000c408084000005000800020001001a005c5b17b70e7c921507482a0bf632f020900128d4d973d25805f070c040195232f020071f5c0a01a1570220003103e5e03e1332f020071f11035758a6200c601404e2918100121e40000040080402600400021f025d0103e0c11002fc00004300060000f1100007006440080000f1100019b0100086400130"), ppid=socket.htonl(18))
def send_IdentityResponse(sock):
    sock.sctp_send(bytes.fromhex("000d403b000005000000020002000800020002001a001211178b2a89af090756082980900035329163006440080000f1100019b010004340060000f1100007"), ppid=socket.htonl(18))


def scenario1(sock):
    send_S1_request(sock)
    fromaddr, flags, msgret, notif = sock.sctp_recv(2048)
    assert msgret.hex() == "201140170000020069000b000000f11000000100001a00574001ff"
    send_TAURequest(sock)
    fromaddr, flags, msgret, notif = sock.sctp_recv(2048)
    send_IdentityResponse(sock)
def scenario2(sock):
    send_S1_request(sock)
    fromaddr, flags, msgret, notif = sock.sctp_recv(2048)
    send_InitialUEMessage(sock)
    fromaddr, flags, msgret, notif = sock.sctp_recv(2048)
    send_IdentityResponse(sock)
if __name__ == "__main__":
    sock = sctp.sctpsocket_tcp(socket.AF_INET);
    sock.connect(("127.0.0.42",36412))
    scenario2(sock)

    
