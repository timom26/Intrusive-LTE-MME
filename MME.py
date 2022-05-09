from EPC import *
from parsing import parsing as parser
import argparse
if __name__ == "__main__":
    argParser = argparse.ArgumentParser(description='This is a bachelor thesis project.')
    group = argParser.add_mutually_exclusive_group(required=False)
    group.add_argument('-IMSITarget', '--t', type=str, nargs='+',help='IMSI list of targeted phones to be blocked')
    group.add_argument('-IMSIOmit', '--o', type=str, nargs='+',help='IMSI list of phones not to be blocked')
    args = argParser.parse_args()
    epcServer = EPCServer()
    print(args.o)
    epcServer.omit = args.o
    epcServer.target = args.t
    while(True):
        print("round")
        if epcServer.state.get_current_state() == "null_state":
            epcServer.init_server()
            epcServer.state.set_current_state("initialised_socket_state")
            print("state is:", epcServer.state.get_current_state())
        if epcServer.state.get_current_state() == "initialised_socket_state":
            poll_again = True
            while (poll_again):
                decoded, poll_again = epcServer.get_packet()
                # epcServer.close_server()
                if (decoded):
                    (type, value) = S1AP.S1AP_PDU_Descriptions.S1AP_PDU()
                    if type == 'initiatingMessage':
                        procedure, protocolIEs_list = value['value'][0], value['value'][1]['protocolIEs']
                        if procedure == 'S1SetupRequest':
                            if parser.S1SetupRequest(epcServer, protocolIEs_list):
                                parser.S1SetupResponse(epcServer, True)
                            else:
                                parser.S1SetupResponse(epcServer, False)
                        elif procedure == 'InitialUEMessage':
                            parser.InitialUEMessage(
                                epcServer, 
                                protocolIEs_list,
                            )
                        elif procedure == 'UplinkNASTransport':
                            parser.UplinkNASTransport(
                                epcServer,
                                protocolIEs_list
                            )
                        else:
                            print("#### Type of the procedure not implemented ! ####")
                            pass  # no need to implement others
                    elif type == 'successfulOutcome':
                        pass
                    elif type == 'unsuccessfulOutcome':
                        if procedure == 'S1SetupFailure':
                            pass
        epcServer.close_server()
        #exit()
