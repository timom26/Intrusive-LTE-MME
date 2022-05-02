from asyncore import poll
from thecalm_impl import *
from parsing import parsing as parser
if __name__ == "__main__":
    epcServer = EPCServer
    epcServer.init_server()
    print("initiated")
    decoded = True
    while (decoded):
        decoded, poll_again = epcServer.get_packet()
        epcServer.close_server()
        if (decoded):
            (type, value) = S1AP.S1AP_PDU_Descriptions.S1AP_PDU()
            if type == 'initiatingMessage':
                procedure, protocolIEs_list = value['value'][0], value['value'][1]['protocolIEs']
                if procedure == 'S1SetupRequest':
                    if parser.S1SetupRequest(epcServer,protocolIEs_list):
                        parser.S1SetupResponse(epcServer,True)
                    else:
                        parser.S1SetupResponse(epcServer,False)
                elif procedure == 'InitialUEMessage':
                    print("initialUEMessage")
                    parser.InitialUEMessage(epcServer,protocolIEs_list)
                else:
                    print("it is not that but instead is",procedure)
                    for i in protocolIEs_list:
                        print(i)
            elif type == 'successfulOutcome':
                print("SUCC")
                procedure, protocolIEs_list = value['value'][0], value['value'][1]['protocolIEs']
                if procedure == 'S1SetupResponse':
                    print("wtf received response on MME")
                else:
                    print("it is not that but instead is",procedure)
                    for i in protocolIEs_list:
                        print(i)
            elif type == 'unsuccessfulOutcome':
                print("UNSUCC")
                if procedure == 'S1SetupFailure':
                    print("fail")
                

