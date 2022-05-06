from binascii import unhexlify, hexlify
from logging import critical
from re import I
import copy
from sys import byteorder
from pycrate_asn1dir import S1AP
from matplotlib.pyplot import show
import pycrate_mobile.NAS
from numpy import empty

class parsing:
    def checkIE_accepted(protocolIEs_list,list_of_mandatory_IEs,list_of_optional_IEs) -> bool:
        mandatory_IEs_and_their_presence = copy.deepcopy(list_of_mandatory_IEs)
        optional_IEs_and_their_presence = copy.deepcopy(list_of_optional_IEs)
        for IE in protocolIEs_list:
            id = IE['id']
            criticality = IE['criticality']
            tmpIE = (id,criticality)
            if tmpIE in list_of_mandatory_IEs:
                if tmpIE in mandatory_IEs_and_their_presence:
                    mandatory_IEs_and_their_presence.remove(tmpIE)
                else:
                    raise Exception("mandatory IE was there twice")
            elif tmpIE in list_of_optional_IEs:
                if tmpIE in optional_IEs_and_their_presence:
                    optional_IEs_and_their_presence.remove(tmpIE)
                else:
                    raise Exception("optional IE was there twice")
            else:
                raise Exception("unknown IE: ",tmpIE)
        if mandatory_IEs_and_their_presence:
            raise Exception("not all Mandatory IEs present")
        print("checkIE succ")
        return True
    def S1SetupRequest(EPC_server,protocolIEs_list):
        """
        mandatory IEs are 
            59 Global ENBID
            64 Supported TAs
                1-256 TAC, for every TAC there are 1-6 Broadcast PLMN identities
            137 Default paging DRX
        Optional IEs are
            60 ENB name
            232 RAT type (associated with the TAC of the indicated PLMNs)
            228 UE retention information
            127 Closed subscriber group
            234 NB iot default paging drx
        """
        print('S1SetupRequest')
        list_of_mandatory_IEs = [
            (59, 'reject'),
            (64, 'reject'),
            (137, 'ignore'),
        ]
        list_of_optional_IEs = [
            (60, 'ignore'),
            (232, 'reject'),
            (228, 'ignore'),
            (127, 'reject'),
            (234, 'ignore'),
        ]
        tmp = parsing.checkIE_accepted(protocolIEs_list,list_of_mandatory_IEs,list_of_optional_IEs)
        for i in protocolIEs_list:
            id = i['id']
            criticality = i['criticality']
            value = i['value'][1]
            print('id',id)
            print(criticality)
            print(value)
            if id == 59:
                print(value['pLMNidentity'])
                print(value['eNB-ID'])
        return True
    def S1SetupResponse (epcServer, success):
        """
        Creates and sends a S1SetupResponse or S1SetupFailure
        """
        if success:
            print("succ s1setup response ")
            IEs = []
            IEs.append({'id': 105, 'criticality': 'reject', 'value': ('ServedGUMMEIs', [{'servedPLMNs': [b'\x00\xf1\x10'], 'servedGroupIDs': [b'\x01\x00'], 'servedMMECs': [b'\x1a']}])})
            IEs.append({'id': 87, 'criticality': 'ignore', 'value': ('RelativeMMECapacity', 255)})
            val = ('successfulOutcome', {'procedureCode': 17, 'criticality': 'ignore', 'value': ('S1SetupResponse', {'protocolIEs': IEs })})
            epcServer.encode_and_send_packet(val)
        else:#failed 
            print("failed s1setup response ")
            IEs = []
            #cause
            IEs.append({'id': 2, 'criticality': 'ignore','value': ('Cause', ('misc', 'unspecified'))})
            val = ('unsuccessfulOutcome', {'procedureCode': 17, 'criticality': 'ignore','value': ('S1SetupFailure', {'protocolIEs': IEs})})
            epcServer.encode_and_send_packet(val)

    def InitialUEMessage(epcServer,protocolIEs_list):
        list_of_mandatory_IEs = [
            (8,'reject'),
            (26,'reject'),
            (67,'reject'),
            (100,'ignore'),
            (134,'ignore'),
        ]
        list_of_optional_IEs = [
            (96,'reject'),
            (127,'reject'),
            (75,'reject'),
            (145,'reject'),
            (155,'ignore'),
            (160,'reject'),
            (170,'ignore'),
            (176,'ignore'),
            (184,'ignore'),
            (186,'ignore'),
            (223,'ignore'),
            (230,'ignore'),
            (242,'ignore'),
            (246,'ignore'),
            (250,'ignore'),
        ]
        parsing.checkIE_accepted(protocolIEs_list,list_of_mandatory_IEs,list_of_optional_IEs)
        print("here")
        for i in protocolIEs_list:
            id = i['id']            
            criticality = i['criticality']
            value = i['value']
            if id == 26:#NAS-PDU message
                value = value[1]#discard text description
                msg, err = pycrate_mobile.NAS.parse_NAS_MO(value)#MobileOriginating decode
                if err:
                    raise Exception("Decoding of incoming MO failed")
                if msg['EMMHeader']['Type'].get_val() != 65:#Attach request 
                    print("not initial message")
                    pass
                ident_type, code = msg['EPSID'][1].decode()
                if ident_type == 1:
                    print("imsi is ",code)
                else:
                    print("unknown code, ",code)


                #print("this is id type and its value: ",msg['EPSID'][0],msg['EPSID'][1])
                #pycrate_mobile.NAS.show(msg._opts)
                #sprint(msg['EPSID']['Type'])


                ########################    N E W   M E S A G G E    ##########################

                #parsing.send_attachReject(epcServer,8)
                #parsing.send_identityResponse(epcServer)
                parsing.send_TAURequest(epcServer)
                #parsing.send_TAUReject(epcServer)





    ############  D E F I N I T I O N S  ######################################################
    ##TAU NAS
    def create_NAS_only_TAURequest():
        return pycrate_mobile.NAS.EMMTrackingAreaUpdateRequest().to_bytes()
    def create_NAS_only_TAUReject():
        msg = pycrate_mobile.NAS.EMMTrackingAreaUpdateReject()
        msg[1].set_val([b'\x09'])
        return msg.to_bytes()
    ##TAU MSG
    def send_TAUReject(epcServer):
        nas_param = parsing.create_NAS_only_TAUReject()
        parsing.create_NAS_PDU_downlink(epcServer,nas_param)
    def send_TAURequest(epcServer):
        nas_param = parsing.create_NAS_only_TAURequest()
        parsing.create_NAS_PDU_downlink(epcServer,nas_param)
    ##identity NAS
    def create_NAS_only_identityResponse():
        msg = pycrate_mobile.NAS.EMMIdentityResponse()
        #msg['ID'].set_val([5, b'\x01\x23\x32\x01\x00\x22\x31'])
        msg['ID'].set_IE(val={'type': 1, 'ident': '208100123456789'}) 
        return msg.to_bytes()
    def create_NAS_only_identityRequest():
        return pycrate_mobile.NAS.EMMIdentityRequest().to_bytes()
    ##identity message
    def sendIdentityRequest(epcServer):
        nas_param = parsing.create_NAS_only_identityRequest()
        parsing.create_NAS_PDU_downlink(epcServer,nas_param)
    def send_identityResponse(epcServer):
        nas_param = parsing.create_NAS_only_identityResponse()
        parsing.create_NAS_PDU_downlink(epcServer,nas_param)
    ##attach NAS
    def create_NAS_only_attachReject(val: int):
        if val > 255 or val < 0: #just to be sure
            raise Exception("illegal cause code for Attach reject")
        msg = pycrate_mobile.NAS.EMMAttachReject()
        tmp_list = []
        tmp_list.append(val.to_bytes(1,byteorder='big'))
        msg['EMMCause'].set_val(tmp_list)
        return msg.to_bytes()
    ##attach message
    def send_attachReject(epcServer,reason):
        nas_param = parsing.create_NAS_only_attachReject(reason)
        parsing.create_NAS_PDU_downlink(epcServer,nas_param)
    
    ##create S1 encapsulation message
    def create_NAS_PDU_downlink(epcServer,nas_param):#TODO add variable IDs
        IEs = []
        IEs.append({'id': 0, 'criticality': 'reject', 'value': ('MME-UE-S1AP-ID', 1)})
        IEs.append({'id': 8, 'criticality': 'reject', 'value': ('ENB-UE-S1AP-ID', 1)})
        IEs.append({'id': 26, 'criticality': 'reject', 'value': ('NAS-PDU', nas_param)})
        val = ('initiatingMessage', {'procedureCode': 11, 'criticality': 'ignore', 'value': ('DownlinkNASTransport', {'protocolIEs': IEs })})
        PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
        PDU.set_val(val)
        print(PDU.to_asn1())
        epcServer.send_packet(PDU.to_aper().hex())