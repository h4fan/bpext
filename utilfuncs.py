# -*- coding: utf-8 -*-

import json, httplib

from rpcconfig import RpcHost, RpcPort, RpcPath, RpcAuthName, RpcToken, DnslogAPIDOMAIN, DnslogAPIURL, DnslogAuthName, DnslogToken, ReverseLengthMap

def getrpcresult(body):
    
    headers = { RpcAuthName: RpcToken, "Content-Type": "application/json"}
    conn = httplib.HTTPConnection(RpcHost, RpcPort)
    conn.request("POST", RpcPath, body= json.dumps(body), headers=headers)
    response = conn.getresponse()
    resp = response.read()
    conn.close()
    #print(resp)
    return json.loads(resp)



def fetchdnslogresults():
    
    headers = {DnslogAuthName: DnslogToken}
    conn = httplib.HTTPSConnection(DnslogAPIDOMAIN)
    conn.request("GET", DnslogAPIURL, headers=headers)
    response = conn.getresponse()
    resp = response.read()
    conn.close()
    #print(resp)
    return json.loads(resp)


def dnslogconvertlongstr(longstr):
    longstrlen = len(longstr)
    longstrlen = longstrlen % 100
    len_str = str(longstrlen).zfill(2)
    result = longstr+ReverseLengthMap[int(len_str[0])]+ReverseLengthMap[int(len_str[1])]
    print(result)
    return result