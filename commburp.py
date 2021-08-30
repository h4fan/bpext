from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IHttpService
from burp import IHttpRequestResponse
from array import array
from java.net import URL 

from burp import IRequestInfo

import re
import os,time,base64,struct,json
import random
import string, uuid, urlparse

from utilfuncs import getrpcresult, fetchdnslogresults
from rpcconfig import ReverseLengthMap, DnslogDOMAIN

RandomPayloadLen = 5
ctpat = re.compile(r'Content-Length:\s*\d+',re.I)
contypepat = re.compile(r'Content-Type:\s*.*',re.I)




def get_random_string(length):
    # Random string with the combination of lower and upper case
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str.lower()

def get_random_domain(length):
    if length < len(ReverseLengthMap):
        return get_random_string(length)+ReverseLengthMap[length]
    else:
        return get_random_string(5)+ReverseLengthMap[5]


def get_random_dns_domain():
    length = random.choice([4,5,6,7,8])
    if length < len(ReverseLengthMap):
        return get_random_string(length)+ReverseLengthMap[length]+"."+DnslogDOMAIN
    else:
        return get_random_string(5)+ReverseLengthMap[5]+"."+DnslogDOMAIN



def isblackext(urlpath, blackextlist):
    for ext in blackextlist:
        if ext in urlpath:
            return True
    return False


def buildReqReplaceBodyAndContype(Req, rawbody, contype):
    OldReq = Req
    OrigLen = len(OldReq)
    
    firstlineindex = OldReq.index("\r\n")
    #fix http 2.0 bug in burp

    NewReq = OldReq[:firstlineindex].replace("HTTP/2","HTTP/1.1") + OldReq[firstlineindex:]

    #headers,body = NewReq.split("\r\n\r\n")
    postindex = NewReq.index("\r\n\r\n")
    headers = NewReq[0:postindex]
    #body = NewReq[postindex:]
    body = "\r\n\r\n"+rawbody
    #print(body)
    if len(body) > 4:
        NewReq = "".join((headers,body))
        newbodyindex = NewReq.index("\r\n\r\n")
        newbody = NewReq[newbodyindex+4:]
        #newheaders,newbody = NewReq.split("\r\n\r\n")
        NewReq = re.sub(ctpat,"Content-Length: "+str(len(newbody)),NewReq)
        NewReq = re.sub(contypepat,"Content-Type: %s" % contype,NewReq)

    if(len(NewReq) == OrigLen):
        return None
    else:
        return NewReq



def changeReqHttpVersion(Req):
    OldReq = Req

    firstlineindex = OldReq.index("\r\n")
    #fix http 2.0 bug in burp

    NewReq = OldReq[:firstlineindex].replace("HTTP/2","HTTP/1.1") + OldReq[firstlineindex:]

    return NewReq


loggedissues = []



def checkresults(addScanIssue):
    global loggedissues
    collresult = fetchdnslogresults()
    print(len(collresult))
    if(len(collresult) == 0):
        return None
    vulnflag = False
    othervulnflag = False
    otherdomain = ""
    issueresult = []
    domainresult = []
    for coll in collresult:
        print(coll)
        type = coll["datatype"]
        if type == 'DNS':
            #self.stdout.println(rq)

            domains = coll["hostname"]
            
            #print("[SSRF----------------------------------]:"+domains)
            #self.stdout.println("[SSRF---------------RAND-STR-------------------]:"+randomssrfpayload)
            #if not vulnflag and (domains == randomssrfpayload or randomssrfpayload in domains):
            if DnslogDOMAIN in domains:
                print("[DNSLOG-------------------------------]:"+domains)
                #self.stdout.println(domains != self.ssrfpayload)
                otherdomain = domains
                if domains not in domainresult:
                    domainresult.append(domains)
                    body = {"jsonrpc": "2.0","method": "getunmarkresultbydns","params": {"dns":domains},"id": str(uuid.uuid1())}
                    rpcresult = json.loads(getrpcresult(body)["result"])
                    print(rpcresult)
                    if len(rpcresult["data"]) > 0:
                        line = rpcresult["data"][0]
                        scandns = str(line["dns"])
                        scanrequrl = str(line["requrl"])
                        scanreqcontent = line["reqcontent"].encode(encoding="utf-8", errors="ignore")
                        scantype = str(line["scantype"])

                        #tmpRequestResponse.setRequest(self._helpers.stringToBytes(scanreqcontent))
                        requrlparsedict = urlparse.urlparse(scanrequrl)

                        issueurl_type = requrlparsedict.hostname + requrlparsedict.path + scantype
                        if issueurl_type not in loggedissues:
                            loggedissues.append(issueurl_type)
                            addScanIssue(CustomScanIssue(
                            CustomHttpService(requrlparsedict.hostname,requrlparsedict.port,requrlparsedict.scheme),
                            URL(scanrequrl),
                            [CustomHttpRequestResponseWithMarkers(CustomHttpService(requrlparsedict.hostname,requrlparsedict.port,requrlparsedict.scheme), bytearray(scanreqcontent) )],
                            scantype,
                            "DNS Found [ %s ] please check history for vuln" % scandns,
                            "High","Certain",scanreqcontent))
                            body = {"jsonrpc": "2.0","method": "markscanresult","params": {"dns":domains},"id": str(uuid.uuid1())}
                            getrpcresult(body)
                        

    return domainresult




#
# class implementing IScanIssue to hold our custom scan issue details
#
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence, req):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

        body = {"jsonrpc": "2.0","method": "logvul","params": {"requrl": url.toString(), "reqcontent": req, "scantype": name+":"+detail},"id": str(uuid.uuid1())}
        getrpcresult(body)

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService


class CustomHttpService(IHttpService):
    def __init__(self, host, port ,protocol):
        self._host = host
        self._port = port 
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port 

    def getProtocol(self):
        return self._protocol


class CustomHttpRequestResponse(IHttpRequestResponse):
    def __init__(self, httpService, req):
        self._httpservice = httpService
        self._req = req

    def getRequest(self):
        return self._req 

    def getResponse(self):
        pass 

    def getHttpService(self):
        return self._httpservice

    def getComment(self):
        pass

    def getHighlight(self):
        pass


class CustomHttpRequestResponseWithMarkers(CustomHttpRequestResponse):
    def getRequestMarkers(self):
        return 

    def getResponseMarkers(self):
        return
