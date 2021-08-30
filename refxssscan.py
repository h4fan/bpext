from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.io import PrintWriter
from burp import IBurpCollaboratorClientContext
from burp import IBurpCollaboratorInteraction
import re
from burp import IParameter

import os,time,base64,struct,json

from commburp import changeReqHttpVersion, CustomScanIssue, get_random_string, isblackext


RandomPayloadLen = 5


class BurpExtender(IBurpExtender, IScannerCheck,IBurpCollaboratorClientContext):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("ref scanner")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.collaboratorContext = callbacks.createBurpCollaboratorClientContext()
        # global GcollaboratorContext,Gstdout 
        # GcollaboratorContext = self.collaboratorContext
        # Gstdout = self.stdout
        
        #self.ssrfpayload = self.collaboratorContext.generatePayload(True)


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




    def doPassiveScan(self, baseRequestResponse):
        # look for matches of our passive check grep string
        #matches = self._get_matches(baseRequestResponse.getResponse(), GREP_STRING_BYTES)


        #if (len(matches) == 0):
        #    return None
        self.randomstr = get_random_string(RandomPayloadLen)

        arbrr = self._helpers.analyzeRequest(baseRequestResponse)

        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        
        urlpath = url.getPath()
        blackextlist = [".js",".css",".font",".jpg",".png",".webp",".gif",".svg",".ico"]
        if isblackext(urlpath, blackextlist):
            return None

        rsp = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        contype = rsp.getStatedMimeType()
        statuscode = rsp.getStatusCode()

        if (not isblackext(contype.lower(),['html','xml',"json"])) or int(statuscode) == 404:
            return None

        paralist = arbrr.getParameters()
        reflectparas = []
        orirespstr = self._helpers.bytesToString(baseRequestResponse.getResponse())

        for pa in paralist:
            #self.stdout.println("" + pa.getName() + ","+pa.getValue())
            v = self._helpers.urlDecode(pa.getValue())
            #self.stdout.println(v)
            #self.stdout.println(pa.getName())
            #self.stdout.println(pa.getType())

            if pa.getType() not in [IParameter.PARAM_XML_ATTR, IParameter.PARAM_XML] and v in orirespstr:
                #self.stdout.println('match')
                reflectparas.append(pa)

        issueresult = []
        vulnparas = []
        xsspayload=self._helpers.urlEncode("a'\"><j"+get_random_string(2)+">_<8"+get_random_string(3))
        newReq = baseRequestResponse.getRequest()
        if isblackext(contype.lower(),['html','xml']):
            for k in reflectparas:
                #self.stdout.println("" + k.getName())
                #self.stdout.println("" + k.getName())
                #self.stdout.println(k.getType())
                newReq = self._helpers.updateParameter(baseRequestResponse.getRequest(),self._helpers.buildParameter(k.getName(),xsspayload,k.getType()))
                newReq = self._helpers.stringToBytes(changeReqHttpVersion(self._helpers.bytesToString(newReq)))
                checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
                modrespstr = self._helpers.bytesToString(checkRequestResponse.getResponse()).split("\r\n\r\n",2)
                if len(modrespstr) == 1:
                    continue
                if xsspayload in modrespstr[1]:
                    self.stdout.println(url)
                    self.stdout.println("[---xss---]: " + k.getName())
                    vulnparas.append(k.getName())
                    
            if vulnparas:
                issueresult.append(CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                        "XSS",
                        "para name [ %s ] xss payload [ %s ] " % (",".join(vulnparas), xsspayload),
                        "High","Certain", self._helpers.bytesToString(baseRequestResponse.getRequest())))

        sqlierrorpayload=self._helpers.urlEncode("a'\"j"+get_random_string(2)+"9"+get_random_string(3))
        flag = False
        for k in paralist:
            #self.stdout.println("" + k.getName())
            if k.getType() in [IParameter.PARAM_XML_ATTR,IParameter.PARAM_XML]:
                continue
            flag = True
            newReq = self._helpers.updateParameter(newReq,self._helpers.buildParameter(k.getName(),k.getValue()+sqlierrorpayload,k.getType()))
        if flag:
            newReq = self._helpers.stringToBytes(changeReqHttpVersion(self._helpers.bytesToString(newReq)))
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
            modrespstr = self._helpers.bytesToString(checkRequestResponse.getResponse()).split("\r\n\r\n",2)
            if len(modrespstr) > 1:
                errorpatterns = ["SQL syntax","sql error","mysql_fetch_array()"]
                if isblackext(modrespstr[1], errorpatterns):
                    self.stdout.println(url)
                    self.stdout.println("[---sql error---] " )
                    issueresult.append(CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                            "SQLiError",
                            "response contains sqli error msg [ %s ] " % ",".join(errorpatterns),
                            "High","Certain", self._helpers.bytesToString(baseRequestResponse.getRequest())))


        sstipayload=self._helpers.urlEncode("a'\"><j"+get_random_string(2)+"{819*615}>_<8"+get_random_string(3))
        flag = False
        for k in paralist:
            #self.stdout.println("" + k.getName())
            if k.getType() in [IParameter.PARAM_XML_ATTR, IParameter.PARAM_XML]:
                continue
            flag = True
            newReq = self._helpers.updateParameter(newReq,self._helpers.buildParameter(k.getName(),k.getValue()+sstipayload,k.getType()))
        if flag:
            newReq = self._helpers.stringToBytes(changeReqHttpVersion(self._helpers.bytesToString(newReq)))
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
            modrespstr = self._helpers.bytesToString(checkRequestResponse.getResponse()).split("\r\n\r\n",2)
            if len(modrespstr) > 1:
                errorpatterns = ["503685","sqlerror"]
                if isblackext(modrespstr[1], errorpatterns):
                    self.stdout.println(url)
                    self.stdout.println("[---ssti---] " )
                    issueresult.append(CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                            "ssti",
                            "response contains ssti msg [ %s ] " % ",".join(errorpatterns),
                            "High","Certain", self._helpers.bytesToString(baseRequestResponse.getRequest())))


        cmdparainjpayload=self._helpers.urlEncode(" && whoami --help -h "+get_random_string(3))
        flag = False
        for k in paralist:
            #self.stdout.println("" + k.getName())
            if k.getType() in [IParameter.PARAM_XML_ATTR, IParameter.PARAM_XML]:
                continue
            flag = True
            newReq = self._helpers.updateParameter(newReq,self._helpers.buildParameter(k.getName(),k.getValue()+cmdparainjpayload,k.getType()))
        if flag:
            newReq = self._helpers.stringToBytes(changeReqHttpVersion(self._helpers.bytesToString(newReq)))
            checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newReq)
            modrespstr = self._helpers.bytesToString(checkRequestResponse.getResponse()).split("\r\n\r\n",2)
            if len(modrespstr) > 1:
                errorpatterns = ["invalid option","Usage:"]
                if isblackext(modrespstr[1], errorpatterns):
                    self.stdout.println(url)
                    self.stdout.println("[---command error---] " )
                    issueresult.append(CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                            "CMDParaInj",
                            "response contains help msg [ %s ] " % ",".join(errorpatterns),
                            "High","Certain", self._helpers.bytesToString(baseRequestResponse.getRequest())))



        if issueresult:
            return issueresult


        return None





    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # make a request containing our injection test in the insertion point
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
