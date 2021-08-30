from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.io import PrintWriter

from java.net import URL

import json,urlparse
from utilfuncs import getrpcresult
import uuid

from commburp import  CustomScanIssue, isblackext


Springbootdict = ["autoconfig","beans","env","configprops","dump","health","info","mappings","metrics","trace","","jolokia"]
Springbootprefix = ["/;/actuator/","/","/actuator/","/manage/"]

Fingerprintword = "Whitelabel Error Page"

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
        callbacks.setExtensionName("spring boot scanner")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

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


        arbrr = self._helpers.analyzeRequest(baseRequestResponse)

        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        
        urlpath = url.getPath()
        SpringFlag = False

        if ".ico" in urlpath:
            body = {"jsonrpc": "2.0","method": "faviconhash","params": {"faviconurl":url.toString()},"id": str(uuid.uuid1())}
            result = getrpcresult(body)["result"]
            if result:
                result = json.loads(result)
                resultdata = str(result["data"])
                if resultdata == "spring-boot":
                    SpringFlag = True
        else:
            blackextlist = [".js",".css",".font",".jpg",".png",".webp",".gif",".svg"]
            if isblackext(urlpath, blackextlist):
                return None

            rsp = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
            contype = rsp.getStatedMimeType()
            statuscode = rsp.getStatusCode()

            if contype.lower() != 'html': # or int(statuscode) == 404:
                return None

        orirespstr = self._helpers.bytesToString(baseRequestResponse.getResponse())

        vulnpathts = []
        issueresult = []

        if SpringFlag or Fingerprintword in orirespstr:
            for prefix in Springbootprefix:
                for path in Springbootdict:
                    #newurl = urlparse.urljoin(url, prefix+path)
                    checkRequestResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), self._helpers.buildHttpRequest(URL(url.getProtocol(),url.getHost(),url.getPort(),prefix+path)))
                    tmprsp = self._helpers.analyzeResponse(checkRequestResponse.getResponse())
                    tmpstatuscode = tmprsp.getStatusCode()
                    if int(tmpstatuscode) == 200:
                        vulnpathts.append(prefix+path)
                    
        if vulnpathts:
            issueresult.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "SprintBootPath",
                    "path  [ %s ] has status code [ %s ] " % (",".join(vulnpathts), '200'),
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
