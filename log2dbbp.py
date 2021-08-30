from burp import IBurpExtender
from burp import IHttpListener

from array import array
from java.io import PrintWriter


import uuid
from utilfuncs import getrpcresult
from commburp import isblackext


class BurpExtender(IBurpExtender, IHttpListener ):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("burplog2db rpc")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        # global GcollaboratorContext,Gstdout 
        # GcollaboratorContext = self.collaboratorContext
        # Gstdout = self.stdout
        


        # register ourselves as a custom scanner check
        callbacks.registerHttpListener(self)


    # helper method to search a response for occurrences of a literal match string
    # and return a list of start/end offsets


    #
    # implement IScannerCheck
    #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only precess proxy
        #self.stdout.println("[url]: "+str(toolFlag) +' | ' + str(messageIsRequest))
        if toolFlag != self._callbacks.TOOL_PROXY:
            return
        # only process requests
        #self.stdout.println("[url]: "+str(toolFlag) +' | ' + str(messageIsRequest))
        if messageIsRequest:
            return
        
        # create a new log entry with the message details

        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        
        urlpath = url.getPath()
        blackextlist = [".js",".css",".font",".jpg",".js",".png",".webp",".gif",".svg",".ico",".woff"]
        if isblackext(urlpath, blackextlist):
            return
        
        #self.stdout.println("[url]: "+url.toString())
        #self.stdout.println("[url]: "+OldReq)
        
        rsp = self._helpers.analyzeResponse(messageInfo.getResponse())

        contype = rsp.getStatedMimeType()
        statuscode = rsp.getStatusCode()
        #self.stdout.println(resphelp.getStatedMimeType())
        #self.stdout.println("[url]: "+contype)
        #self.stdout.println("[url]: "+respheaders)
        if contype.lower() in 'html|json' and int(statuscode) != 404:
            respheaders = self._helpers.bytesToString(messageInfo.getResponse()).split("\r\n\r\n",2)[0]
            method = self._helpers.analyzeRequest(messageInfo).getMethod()
            OldReq = self._helpers.bytesToString(messageInfo.getRequest())
            body = {"jsonrpc": "2.0","method": "loghttp2db","params": {"requrl": str(url),"reqmethod":str(method), "reqfulldata": OldReq, "respheaders": respheaders},"id": str(uuid.uuid1())}
            getrpcresult(body)
            return
        


