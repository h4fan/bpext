from burp import IBurpExtender
from burp import IProxyListener

from java.io import PrintWriter
import re

REPORT_API = 'YOUR_CSP_REPORT_API'


class BurpExtender(IBurpExtender, IProxyListener):

    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("CSPreport2me")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
        # register ourselves as an HTTP listener
        callbacks.registerProxyListener(self)

    #
    # implement IHttpListener
    #
    
    def processProxyMessage(self, messageIsRequest, message):
        # only process response
        if messageIsRequest:
            return

        # get the HTTP service for the request
        HttpRequestResponse = message.getMessageInfo()

        OriResp = self._helpers.bytesToString(HttpRequestResponse.getResponse())

        #headers,body = NewReq.split("\r\n\r\n")
        postindex = OriResp.index("\r\n\r\n")
        headers = OriResp[0:postindex]
        body = OriResp[postindex:]
        #print(body) Content-Security-Policy
        if 'content-security-policy' not in headers.lower():
            return
        newheaders = re.sub(r'report-uri .*','report-uri '+ REPORT_API, headers, 0, re.I)
        NewResp = "".join((newheaders,body))
        url = self._helpers.analyzeRequest(HttpRequestResponse).getUrl()
        self.stdout.println("[content-security-policy report-uri] changed: %s" % url)
        
        #self.stdout.println("[new headers]" + newheaders)

     

        HttpRequestResponse.setResponse(self._helpers.stringToBytes(NewResp))
        
        # # if the host is HOST_FROM, change it to HOST_TO
        # if (HOST_FROM == httpService.getHost()):
        #     messageInfo.setHttpService(self._helpers.buildHttpService(HOST_TO,
        #         httpService.getPort(), httpService.getProtocol()))