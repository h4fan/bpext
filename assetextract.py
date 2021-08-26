#
#  BurpLinkFinder - Find links within JS files.
#
#  Copyright (c) 2019 Frans Hendrik Botes
#  Credit to https://github.com/GerbenJavado/LinkFinder for the idea and regex
#  Credit to BurpJSLinkFinder
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser

import urlparse


import logging,datetime,os
logpath = os.environ['HOME']+"/log/" +'bplinks%s.log' %(datetime.date.today())
logging.basicConfig(filename= logpath, format='%(message)s', level=logging.INFO)


# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params

JSExclusionList = ['jquery', 'google-analytics','gpt.js','www.googleadservices.com']

LinksResultSet = set()

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Assetextract")

        callbacks.issueAlert("BurpJSLinkFinder Passive Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)
        
        #print ("Burp JS LinkFinder loaded.")
        #print ("Copyright (c) 2019 Frans Hendrik Botes")
        self.outputTxtArea.setText("")

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("LinkFinder Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()



        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

    def getTabCaption(self):
        return "JSLink"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
          self.outputTxtArea.setText("" )

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        #print("\n" + "Export to : " + filename)
        open(filename, 'w', 0).write(self.outputTxtArea.text)

    
    def doPassiveScan(self, ihrr):
        
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)
            linkA = linkAnalyse(ihrr,self.helpers)
            blackextlist = [".css",".font",".jpg",".png",".webp",".gif",".svg"]
            if isblackext(str(urlReq),blackextlist):
                return None
            reqheaderlist = self.helpers.analyzeRequest(ihrr).getHeaders()
            httpreferer = urlReq
            schema = 'https'
            #httprefererparseresult = ""
            for header in reqheaderlist:
                if 'referer:' in header.lower():
                    #print(header)
                    httpreferer = header.lower().replace('referer:',"").strip()
                    #httprefererparseresult = urlparse.urlparse(httpreferer)
                    if 'http:' in httpreferer:
                        schema = 'http'

            # check if JS file
            if ".js" in str(urlReq) or '.html' in str(urlReq):
                # Exclude casual JS files
                if any(x in testString for x in JSExclusionList):
                    #print("\n" + "[-] URL excluded " + str(urlReq))
                    pass
                else:
                    #self.outputTxtArea.append("\n[url:]"  + str(urlReq))
                    issueText = linkA.analyseURL()
                    for counter, issueText in enumerate(issueText):
                            #print("TEST Value returned SUCCESS")
                            #self.outputTxtArea.append("\n" + "\t" + str(counter)+' - ' +issueText['link'])
                            linkstr = issueText['link']
                            linkstr = urlparse.urljoin(httpreferer, linkstr)
                            if(linkstr not in LinksResultSet):
                                LinksResultSet.add(linkstr)
                                # if '//' in linkstr and linkstr.index("//") == 0:
                                #     linkstr = schema+":"+linkstr
                                # elif linkstr[0] == '/' and linkstr[1] != '/':
                                #     linkstr = httpreferer + linkstr
                                # elif linkstr[0:2] != 'ht':
                                #     linkstr = httpreferer + '/' + linkstr
                                self.outputTxtArea.append("\n" + linkstr)
                                logging.info(linkstr)
                                # print(linkstr)

                    #issues = ArrayList()
                    #issues.add(SRI(ihrr, self.helpers))
                    #return issues
                    return None
        except UnicodeEncodeError:
            #print ("Error in URL decode.")
            pass
        return None


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print "Burp JS LinkFinder unloaded"
        return


def isblackext(urlpath, blackextlist):
    for ext in blackextlist:
        if ext in urlpath:
            return True
    return False

class linkAnalyse():
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        

    regex_str = """
    
      (?:"|')                               # Start newline delimiter
    
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/\s]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
    
        |
    
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|\s()]{1,})                   # Rest of the characters can't be
    
        |
    
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
    
        |
    
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
    
      )
    
      (?:"|')                               # End newline delimiter
    
    """     

    def	parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        #print ("TEST parselfile #2")
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(1)} for m in re.finditer(regex, content)]
        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items
    
        # Match Regex
        filtered_items = []
        blackextlist = [".js",".css",".font",".jpg",".png",".webp",".gif",".svg",".ttf",".woff",".mp4","www.w3.org",".vue",".less",".sass",".ico","vuejs.org","momentjs.com",\
        "www.beian.gov.cn"]
        for item in items:
            if isblackext(item["link"], blackextlist):
                continue
            if (item["link"][0] == "." or item["link"][0] == "/") and item["link"][-1] == "\\":
                continue
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    #print ("TEST parselfile #3")
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items

    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):
        
        endpoints = ""
        #print("TEST AnalyseURL #1")
        mime_type=self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if mime_type.lower() == 'script':
                url = self.reqres.getUrl()
                encoded_resp=binascii.b2a_base64(self.reqres.getResponse())
                decoded_resp=base64.b64decode(encoded_resp)
                endpoints=self.parser_file(decoded_resp, self.regex_str)
                #print("TEST AnalyseURL #2")
                return endpoints
        return endpoints


class SRI(IScanIssue,ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Linkfinder Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has analysed the following JS file for links: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self.reqres]
        return rra
        
    def getHttpService(self):
        return self.reqres.getHttpService()
        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
