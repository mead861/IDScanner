from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import re

# Implement BurpExtender to inherit from multiple base classes
# IBurpExtender is the base class required for all extensions
# IScannerCheck lets us register our extension with Burp as a custom scanner check
class BurpExtender(IBurpExtender, IScannerCheck):
    
    # The only method of the IBurpExtender interface.
    # This method is invoked when the extension is loaded and registers
    # an instance of the IBurpExtenderCallbacks interface
    def	registerExtenderCallbacks(self, callbacks):
        # Put the callbacks parameter into a class variable so we have class-level scope
        self._callbacks = callbacks

        # Set the name of our extension, which will appear in the Extender tool when loaded
        self._callbacks.setExtensionName("User ID Scanner")
        
        # Register the user is scanner, so Burp will use this extension
        # to perform active or passive scanning and report on scan issues returned
        self._callbacks.registerScannerCheck(self)
        
        return
 
    # This method is called when multiple issues are reported for the same URL
    # In this case we are checking if the issue detail is different, as the
    # issues from our scans include affected parameters/values in the detail,
    # which we will want to report as unique issue instances
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0
       
    # Implement the doPassiveScan method of IScannerCheck interface
    # Burp Scanner invokes this method for each base request/response that is passively scanned.
    def doPassiveScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        scan_issues = []
        tmp_issues = []
        
        # Create an instance of our CustomScans object, passing the
        # base request and response, and our callbacks object
        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)

        # Call the findReflections method of our CustomScans object to check
        # the request parameters for a reflected parameter value in the response 
       
       
        
        #tmp_issues = self._CustomScans.findReflections(issuename, issuelevel, issuedetail)
        
        # Add the issues from findReflections to the list of issues to be returned
        scan_issues = scan_issues + tmp_issues
        
        tmp_issues = []
        
       # change prefix to match user id format
	   
        regex = "[*prefix*]"
        issuename = "User ID Found"
        issuelevel = "Medium"
        issuedetail = """The application response contains a User ID
                <br><br><b>$ID$</b><br><br>  """
        
        tmp_issues = self._CustomScans.findid(regex, issuename, issuelevel, issuedetail)
        
        # Add the issues from findid to the list of issues to be returned
        scan_issues = scan_issues + tmp_issues
                        
        # Finally, per the interface contract, doPassiveScan needs to return a
        # list of scan issues, if any, and None otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        # Set class variables with the arguments passed to the constructor
        self._requestResponse = requestResponse
        self._callbacks = callbacks
        
        # Get an instance of IHelpers, which has lots of useful methods, as a class
        # variable, so we have class-level scope to all the helper methods
        self._helpers = self._callbacks.getHelpers()
        
        # Put the parameters from the HTTP message in a class variable so we have class-level scope
        self._params = self._helpers.analyzeRequest(requestResponse.getRequest()).getParameters()
        return
    
    # This is a custom scan method to look for potential reflected XSS candidates, by
    # looking for request parameter values that appear in the response.
    # This should be re-factored to include checks for reflection from other input
    # sources such as headers, including cookies.  An exercise for later, naturally.
   
    
    # This is a custom scan method to Look for all occurrences in the response
    # that match the passed regular expression
    def findid(self, regex, issuename, issuelevel, issuedetail):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)
        
        # Compile the regular expression, telling Python to ignore EOL/LF
        myre = re.compile(regex, re.DOTALL)

        # Using the regular expression, find all occurrences in the base response
        match_vals = myre.findall(self._helpers.bytesToString(response))

        # For each matched value found, find its start position, so that we can create
        # the offset needed to apply appropriate markers in the resulting Scanner issue
        for ref in match_vals:
            offsets = []
            start = self._helpers.indexOf(response,
                                ref, True, 0, responseLength)
            offset[0] = start
            offset[1] = start + len(ref)
            offsets.append(offset)
           
            # Create a ScanIssue object and append it to our list of issues, marking
            # the matched value in the response.
            scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                    self._helpers.analyzeRequest(self._requestResponse).getUrl(), 
                    [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                    issuename, issuelevel, issuedetail.replace("$ID$", ref)))

        return (scan_issues)

# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice 

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"