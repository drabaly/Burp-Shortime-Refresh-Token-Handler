from burp import IBurpExtender, IHttpListener, ISessionHandlingAction, IHttpService
from java.net import URL
import json

TARGETURL = URL("FIXME") # FIXME: Put the URL to get the token here
PORT = 443
BODY = "grant_type=refresh_token&refresh_token={token}" # FIXME: You might need to add other parameters

print(TARGETURL.getPath())

class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._access_token = None
        self._refresh_token = None
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("Update refresh token")
        callbacks.registerSessionHandlingAction(self)
        return


    def getActionName(self):
        return "Update refresh token"

    def performAction(self, currentRequest, macroItems):
        if self._refresh_token is None:
            print("Please authenticate manually so the refresh token is set")
            return
        httpService = self._helpers.buildHttpService(TARGETURL.getHost(), PORT, TARGETURL.getProtocol())

        body = BODY.format(token=self._refresh_token)
        headers = [
            "POST " + TARGETURL.getPath() + " HTTP/1.1",
            "Host: " + TARGETURL.getHost(),
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: " + str(len(body)),
            "Connection: close"
        ]

        request = self._helpers.stringToBytes("\r\n".join(headers) + "\r\n\r\n" + body)
        self._callbacks.makeHttpRequest(httpService, request)
        print("[-] Authentication request performed")

    def handleRequest(self, content):
        if self._access_token is None:
            return
        request = content.getRequest()
        requestInfo = self._helpers.analyzeRequest(request)
        headers = requestInfo.getHeaders()
        for i in range(len(headers)):
            if "Authorization" in headers[i]:
                headers[i] = "Authorization: Bearer " + self._access_token
                headersString = "\r\n".join(headers)
                body = self._helpers.bytesToString(request[requestInfo.getBodyOffset():])
                newRequest = headersString + "\r\n\r\n" + body
                content.setRequest(self._helpers.stringToBytes(newRequest))

    def handleResponse(self, content):
        requestInfo = self._helpers.analyzeRequest(content.getRequest())
        requestHeaders = requestInfo.getHeaders()
        response = content.getResponse()
        if response and TARGETURL.getPath() in requestHeaders[0]:
            responseInfo = self._helpers.analyzeResponse(response)
            body = self._helpers.bytesToString(response[responseInfo.getBodyOffset():])
            result = json.loads(body)
            if "access_token" in result:
                print("[+] Access token: " + result["access_token"])
                print("[+] Refresh token: " + result["refresh_token"])
                self._access_token = result["access_token"]
                self._refresh_token = result["refresh_token"]

    def processHttpMessage(self, tool, is_request, content):
        if is_request and tool in [self._callbacks.TOOL_SCANNER, self._callbacks.TOOL_EXTENDER]:
            self.handleRequest(content)
        else:
            self.handleResponse(content)
