from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JScrollPane, BoxLayout, JMenuItem, JCheckBox
import java.util.ArrayList as ArrayList
import threading
import json
import traceback

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AuthSniper BApp (Native AST)")
        
        self.stdout = callbacks.getStdout()
        
        # Build UI configuration tab
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        
        self.tokenADict = JTextField(30)
        self.tokenADict.setText("Bearer VictimTokenHere")
        
        self.tokenBDict = JTextField(30)
        self.tokenBDict.setText("Bearer AttackerTokenHere")
        
        # Passive Scanner Toggle
        self.passiveToggle = JCheckBox("Enable Passive BOLA Scanning (100% Native JVM, Zero Binary Executions)", False)
        
        self._panel.add(JLabel("Victim Token / User A (e.g., Bearer XXX or Cookie: id=XXX):"))
        self._panel.add(self.tokenADict)
        self._panel.add(JLabel("Attacker Token / User B (e.g., Bearer YYY or Cookie: id=YYY):"))
        self._panel.add(self.tokenBDict)
        self._panel.add(self.passiveToggle)
        
        self.logArea = JTextArea(20, 50)
        self.logArea.setEditable(False)
        self._panel.add(JLabel("AuthSniper Live AST Hunting Logs:"))
        self._panel.add(JScrollPane(self.logArea))
        
        callbacks.customizeUiComponent(self._panel)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        
        self.printLog("[*] AuthSniper Native BApp Loaded. 100% Jython AST engine active.")

    def printLog(self, message):
        self.logArea.append(message + "\n")
        self.logArea.setCaretPosition(self.logArea.getDocument().getLength())

    def getTabCaption(self):
        return "AuthSniper"
        
    def getUiComponent(self):
        return self._panel
        
    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Send to AuthSniper (Native BOLA Scan)", actionPerformed=self.menuAction)
        menuList.add(menuItem)
        return menuList
        
    def menuAction(self, event):
        messages = self.context.getSelectedMessages()
        if not messages:
            return
        # Run on a background thread to keep Burp UI responsive
        t = threading.Thread(target=self.fireSniper, args=(messages[0],))
        t.start()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.passiveToggle.isSelected():
            return
            
        if toolFlag == self._callbacks.TOOL_PROXY and not messageIsRequest:
            resp = messageInfo.getResponse()
            if not resp:
                return
                
            respInfo = self._helpers.analyzeResponse(resp)
            if respInfo.getStatusCode() >= 400:
                return
                
            mimeType = respInfo.getStatedMimeType()
            if mimeType and "JSON" in mimeType.upper():
                t = threading.Thread(target=self.fireSniper, args=(messageInfo, True))
                t.start()

    def swap_auth(self, request_bytes, new_token):
        reqInfo = self._helpers.analyzeRequest(request_bytes)
        headers = reqInfo.getHeaders()
        body = request_bytes[reqInfo.getBodyOffset():]
        
        new_headers = []
        auth_swapped = False
        
        if "Bearer " in new_token:
            for header in headers:
                if header.lower().startswith("authorization:"):
                    new_headers.append("Authorization: " + new_token)
                    auth_swapped = True
                else:
                    new_headers.append(header)
            if not auth_swapped:
                new_headers.append("Authorization: " + new_token)
        elif "Cookie:" in new_token or "=" in new_token:
            for header in headers:
                if header.lower().startswith("cookie:"):
                    new_headers.append("Cookie: " + new_token.replace("Cookie: ", ""))
                    auth_swapped = True
                else:
                    new_headers.append(header)
            if not auth_swapped:
                new_headers.append("Cookie: " + new_token.replace("Cookie: ", ""))
        else:
             new_headers = list(headers)
             new_headers.append(new_token)
             
        return self._helpers.buildHttpMessage(new_headers, body)

    def extract_json(self, response_bytes):
        if not response_bytes:
            return None
        respInfo = self._helpers.analyzeResponse(response_bytes)
        offset = respInfo.getBodyOffset()
        body_string = self._helpers.bytesToString(response_bytes[offset:])
        try:
            return json.loads(body_string)
        except Exception:
            return None

    def get_structure(self, value):
        if isinstance(value, dict):
            struct = {}
            for k, v in value.items():
                struct[k] = self.get_structure(v)
            return struct
        elif isinstance(value, (list, tuple)):
            if len(value) > 0:
                struct_first = self.get_structure(value[0])
                return ["ARRAY", struct_first]
            return ["ARRAY", "EMPTY"]
        elif isinstance(value, (int, long, float)):
            return "NUMBER"
        elif isinstance(value, basestring):
            return "STRING"
        elif isinstance(value, bool):
            return "BOOL"
        return "NULL"

    def is_generic_error(self, val):
        if not isinstance(val, dict):
            return False
        
        lower_keys = [k.lower() for k in val.keys()]
        if "error" in lower_keys or "errors" in lower_keys:
            return True
        
        for k, v in val.items():
            k_low = k.lower()
            if k_low == "status":
                if isinstance(v, basestring) and v.lower() in ("error", "fail", "false", "unauthorized"):
                    return True
                if isinstance(v, bool) and not v:
                    return True
            if k_low == "message" and isinstance(v, basestring):
                v_low = v.lower()
                if "unauthorized" in v_low or "forbidden" in v_low or "not found" in v_low or "expired" in v_low:
                    return True
        return False

    def fireSniper(self, msg, is_passive=False):
        try:
            target_service = msg.getHttpService()
            request_bytes = msg.getRequest()
            
            attacker_token = self.tokenBDict.getText()
            if not attacker_token or "AttackerTokenHere" in attacker_token:
                if not is_passive:
                    self.printLog("[-] Please set your Attacker Token first.")
                return

            req_info = self._helpers.analyzeRequest(target_service, request_bytes)
            url = req_info.getUrl().toString()
            
            victim_resp_bytes = msg.getResponse()
            if not victim_resp_bytes and not is_passive:
                 victim_req = self.swap_auth(request_bytes, self.tokenADict.getText())
                 victim_http = self._callbacks.makeHttpRequest(target_service, victim_req)
                 victim_resp_bytes = victim_http.getResponse()
            
            if not victim_resp_bytes:
                return
                
            victim_info = self._helpers.analyzeResponse(victim_resp_bytes)
            if victim_info.getStatusCode() >= 400:
                if not is_passive:
                    self.printLog("[*] Skipping " + url + " - Victim request returned " + str(victim_info.getStatusCode()))
                return

            victim_json = self.extract_json(victim_resp_bytes)
            if not victim_json:
                if not is_passive:
                    self.printLog("[-] Skipping " + url + " - No JSON found in Victim response.")
                return

            if self.is_generic_error(victim_json):
                 return

            # Execute Attacker Request Natively
            attacker_req = self.swap_auth(request_bytes, attacker_token)
            attacker_http = self._callbacks.makeHttpRequest(target_service, attacker_req)
            attacker_resp_bytes = attacker_http.getResponse()
            
            if not attacker_resp_bytes:
                return
            
            attacker_info = self._helpers.analyzeResponse(attacker_resp_bytes)
            if attacker_info.getStatusCode() >= 400:
                return 
                
            attacker_json = self.extract_json(attacker_resp_bytes)
            if not attacker_json:
                return

            if self.is_generic_error(attacker_json):
                return

            # AST Verification
            struct_v = self.get_structure(victim_json)
            struct_a = self.get_structure(attacker_json)
            
            if struct_v == struct_a:
                self.printLog("\n[!!!] BOLA DETECTED - AST 100% Match\n -> Target: " + url)
            else:
                 if not is_passive:
                    self.printLog("[-] Safe: " + url)
                    
        except Exception as e:
            self.printLog("[EXCEPTION] " + str(e) + "\n" + traceback.format_exc())
