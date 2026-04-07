from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JScrollPane, BoxLayout, JMenuItem, JCheckBox
import java.util.ArrayList as ArrayList
import threading
import subprocess
import os
import tempfile
import json

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AuthSniper-X")
        
        # Build UI configuration tab
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        
        self.binPath = JTextField(50)
        self.binPath.setText(r"C:\Users\User\.gemini\antigravity\scratch\AuthSniper\authsniper.exe")
        
        self.tokenADict = JTextField(30)
        self.tokenADict.setText("Bearer VictimTokenHere")
        
        self.tokenBDict = JTextField(30)
        self.tokenBDict.setText("Bearer AttackerTokenHere")
        
        # New Feature: Passive Scanner Toggle
        self.passiveToggle = JCheckBox("Enable Passive BOLA Scanning (In-Scope HTTP 200 JSON traffic only)", False)
        
        self._panel.add(JLabel("AuthSniper Go Binary Path:"))
        self._panel.add(self.binPath)
        self._panel.add(JLabel("Victim Token / User A (e.g., Bearer XXX or Cookie: id=XXX):"))
        self._panel.add(self.tokenADict)
        self._panel.add(JLabel("Attacker Token / User B (e.g., Bearer YYY or Cookie: id=YYY):"))
        self._panel.add(self.tokenBDict)
        self._panel.add(self.passiveToggle)
        
        self.logArea = JTextArea(20, 50)
        self.logArea.setEditable(False)
        self._panel.add(JLabel("AuthSniper Logs:"))
        self._panel.add(JScrollPane(self.logArea))
        
        callbacks.customizeUiComponent(self._panel)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        
        self.logArea.append("[*] AuthSniper Loaded. Passive Ghost Mode available!\n")

    def getTabCaption(self):
        return "AuthSniper"
        
    def getUiComponent(self):
        return self._panel
        
    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Send to AuthSniper (AST BOLA Test)", actionPerformed=self.menuAction)
        menuList.add(menuItem)
        return menuList
        
    def menuAction(self, event):
        messages = self.context.getSelectedMessages()
        if not messages:
            return
        self.fireSniper(messages[0])

    # The Passive Listener Hook
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.passiveToggle.isSelected():
            return
            
        # Only process Proxy responses to ensure the original request was successful
        if toolFlag == self._callbacks.TOOL_PROXY and not messageIsRequest:
            resp = messageInfo.getResponse()
            if not resp:
                return
                
            respInfo = self._helpers.analyzeResponse(resp)
            # Proceed only if HTTP 2XX or 3XX
            if respInfo.getStatusCode() >= 400:
                return
                
            # Ideally restrict to JSON/XML, simple check based on inferred MIME type
            mimeType = respInfo.getStatedMimeType()
            if mimeType and "JSON" in mimeType.upper():
                # Fast track
                self.fireSniper(messageInfo)

    def fireSniper(self, msg):
        request_bytes = msg.getRequest()
        target_service = msg.getHttpService()
        isHttps = "true" if target_service.getProtocol() == "https" else "false"
        url = self._helpers.analyzeRequest(target_service, request_bytes).getUrl().toString()
        
        # Save raw HTTP request 
        reqTemp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        reqTemp.write(request_bytes)
        reqTemp.close()
        
        # Save config JSON securely
        cfgTemp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode='w')
        configData = {
            "tokenA": self.tokenADict.getText(),
            "tokenB": self.tokenBDict.getText()
        }
        json.dump(configData, cfgTemp)
        cfgTemp.close()
        
        bPath = self.binPath.getText()
        
        def run_sniper():
            cmd = [bPath, "-r", reqTemp.name, "-https=" + isHttps, "-cfg", cfgTemp.name, "-silent"]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                
                if out:
                    # Clean stdout to logs
                    self.logArea.append(f"[*] Endpoint: {url}\n")
                    self.logArea.append(out.decode('utf-8'))
                if err:
                    pass # Ignore generic connection errors in passive mode
                
            except Exception as e:
                self.logArea.append(f"[Error] {str(e)}\n")
            finally:
                os.remove(reqTemp.name)
                os.remove(cfgTemp.name)

        t = threading.Thread(target=run_sniper)
        t.start()
