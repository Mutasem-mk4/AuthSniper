from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JScrollPane, BoxLayout, JMenuItem
from java.awt import BorderLayout
from java.io import PrintWriter
import java.util.ArrayList as ArrayList
import threading
import subprocess
import os
import tempfile

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AuthSniper-X")
        
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
        # Build UI configuration tab
        self._panel = JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))
        
        self.binPath = JTextField(50)
        self.binPath.setText(r"C:\Users\User\.gemini\antigravity\scratch\AuthSniper\authsniper.exe")
        
        self.tokenADict = JTextField(30)
        self.tokenADict.setText("Bearer VictimTokenHere")
        
        self.tokenBDict = JTextField(30)
        self.tokenBDict.setText("Bearer AttackerTokenHere")
        
        self._panel.add(JLabel("AuthSniper Go Binary Path:"))
        self._panel.add(self.binPath)
        self._panel.add(JLabel("Victim Token / User A (e.g., Bearer XXX or Cookie: id=XXX):"))
        self._panel.add(self.tokenADict)
        self._panel.add(JLabel("Attacker Token / User B (e.g., Bearer YYY or Cookie: id=YYY):"))
        self._panel.add(self.tokenBDict)
        
        self.logArea = JTextArea(20, 50)
        self.logArea.setEditable(False)
        self._panel.add(JLabel("AuthSniper Logs:"))
        self._panel.add(JScrollPane(self.logArea))
        
        callbacks.customizeUiComponent(self._panel)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        self.stdout.println("AuthSniper-X Extension Loaded Successfully!")
        self.logArea.append("[*] AuthSniper loaded. Configure your tokens above and right-click any request to test for BOLA!\n")

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
            
        msg = messages[0]
        request_bytes = msg.getRequest()
        target_service = msg.getHttpService()
        isHttps = "true" if target_service.getProtocol() == "https" else "false"
        url = self._helpers.analyzeRequest(target_service, request_bytes).getUrl().toString()
        
        # Save raw HTTP request to temp file
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        temp.write(request_bytes)
        temp.close()
        
        tokenA = self.tokenADict.getText()
        tokenB = self.tokenBDict.getText()
        bPath = self.binPath.getText()
        
        def run_sniper():
            self.logArea.append(f"[*] Analyzing Endpoint: {url}\n")
            cmd = [bPath, "-r", temp.name, "-https=" + isHttps, "-t1", tokenA, "-t2", tokenB, "-silent"]
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                
                if out:
                    self.logArea.append(out.decode('utf-8'))
                if err:
                    # Ignore minor warnings if any, but log errors
                    self.logArea.append(err.decode('utf-8'))
                
            except Exception as e:
                self.logArea.append(f"[Error Executing Go Binary] {str(e)}\n")
            finally:
                os.remove(temp.name)

        # Run via thread to avoid freezing Burp UI
        t = threading.Thread(target=run_sniper)
        t.start()
