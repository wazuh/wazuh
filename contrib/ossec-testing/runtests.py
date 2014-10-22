import ConfigParser
import subprocess 
import os 
import sys
import os.path 

class OssecTester(object):
    def __init__(self):
        self._error = False
        self._debug = False 
        self._quiet = False 
        self._ossec_conf = "/var/ossec/etc/ossec.conf"
        self._base_dir = "/var/ossec/"
        self._ossec_path = "/var/ossec/bin/"
        self._test_path = "./tests" 

    def buildCmd(self, rule, alert, decoder):
        cmd = ['%s/ossec-logtest'%(self._ossec_path),] 
        if self._ossec_conf: cmd += ["-c",self._ossec_conf]
        if self._base_dir: cmd += ["-D", self._base_dir]
        cmd += ['-U', "%s:%s:%s"%(rule,alert,decoder)]
        return cmd

    def runTest(self, log, rule, alert, decoder, section, name, negate=False):
        #print self.buildCmd(rule, alert, decoder)
        p = subprocess.Popen(self.buildCmd(rule, alert, decoder),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                shell=False)
        std_out = p.communicate(log)[0]
        if (p.returncode != 0 and not negate) or (p.returncode == 0 and negate):
            self._error = True 
            print "" 
            print "-" * 60
            print "Failed: Exit code = %s"%(p.returncode) 
            print "        Alert     = %s"%(alert) 
            print "        Rule      = %s"%(rule)
            print "        Decoder   = %s"%(decoder)
            print "        Section   = %s"%(section)
            print "        line name = %s"%(name)
            print " " 
            print std_out 
        elif self._debug:
            print "Exit code= %s"%(p.returncode) 
            print std_out
        else:
            sys.stdout.write(".")

    def run(self):
        for aFile in os.listdir(self._test_path):
            aFile = os.path.join(self._test_path, aFile)
            print "- [ File = %s ] ---------"%(aFile)
            if aFile.endswith(".ini"):
                tGroup = ConfigParser.ConfigParser()
                tGroup.read([aFile])
                tSections = tGroup.sections()
                for t in tSections:
                    rule = tGroup.get(t, "rule")
                    alert = tGroup.get(t, "alert")
                    decoder = tGroup.get(t, "decoder")
                    for (name, value) in tGroup.items(t):
                        if name.startswith("log "):
                            if self._debug: 
                                print "-"* 60
                            if name.endswith("pass"):
                                neg = False 
                            elif name.endswith("fail"):
                                neg = True
                            else:
                                neg = False 
                            self.runTest(value, rule, alert, decoder, t, name, negate=neg)
                print ""
        if self._error: 
            sys.exit(1)

if __name__ == "__main__":
    OT = OssecTester()
    OT.run() 






