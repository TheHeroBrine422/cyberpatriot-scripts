import os

prohibitedFiles = [".midi",	".mid",	".mod",	".mp3",	".mp2",	".mpa",	".m4a",	".abs",	".mpega",	".au",	".snd",	".wav",	".aiff",	".aif",	".sid",	".flac",	".ogg",	".aac",	".mpeg",	".mpg",	".mpe",	".dl",	".movie",	".movi",	".mv",	".iff",	".anim5",	".anim3",	".anim7",	".avi",	".vfw",	".avx",	".fli",	".flc",	".mov",	".qt",	".spl",	".swf",	".dcr",	".dir",	".dxr",	".rpm",	".rm",	".smi",	".ra",	".ram",	".rv",	".wmv",	".asf",	".asx",	".wma",	".wax",	".wmv",	".wmx",	".3gp",	".mov",	".mp4",	".avi",	".swf",	".flv",	".m4v",	".tiff",	".tif",	".rs",	".im1", ".rgb",	".xwd",	".ppm",	".pbm",	".pgm",	".pcx",	".ico"	".svgz",	".bmp",	".img",	".txt",	".exe",	".msi",	".bat",	".sh", "Information Gathering","ace-voip","Amap","APT2","arp-scan","Automater","bing-ip2hosts","braa","CaseFile","CDPSnarf","cisco-torch","copy-router-config","DMitry","dnmap","dnsenum","dnsmap","DNSRecon","dnstracer","dnswalk","DotDotPwn","enum4linux","enumIAX","EyeWitness","Faraday","Fierce","Firewalk","fragroute","fragrouter","Ghost Phisher","GoLismero","goofile","hping3","ident-user-enum","InSpy","InTrace","iSMTP","lbd","Maltego Teeth","masscan","Metagoofil","Miranda","nbtscan-unixwiz","Nikto","Nmap","ntop","OSRFramework","Parsero","Recon-ng","SMBMap","smtp-user-enum","snmp-check","SPARTA","sslcaudit","SSLsplit","sslstrip","SSLyze","Sublist3r","THC-IPV6","theHarvester","TLSSLed","twofi","Unicornscan","URLCrazy","Wireshark","WOL-E","Xplico","Vulnerability Analysis","BBQSQL","BED","cisco-auditing-tool","cisco-global-exploiter","cisco-ocs","cisco-torch","copy-router-config","Doona","DotDotPwn","HexorBase","jSQL Injection","Lynis","Nmap","ohrwurm","openvas","Oscanner","Powerfuzzer","sfuzz","SidGuesser","SIPArmyKnife","sqlmap","Sqlninja","sqlsus","THC-IPV6","tnscmd10g","unix-privesc-check","Yersinia","Exploitation Tools","Armitage","Backdoor Factory","BeEF","cisco-auditing-tool","cisco-global-exploiter","cisco-ocs","cisco-torch","Commix","crackle","exploitdb","jboss-autopwn","Linux Exploit Suggester","Maltego Teeth","Metasploit Framework","MSFPC","RouterSploit","ShellNoob","sqlmap","THC-IPV6","Yersinia","Wireless Attacks","Airbase-ng","Aircrack-ng","Airdecap-ng and Airdecloak-ng","Aireplay-ng","airgraph-ng","Airmon-ng","Airodump-ng","airodump-ng-oui-update","Airolib-ng","Airserv-ng","Airtun-ng","Asleap","Besside-ng","Bluelog","BlueMaho","Bluepot","BlueRanger","Bluesnarfer","Bully","coWPAtty","crackle","eapmd5pass","Easside-ng","Fern Wifi Cracker","FreeRADIUS-WPE","Ghost Phisher","GISKismet","Gqrx","gr-scan","hostapd-wpe","ivstools","kalibrate-rtl","KillerBee","Kismet","makeivs-ng","mdk3","mfcuk","mfoc","mfterm","Multimon-NG","Packetforge-ng","PixieWPS","Pyrit","Reaver","redfang","RTLSDR Scanner","Spooftooph","Tkiptun-ng","Wesside-ng","Wifi Honey","wifiphisher","Wifitap","Wifite","wpaclean","Forensics Tools","Binwalk","bulk-extractor","Capstone","chntpw","Cuckoo","dc3dd","ddrescue","DFF","diStorm3","Dumpzilla","extundelete","Foremost","Galleta","Guymager","iPhone Backup Analyzer","pdf-parser","pdfid","pdgmail","peepdf","RegRipper","Volatility","Xplico","Web Applications","apache-users","Arachni","BBQSQL","BlindElephant","Burp Suite","CutyCapt","DAVTest","deblaze","DIRB","DirBuster","fimap","FunkLoad","Gobuster","Grabber","hURL","jboss-autopwn","joomscan","jSQL Injection","Maltego Teeth","Nikto","PadBuster","Paros","Parsero","plecost","Powerfuzzer","ProxyStrike","Recon-ng","Skipfish","sqlmap","Sqlninja","sqlsus","ua-tester","Uniscan","w3af","WebScarab","Webshag","WebSlayer","WebSploit","Wfuzz","WhatWeb","WPScan","XSSer","zaproxy","Stress Testing","DHCPig","FunkLoad","iaxflood","Inundator","inviteflood","ipv6-toolkit","mdk3","Reaver","rtpflood","SlowHTTPTest","t50","Termineter","THC-IPV6","THC-SSL-DOS","Spoofing","bettercap","Burp Suite","DNSChef","fiked","hamster-sidejack","HexInject","iaxflood","inviteflood","iSMTP","isr-evilgrade","mitmproxy","ohrwurm","protos-sip","rebind","responder","rtpbreak","rtpinsertsound","rtpmixsound","sctpscan","SIPArmyKnife","SIPp","SIPVicious","SniffJoke","SSLsplit","sslstrip","THC-IPV6","VoIPHopper","WebScarab","Wireshark","xspy","Yersinia","zaproxy","BruteSpray","Burp Suite","CeWL","chntpw","cisco-auditing-tool","CmosPwd","creddump","crowbar","crunch","findmyhash","gpp-decrypt","hash-identifier","Hashcat","HexorBase","THC-Hydra","hydra","john","John the Ripper","Johnny","keimpx","Maltego Teeth","Maskprocessor","multiforcer","Ncrack","oclgausscrack","ophcrack","patator","phrasendrescher","polenum","RainbowCrack","rcracki-mt","RSMangler","SecLists","SQLdict","Statsprocessor","THC-pptp-bruter","TrueCrack","WebScarab","wordlists","zaproxy","CryptCat","Cymothoa","dbd","dns2tcp","HTTPTunnel","Intersect","Nishang","polenum","PowerSploit","pwnat","RidEnum","sbd","shellter","U3-Pwn","Webshells","Weevely","Winexe","android-sdk","apktool","dex2jar","Sakis3G","smali","apktool","dex2jar","diStorm3","edb-debugger","jad","javasnoop","JD-GUI","OllyDbg","smali","Valgrind","YARA","CaseFile","cherrytree","CutyCapt","dos2unix","Dradis","MagicTree","Metagoofil","Nipper-ng","pipal","RDPY", "bruteforce", "hack", "crack", "vuln", "rootkit"]

def findFiles(dir):
    try:
        files = os.listdir(dir)
        for file in files:
            path = dir+file
            if (os.path.isdir(path) and path != '/proc'):
                findFiles(path+"/")
            for test in prohibitedFiles:
                if path.lower().find(test.lower()) > -1:
                    print(test+": "+path)
                    break
    except:
        pass


findFiles("/home/")
