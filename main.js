/*
TODO:
Test changing user passwords and setting admin groups.
Test Prohibited files scan. Have never actually let it finish.
Auto Updates (only possible through GUI AFAIK) and security upgrades
*/

// options:
let you = "hero"
let admins = [you, ""]
let standardUsers = [""]
let distro = "ubuntu" // Options: 'ubuntu' or 'debian'
// Still options, but not needed to change:
let password = "Cyb3rPatr!0t$" // this password is a bit short.
let prohibitedSoftware = ["Information Gathering","ace-voip","Amap","APT2","arp-scan","Automater","bing-ip2hosts","braa","CaseFile","CDPSnarf","cisco-torch","copy-router-config","DMitry","dnmap","dnsenum","dnsmap","DNSRecon","dnstracer","dnswalk","DotDotPwn","enum4linux","enumIAX","EyeWitness","Faraday","Fierce","Firewalk","fragroute","fragrouter","Ghost Phisher","GoLismero","goofile","hping3","ident-user-enum","InSpy","InTrace","iSMTP","lbd","Maltego Teeth","masscan","Metagoofil","Miranda","nbtscan-unixwiz","Nikto","Nmap","ntop","OSRFramework","p0f","Parsero","Recon-ng","SET","SMBMap","smtp-user-enum","snmp-check","SPARTA","sslcaudit","SSLsplit","sslstrip","SSLyze","Sublist3r","THC-IPV6","theHarvester","TLSSLed","twofi","Unicornscan","URLCrazy","Wireshark","WOL-E","Xplico","Vulnerability Analysis","BBQSQL","BED","cisco-auditing-tool","cisco-global-exploiter","cisco-ocs","cisco-torch","copy-router-config","Doona","DotDotPwn","HexorBase","jSQL Injection","Lynis","Nmap","ohrwurm","openvas","Oscanner","Powerfuzzer","sfuzz","SidGuesser","SIPArmyKnife","sqlmap","Sqlninja","sqlsus","THC-IPV6","tnscmd10g","unix-privesc-check","Yersinia","Exploitation Tools","Armitage","Backdoor Factory","BeEF","cisco-auditing-tool","cisco-global-exploiter","cisco-ocs","cisco-torch","Commix","crackle","exploitdb","jboss-autopwn","Linux Exploit Suggester","Maltego Teeth","Metasploit Framework","MSFPC","RouterSploit","SET","ShellNoob","sqlmap","THC-IPV6","Yersinia","Wireless Attacks","Airbase-ng","Aircrack-ng","Airdecap-ng and Airdecloak-ng","Aireplay-ng","airgraph-ng","Airmon-ng","Airodump-ng","airodump-ng-oui-update","Airolib-ng","Airserv-ng","Airtun-ng","Asleap","Besside-ng","Bluelog","BlueMaho","Bluepot","BlueRanger","Bluesnarfer","Bully","coWPAtty","crackle","eapmd5pass","Easside-ng","Fern Wifi Cracker","FreeRADIUS-WPE","Ghost Phisher","GISKismet","Gqrx","gr-scan","hostapd-wpe","ivstools","kalibrate-rtl","KillerBee","Kismet","makeivs-ng","mdk3","mfcuk","mfoc","mfterm","Multimon-NG","Packetforge-ng","PixieWPS","Pyrit","Reaver","redfang","RTLSDR Scanner","Spooftooph","Tkiptun-ng","Wesside-ng","Wifi Honey","wifiphisher","Wifitap","Wifite","wpaclean","Forensics Tools","Binwalk","bulk-extractor","Capstone","chntpw","Cuckoo","dc3dd","ddrescue","DFF","diStorm3","Dumpzilla","extundelete","Foremost","Galleta","Guymager","iPhone Backup Analyzer","p0f","pdf-parser","pdfid","pdgmail","peepdf","RegRipper","Volatility","Xplico","Web Applications","apache-users","Arachni","BBQSQL","BlindElephant","Burp Suite","CutyCapt","DAVTest","deblaze","DIRB","DirBuster","fimap","FunkLoad","Gobuster","Grabber","hURL","jboss-autopwn","joomscan","jSQL Injection","Maltego Teeth","Nikto","PadBuster","Paros","Parsero","plecost","Powerfuzzer","ProxyStrike","Recon-ng","Skipfish","sqlmap","Sqlninja","sqlsus","ua-tester","Uniscan","w3af","WebScarab","Webshag","WebSlayer","WebSploit","Wfuzz","WhatWeb","WPScan","XSSer","zaproxy","Stress Testing","DHCPig","FunkLoad","iaxflood","Inundator","inviteflood","ipv6-toolkit","mdk3","Reaver","rtpflood","SlowHTTPTest","t50","Termineter","THC-IPV6","THC-SSL-DOS","Spoofing","bettercap","Burp Suite","DNSChef","fiked","hamster-sidejack","HexInject","iaxflood","inviteflood","iSMTP","isr-evilgrade","mitmproxy","ohrwurm","protos-sip","rebind","responder","rtpbreak","rtpinsertsound","rtpmixsound","sctpscan","SIPArmyKnife","SIPp","SIPVicious","SniffJoke","SSLsplit","sslstrip","THC-IPV6","VoIPHopper","WebScarab","Wireshark","xspy","Yersinia","zaproxy","BruteSpray","Burp Suite","CeWL","chntpw","cisco-auditing-tool","CmosPwd","creddump","crowbar","crunch","findmyhash","gpp-decrypt","hash-identifier","Hashcat","HexorBase","THC-Hydra","hydra","john","John the Ripper","Johnny","keimpx","Maltego Teeth","Maskprocessor","multiforcer","Ncrack","oclgausscrack","ophcrack","PACK","patator","phrasendrescher","polenum","RainbowCrack","rcracki-mt","RSMangler","SecLists","SQLdict","Statsprocessor","THC-pptp-bruter","TrueCrack","WebScarab","wordlists","zaproxy","CryptCat","Cymothoa","dbd","dns2tcp","HTTPTunnel","Intersect","Nishang","polenum","PowerSploit","pwnat","RidEnum","sbd","shellter","U3-Pwn","Webshells","Weevely","Winexe","android-sdk","apktool","Arduino","dex2jar","Sakis3G","smali","apktool","dex2jar","diStorm3","edb-debugger","jad","javasnoop","JD-GUI","OllyDbg","smali","Valgrind","YARA","CaseFile","cherrytree","CutyCapt","dos2unix","Dradis","MagicTree","Metagoofil","Nipper-ng","pipal","RDPY", "bruteforce", "hack", "crack", "vuln", "rootkit"]
let prohibitedFiles = [	".midi",	".mid",	".mod",	".mp3",	".mp2",	".mpa",	".m4a",	".abs",	".mpega",	".au",	".snd",	".wav",	".aiff",	".aif",	".sid",	".flac",	".ogg",	".aac",	".mpeg",	".mpg",	".mpe",	".dl",	".movie",	".movi",	".mv",	".iff",	".anim5",	".anim3",	".anim7",	".avi",	".vfw",	".avx",	".fli",	".flc",	".mov",	".qt",	".spl",	".swf",	".dcr",	".dir",	".dxr",	".rpm",	".rm",	".smi",	".ra",	".ram",	".rv",	".wmv",	".asf",	".asx",	".wma",	".wax",	".wmv",	".wmx",	".3gp",	".mov",	".mp4",	".avi",	".swf",	".flv",	".m4v",	".tiff",	".tif",	".rs",	".im1",	".gif",	".jpeg",	".jpg",	".jpe",	".png",	".rgb",	".xwd",	".xpm",	".ppm",	".pbm",	".pgm",	".pcx",	".ico",	".svg",	".svgz",	".bmp",	".img",	".txt",	".exe",	".msi",	".bat",	".sh", ...prohibitedSoftware]
let debug = false // currently makes simpleExec log all stdout


// code:
const { execSync } = require('child_process');
const fs = require('fs')
const path = require("path");

let allUsers = admins.join(standardUsers);
let uids = [];
let files = [];
let badSoftware = [];
let seenUsers = [];

async function findFiles(Directory) { // https://stackoverflow.com/a/63111390
  fs.readdirSync(Directory).forEach(File => {
      const absolute = path.join(Directory, File);
      if (fs.statSync(absolute).isDirectory()) {
        findFiles(absolute)
      } else {
          for (let j = 0; j < prohibitedFiles.length; j++) {
            if (absolute.toLowerCase().includes(prohibitedFiles[j].toLowerCase())) {
              console.log(files[i])
              break
            }
          }
        return "";
      }
  });
}

async function simpleExec(cmd) {
  try {
    stdout = await execSync(cmd, (err, stdout, stderr) => {
      if (err) {
       return stderr.toString();
      }
      return stdout.toString()
    });
    if (debug) {
      console.log(stdout)
    }
    return stdout
  } catch (e) {
    return e
  }
}

async function modifyLines(fileName, lines) {
  if (fs.existsSync(fileName)) {
    file = fs.readFileSync(fileName).toString()
    await fs.writeFileSync(fileName.replace(/\//g, '-')+"_backup", file)
    file = file.split("\n")
    for (var i = 0; i < lines.length; i++) {
      found = false
      for (var j = 0; j < file.length; j++) {
        if (file[j].toLowerCase().includes(lines[i][0].toLowerCase())) {
          file[j] = lines[i][1]
          found = true
          break
        }
      }
      if (!found) {
        file.push(lines[i][1])
      }
    }

    await fs.writeFileSync(fileName, file.join("\n"))
  }
}

(async () => {
  console.log("Installing needed programs.")
  await simpleExec('apt -y update')
  await simpleExec('apt -y install clamtk ufw libpam-cracklib git')
  console.log("enabling firewall.")
  await simpleExec('ufw enable')
  console.log("basic configuration (sshd, lightdm, password settings and lockout)")
  await simpleExec('passwd -l root')
  await simpleExec('chmod 640 /etc/shadow')
  await modifyLines("/etc/ssh/sshd_config", [["PermitRootLogin", "PermitRootLogin no"],
  ["LoginGraceTime", "LoginGraceTime 60"],
  ["Protocol", "Protocol 2"],
  ["PermitEmptyPasswords", "PermitEmptyPasswords no"],
  ["PasswordAuthentication", "PasswordAuthentication yes"],
  ["X11Fowarding", "X11Fowarding no"],
  ["UsePAM", "UsePAM yes"]])
  await modifyLines("/etc/lightdm/lightdm.conf", [["allow-guest", "allow-guest=false"],
  ["greeter0-hide-users", "greeter0hide-users=true"],
  ["greeter-show-manual-login"," greeter-show-manual-login=true"],
  ["autologin-user","autologin-user=none"]])
  await modifyLines("/etc/login.defs", [["PASS_MIN_DAYS", "PASS_MIN_DAYS 7"],
  ["PASS_MAX_DAYS", "PASS_MAX_DAYS 90"],
  ["PASS_WARN_AGE", "PASS_WARN_AGE 14"],
  ["FAILLOG_ENAB", "FAILLOG_ENAB YES"],
  ["LOG_UNKFAIL_ENAB", "LOG_UNKFAIL_ENAB YES"],
  ["SYSLOG_SU_ENAB", "SYSLOG_SU_ENAB YES"],
  ["SYSLOG_SG_ENAB", "SYSLOG_SG_ENAB YES"]])
  await modifyLines("/etc/pam.d/common-password", [["pam_unix.so", "password  [success=1 default=ignore]  pam_unix.so obscure use_authtok try_first_pass sha512 minlen=8 remember=5"], ["pam_cracklib.so","password   requisite   pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"]])
  await modifyLines("/etc/pam.d/common-auth", [["pam_tally2.so", "auth required pam_tally2.so  file=/var/log/tallylog deny=3 even_deny_root unlock_time=1800"]])
  await simpleExec('sysctl -p')
  await modifyLines("/etc/sysctl.conf", [["net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.all.accept_redirects = 0"],
  ["net.ipv4.ip_forward", "net.ipv4.ip_forward = 0"],
  ["net.ipv4.conf.all.send_redirects", "net.ipv4.conf.all.send_redirects = 0"],
  ["net.ipv4.conf.default.send_redirects", "net.ipv4.conf.default.send_redirects = 0"],
  ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.rp_filter=1"],
  ["net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.all.accept_source_route=0"],
  ["net.ipv4.tcp_max_syn_backlog", "net.ipv4.tcp_max_syn_backlog = 2048"],
  ["net.ipv4.tcp_synack_retries", "net.ipv4.tcp_synack_retries = 2"],
  ["net.ipv4.tcp_syn_retries", "net.ipv4.tcp_syn_retries = 5"],
  ["net.ipv4.tcp_syncookies", "net.ipv4.tcp_syncookies = 1"],
  ["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.all.disable_ipv6 = 1"],
  ["net.ipv6.conf.default.disable_ipv6", "net.ipv6.conf.default.disable_ipv6=1"],
  ["net.ipv6.conf.lo.disable_ipv6", "net.ipv6.conf.lo.disable_ipv6=1"]])

  console.log("Programs listening to ports:\nuse `lsof -i :$port` to determine the program listening.")
  ports = (await simpleExec('ss -ln')).toString()
  ports = ports.split("\n")
  for (var i = 0; i < ports.length; i++) {
    if (ports[i].toLowerCase().includes("127.0.0.1".toLowerCase()) && ports[i].toLowerCase().includes("LISTEN".toLowerCase())) {
      console.log(ports[i])
    }
  }

  console.log("\nchecking user accounts. Delete users with userdel --remove $user")
  passwd = await fs.readFileSync("/etc/passwd").toString()
  oddUsers = []
  await fs.writeFileSync("passwd_backup", passwd)
  passwd = passwd.split("\n")
  for (let i = 0; i < passwd.length-1; i++) {
    passwd[i] = passwd[i].split(':');
    seenUsers.push(passwd[i][0])

    if (passwd[i][2] > 1000 && allUsers.indexOf(passwd[i][0]) > -1 && passwd[i][0].toLowerCase() != you.toLowerCase()) {
      await simpleExec('echo \"'+passwd[i][0]+':'+password+'\" | chpasswd')
      //console.log("User password changed: "+passwd[i][0])
    } else if (passwd[i][2] > 1000 && allUsers.indexOf(passwd[i][0]) < 0) {
      console.log("This user likely needs to be deleted "+passwd[i][0])
    } else if (passwd[i][2] < 1000 && allUsers.indexOf(passwd[i][0]) > -1) {
      console.log("This user looks a bit weird due to UID: "+passwd[i].join(":"))
    } else if (passwd[i][2] < 1000) {
      await simpleExec('usermod --shell /sbin/nologin '+passwd[i][0])
      //console.log("User changed: "+passwd[i][0]+':'+passwd[i][2])
    } else {
      oddUsers.push(passwd[i][0])
    }

    passwd[i] = passwd[i].join(":")
  }

  for (var i = 0; i < oddUsers.length; i++) {
    console.log("Odd User: "+oddUsers[i])
  }

  console.log("checking groups")
  group = await fs.readFileSync("/etc/group").toString()
  await fs.writeFileSync("group_backup", group)
  group = group.split("\n")
  for (let i = 0; i < group.length; i++) {
    group[i] = group[i].split(':');

    if (group[i][0].includes('adm') || group[i][0].includes('sudo')) {
      group[3] = "syslog,"+admins.join(",")
    }

    group[i] = group[i].join(":")
  }
  await fs.writeFileSync("/etc/group", group.join("\n"))

  console.log("installing lynis")
  await simpleExec('git clone https://github.com/CISOfy/lynis')
  await simpleExec('chmod 777 -R lynis')
  await simpleExec('chown -R '+you+':'+you+' lynis')

  console.log("scanning for prohibited programs.")

  dpkgList = (await simpleExec('dpkg -l')).toString().split('\n')

  for (let i = 0; i < dpkgList.length; i++) {
    for (let j = 0; j < prohibitedSoftware.length; j++) {
      if (dpkgList[i].toLowerCase().includes(prohibitedSoftware[j].toLowerCase())) {
        badSoftware.push(dpkgList[i])
        break
      }
    }
  }

  console.log(badSoftware.join('\n'))

  console.log("\n\n\nThe script is mostly done now. It will now scan for prohibited files but this will take a long time.\n\nWhat to do next:\nRun lynis. It has already been installed. ./lynis aduit system\nUpdate the system using apt update and apt dist-upgrade\nCheck crontabs and services\nEnable auto updates and auto software updates.\nCheck above suggested files, programs, and users.\nDouble check /etc/passwd and /etc/group\nDouble check installed programs and files.\nAlso might want to make sure the system reboots properly when you reboot to make sure none of the updates or config file changes failed.")

  console.log("\nscanning for prohibited files. This could take a while.")
  await execSync('python3 files.py')

})();
