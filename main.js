/*
TODO:
Test everything.
Auto Updates (only possible through GUI AFAIK) and security upgrades
*/

// options:
let you = "hero"
let admins = [you, ""]
let standardUsers = [""]
let distro = "ubuntu" // Options: 'ubuntu' or 'debian'
// Still options, but not needed to change:
let password = "Cyb3rPatr!0t$" // this password is a bit short.
let prohibitedSoftware = ["hydra"] // TODO: find a good list for this.
let prohibitedFiles = [".mp4", ".mp3"] // TODO: find a good list for this.
let debug = true // currently makes simpleExec log all stdout


// code:
const { execSync } = require('child_process');
const fs = require('fs')
const path = require("path");

let allUsers = admins.join(standardUsers);
let uids = [];
let files = [];
let badFiles = [];
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
              badFiles.push(files[i])
              break
            }
          }
        return "";
      }
  });
}

async function simpleExec(cmd) {
  try {
    stdout = (await execSync(cmd)).toString()
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
  await modifyLines("/etc/pam.d/common-password", [["pam_unix.so", "password   required   pam_unix.so minlen=8 remember=5"], ["pam.cracklib.so","password   required   pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"]])
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

  console.log("Programs listening to ports:\n use `lsof -i :$port` to determine the program listening.")
  ports = (await simpleExec('ss -ln')).split("\n")
  for (var i = 0; i < ports.length; i++) {
    if (ports[i].toLowerCase().includes("127.0.0.1".toLowerCase()) && ports[i].toLowerCase().includes("LISTEN".toLowerCase())) {
      console.log(ports[i])
    }
  }

  console.log("checking user accounts. Delete users with userdel --remove $user")
  passwd = await fs.readFileSync("/etc/passwd").toString()
  await fs.writeFileSync("passwd_backup", passwd)
  passwd = passwd.split("\n")
  for (let i = 0; i < passwd.length; i++) {
    passwd[i] = passwd[i].split(':');
    seenUsers.push(passwd[i][0])

    if (passwd[i][2] > 1000 && allUsers.indexOf(passwd[i][0]) > -1 && passwd[i][0].toLowerCase() != you.toLowerCase()) {
      await simpleExec('echo \"'+passwd[i][0]+':'+password+'\" | chpasswd')
    } else if (passwd[i][2] > 1000 && allUsers.indexOf(passwd[i][0]) < 0) {
      console.log("This user likely needs to be deleted "+passwd[i][0])
    } else if (passwd[i][2] < 1000 && allUsers.indexOf(passwd[i][0]) > -1) {
      console.log("This user looks a bit weird due to UID: "+passwd[i].join(":"))
    } else {
      await simpleExec('usermod --shell /sbin/nologin '+passwd[i][0])
    }

    passwd[i] = passwd[i].join(":")
  }

  console.log("checking groups")
  group = await fs.readFileSync("/etc/group").toString()
  await fs.writeFileSync("group_backup", group)
  group = group.split("\n")
  for (let i = 0; i < group.length; i++) {
    group[i] = group[i].split(':');

    if (group[i][0].includes('adm') || group[i][0].includes('sudo')) {
      group[3] = admins.join(",")
    }

    group[i] = group[i].join(":")
  }
  await fs.writeFileSync("/etc/group", group.join("\n"))

  console.log("lynis system report:")
  await simpleExec('git clone https://github.com/CISOfy/lynis')
  await simpleExec('chmod 777 -R lynis')
  await simpleExec('cd lynis')
  console.log(await simpleExec('./lynis audit system'))

  console.log("scanning for prohibited programs.")

  dpkgList = (await simpleExec('dpkg -l')).split('\n')

  for (let i = 0; i < dpkgList.length; i++) {
    for (let j = 0; j < prohibitedSoftware.length; j++) {
      if (dpkgList[i].toLowerCase().includes(prohibitedSoftware[j].toLowerCase())) {
        badSoftware.push(dpkgList[i])
        break
      }
    }
  }

  console.log(badSoftware.join('\n'))

  console.log("\n\n\nThe script is mostly done now. It will now scan for prohibited files but this will take a long time.\n\nWhat to do next:\nUpdate the system using apt update and apt dist-upgrade\nCheck crontabs and services\nEnable auto updates and auto software updates.\nCheck above suggested files, programs, and lynis report.\nDouble check /etc/passwd and /etc/group\nDouble check installed programs and files.\nAlso might want to make sure the system reboots properly when you reboot to make sure none of the updates or config file changes failed.")

  console.log("\nscanning for prohibited files. This could take a while.")
  await findFiles("/");
  console.log(badFiles.join('\n'))
  console.log("rm -rf "+badFiles.join(' '))

})();
