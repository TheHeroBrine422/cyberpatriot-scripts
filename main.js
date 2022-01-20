/*
TODO:
User checks (/etc/passwd and /etc/groups and /home)
Program checks (dpkg and apt)
Auto Updates (only possible through GUI AFAIK) and security upgrades
apt upgrade and apt dist-upgrade
https://github.com/CISOfy/Lynis
*/

let you = "hero"
let users = [""]
let admins = [you, ""]
let password = "Cyb3rPatr!0t$"

const { exec } = require('child_process');
const fs = require('fs')

async function simpleExec(cmd) {
  return await exec('sudo su -', (err, stdout, stderr) => {
    if (err) {
      console.log(stderr)
      return ""
    }
    return stdout
  });
}

async function modifyLines(fileName, lines) {
  if (path.existsSync(fileName)) {
    file = fs.readFileSync(fileName).split("\n")
    for (var i = 0; i < lines.length; i++) {
      found = false
      for (var j = 0; j < file.length; j++) {
        if (file[j].includes(lines[i][0]) {
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
  console.log("installing programs.")
  await simpleExec('sudo apt-get update')
  await simpleExec('apt-get install clamtk ufw libpam-cracklib')
  console.log("enabling firewall.")
  await simpleExec('ufw enable')
  await simpleExec('passwd -l root')
  console.log("basic configuration (sshd, lightdm, password settings and lockout)")
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
  await modifyLines("/etc/pam.d/common-password", [["pam_unix.so", ""], ["pam.cracklib.so",""]]) // TODO:
  await modifyLines("/etc/pam.d/common-auth", [["pam_tally2.so", "auth required pam_tally2.so  file=/var/log/tallylog deny=3 even_deny_root unlock_time=1800"]])
  await simpleExec('Sysctl -p')
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

  console.log("Programs listening to ports:\n use `sudo lsof -i :$port` to determine the program listening.")
  ports = (await simpleExec('ss -ln')).split("\n")
  for (var i = 0; i < ports.length; i++) {
    if (ports[i].includes("127.0.0.1")) {
      console.log(ports[i])
    }
  }

})();

/* Old shellscript code:

sudo su -
apt-get install clamtk ufw
ufw enable



_users=$(awk -F'[/:]' '{if ($3 >= 1000 && $3 != 65534) print $1}' /etc/passwd)

for _user in "${_users[@]}"
do
    USERPW="Cyb3rPatr!0t$"
    HASH=$(echo "$USERPW" | openssl passwd -1 -stdin)
    # single quotes around hash, so coincidental
    # stuff like $1 in the pw hash survives
    sudo usermod --password '$HASH' $_user"
done
*/
