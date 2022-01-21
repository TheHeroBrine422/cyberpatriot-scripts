sudo apt -y install nodejs
mkdir script
cd script
wget https://raw.githubusercontent.com/TheHeroBrine422/cyberpatriot-scripts/main/main.js
echo "Configure options (first variables in main.js), then run `sudo node --max-old-space-size=8192 main.js`"
