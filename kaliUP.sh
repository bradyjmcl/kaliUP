#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color (reset)

# Check if user is root else print root message and exit.
if [ "$EUID" -ne 0 ]; then
	printf "\n ${RED}-_-_-_-_- This script must be run as root. Please use sudo to run kaliUP. -_-_-_-_- ${NC}\n\n"
	exit 1
fi

# Let user know that script is intended to be run after an apt update & apt upgrade
printf "\n${YELLOW}This script is intended to be run after an ${WHITE}apt update ${YELLOW}and ${WHITE}apt upgrade${YELLOW}. These commands are not included for brevity, but please cancel with ${RED}Ctrl + C ${YELLOW}if you haven't run them already.${NC}\n\n"
sleep 10
printf "\n${GREEN}Okay, here we go! ${NC}\n\n"
sleep 2

# Set up global variable for architecture
uname_m=$(uname -m)
if [ "$uname_m" == "aarch64" ]; then 
    arch="arm64"
fi

if [ "$uname_m" == "x86_64" ]; then
    arch="amd64"
fi

printf "\n ${YELLOW}-_-_-_-_- Sanity Checking Kali Keyring -_-_-_-_- ${NC}\n\n"
wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg
printf "\n ${GREEN}-_-_-_-_- Kali Keyring is correct -_-_-_-_- ${NC}\n\n"

printf "\n ${PURPLE}-_-_-_-_- Installing ntpdate -_-_-_-_- ${NC}\n\n"
apt install -y ntpsec-ntpdate
printf "\n ${GREEN}-_-_-_-_- Finished installing ntpdate -_-_-_-_- ${NC}\n\n"

printf "\n ${PURPLE}-_-_-_-_- Installing sickle -_-_-_-_- ${NC}\n\n"
apt install -y sickle
printf "\n ${GREEN}-_-_-_-_- Finished installing sickle -_-_-_-_- ${NC}\n\n"

printf "\n ${PURPLE}-_-_-_-_- Installing netexec -_-_-_-_- ${NC}\n\n"
apt install -y netexec
printf "\n ${GREEN}-_-_-_-_- Finished installing netexec -_-_-_-_- ${NC}\n\n"

printf "\n ${PURPLE}-_-_-_-_- Installing mitm6 -_-_-_-_- ${NC}\n\n"
apt install -y mitm6
printf "\n ${GREEN}-_-_-_-_- Finished installing mitm6 -_-_-_-_- ${NC}\n\n"

printf "\n ${PURPLE}-_-_-_-_- Installing coercer -_-_-_-_- ${NC}\n\n"
apt install -y coercer
printf "\n ${GREEN}-_-_-_-_- Finished installing coercer -_-_-_-_- ${NC}\n\n"

printf "\n ${PURPLE}-_-_-_-_- Installing autorecon -_-_-_-_- ${NC}\n\n"
apt install -y autorecon
printf "\n ${GREEN}-_-_-_-_- Finished installing autorecon -_-_-_-_- ${NC}\n\n"

printf "\n ${PURPLE}-_-_-_-_- Installing wireguard -_-_-_-_- ${NC}\n\n"
apt install -y wireguard
printf "\n ${GREEN}-_-_-_-_- Finished installing wireguard -_-_-_-_- ${NC}\n\n"

# Install gobuster
printf "\n ${PURPLE}-_-_-_-_- Installing gobuster -_-_-_-_- ${NC}\n\n"
apt install -y gobuster
printf "\n ${GREEN}-_-_-_-_- Finished installing gobuster -_-_-_-_- ${NC}\n\n"

# Install keepassxc
printf "\n ${PURPLE}-_-_-_-_- Installing keepassxc -_-_-_-_- ${NC}\n\n"
apt install -y keepassxc
printf "\n ${GREEN}-_-_-_-_- Finished installing keepassxc -_-_-_-_- ${NC}\n\n"

# Install LibreOffice
printf "\n ${PURPLE}-_-_-_-_- Installing LibreOffice -_-_-_-_- ${NC}\n\n"
apt install -y libreoffice
printf "\n ${GREEN}-_-_-_-_- Finished installing LibreOffice -_-_-_-_- ${NC}\n\n"

# Install bloodyAD
printf "\n ${PURPLE}-_-_-_-_- Installing bloodyAD -_-_-_-_- ${NC}\n\n"
apt remove bloodyad && pipx install bloodyad
cp /root/.local/bin/bloodyAD /usr/bin/bloodyAD

# Add an alias for 'bloodyad'
echo '' >> /home/$SUDO_USER/.zshrc
echo '# bloodyAD alias' >> /home/$SUDO_USER/.zshrc
echo 'alias bloodyad='/usr/bin/bloodyAD'' >> /home/$SUDO_USER/.zshrc
printf "\n ${GREEN}-_-_-_-_- Finished installing bloodyAD -_-_-_-_- ${NC}\n\n"

# Install certipy
printf "\n ${PURPLE}-_-_-_-_- Installing certipy -_-_-_-_- ${NC}\n\n"
apt install -y certipy-ad

# Add an alias for 'certipy'
echo '' >> /home/$SUDO_USER/.zshrc
echo '# certipy alias' >> /home/$SUDO_USER/.zshrc
echo 'alias certipy='/usr/bin/certipy-ad'' >> /home/$SUDO_USER/.zshrc
printf "\n ${GREEN}-_-_-_-_- Finished installing certipy -_-_-_-_- ${NC}\n\n"

# Install Docker
printf "\n ${PURPLE}-_-_-_-_- Installing Docker -_-_-_-_- ${NC}\n\n"
apt install -y docker.io
systemctl enable docker --now
systemctl enable docker.service
systemctl enable containerd.service
usermod -aG docker $SUDO_USER
apt install -y docker-compose
printf "\n ${GREEN}-_-_-_-_- Finished installing Docker -_-_-_-_- ${NC}\n\n"

# Install Go
printf "\n ${PURPLE}-_-_-_-_- Installing Go -_-_-_-_- ${NC}\n\n"
curl -sS https://webi.sh/golang | sh
cp /root/.local/opt/go/bin/go /usr/bin/go
printf "\n ${GREEN}-_-_-_-_- Finished installing Go -_-_-_-_- ${NC}\n\n"

# Install Rust
printf "\n ${PURPLE}-_-_-_-_- Installing Rust -_-_-_-_- ${NC}\n\n"
apt install -y rustup
rustup default stable
printf "\n ${GREEN}-_-_-_-_- Finished installing Rust -_-_-_-_- ${NC}\n\n"

# Install Bloodhound (Community Edition)
printf "\n ${PURPLE}-_-_-_-_- Installing Bloodhound-CE -_-_-_-_- ${NC}\n\n"
mkdir /opt/bloodhound-cli
cd /opt/bloodhound-cli
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-$arch.tar.gz
tar -xvzf bloodhound-cli-linux-$arch.tar.gz
rm bloodhound-cli-linux-$arch.tar.gz

# Add an alias for 'bloodhound-ce'
echo '' >> /home/$SUDO_USER/.zshrc
echo '# bloodhound alias' >> /home/$SUDO_USER/.zshrc
echo 'alias bhce='sudo /opt/bloodhound-cli/bloodhound-cli containers up'' >> /home/$SUDO_USER/.zshrc
printf "\n ${GREEN}-_-_-_-_- Finished installing Bloodhound-CE -_-_-_-_- ${NC}\n\n"

# Install RustHound
printf "\n ${PURPLE}-_-_-_-_- Installing RustHound-CE -_-_-_-_- ${NC}\n\n"
cargo install rusthound-ce
cp /root/.cargo/bin/rusthound-ce /usr/bin/rusthound-ce

# Add an alias for 'rhce'
echo '' >> /home/$SUDO_USER/.zshrc
echo '# rusthound alias' >> /home/$SUDO_USER/.zshrc
echo 'alias rhce='/usr/bin/rusthound-ce'' >> /home/$SUDO_USER/.zshrc
printf "\n ${GREEN}-_-_-_-_- Finished installing RustHound -_-_-_-_- ${NC}\n\n"

# Install snmp-mibs-downloader
printf "\n ${PURPLE}-_-_-_-_- Installing MIBS Downloader -_-_-_-_- ${NC}\n\n"
apt install -y snmp-mibs-downloader
printf "\n ${GREEN}-_-_-_-_- Finished installing MIBS Downloader -_-_-_-_- ${NC}\n\n"

printf "\n ${CYAN}-_-_-_-_- Downloading MIBS... -_-_-_-_- ${NC}\n\n"
download-mibs
sed -i 's/^mibs :/# mibs :/' /etc/snmp/snmp.conf
printf "\n ${GREEN}-_-_-_-_- Finished downloading MIBS -_-_-_-_- ${NC}\n\n"

# Clone krbrelayx
printf "\n ${PURPLE}-_-_-_-_- Cloning krbrelayx -_-_-_-_- ${NC}\n\n"
git clone https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx
printf "\n ${GREEN}-_-_-_-_- Finished cloning krbrelayx -_-_-_-_- ${NC}\n\n"

# Clone PKINITtools
printf "\n ${PURPLE}-_-_-_-_- Cloning PetitPotam -_-_-_-_- ${NC}\n\n"
git clone https://github.com/dirkjanm/PKINITtools.git /opt/PKINITtools
printf "\n ${GREEN}-_-_-_-_- Finished cloning PetitPotam -_-_-_-_- ${NC}\n\n"

# Clone PetitPotam
printf "\n ${PURPLE}-_-_-_-_- Cloning PKINITtools -_-_-_-_- ${NC}\n\n"
git clone https://github.com/topotam/PetitPotam.git /opt/petitpotam
printf "\n ${GREEN}-_-_-_-_- Finished cloning PKINITtools -_-_-_-_- ${NC}\n\n"

# Clone pywhisker
printf "\n ${PURPLE}-_-_-_-_- Cloning pywhisker -_-_-_-_- ${NC}\n\n"
git clone https://github.com/ShutdownRepo/pywhisker.git /opt/pywhisker
printf "\n ${GREEN}-_-_-_-_- Finished cloning pywhisker -_-_-_-_- ${NC}\n\n"

# Clone sccmhunter
printf "\n ${PURPLE}-_-_-_-_- Cloning sccmhunter -_-_-_-_- ${NC}\n\n"
git clone https://github.com/garrettfoster13/sccmhunter.git /opt/sccmhunter
printf "\n ${GREEN}-_-_-_-_- Finished cloning sccmhunter -_-_-_-_- ${NC}\n\n"

# Clone Impacket (SCCM Relay)
printf "\n ${PURPLE}-_-_-_-_- Cloning Impacket (SCCM Relay) -_-_-_-_- ${NC}\n\n"
git clone -b feature/relay-sccm-adminservice --single-branch https://github.com/garrettfoster13/impacket.git /opt/impacket_sccm_relay
printf "\n ${GREEN}-_-_-_-_- Finished cloning Impacket (SCCM Relay) -_-_-_-_- ${NC}\n\n"

# Clone pimpmykali
printf "\n ${PURPLE}-_-_-_-_- Cloning PimpMyKali -_-_-_-_- ${NC}\n\n"
git clone https://github.com/Dewalt-arch/pimpmykali.git /opt/pimpmykali
printf "\n ${GREEN}-_-_-_-_- Finished cloning PimpMyKali -_-_-_-_- ${NC}\n\n"

# Install sublime text
printf "\n ${PURPLE}-_-_-_-_- Installing Sublime Text 4 -_-_-_-_- ${NC}\n\n"
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt-get update
apt-get install sublime-text
printf "\n ${GREEN}-_-_-_-_- Finished installing Sublime Text 4 -_-_-_-_- ${NC}\n\n"

# Set up staging directory
mkdir /opt/staging

# Set up Ligolo directories
printf "\n ${PURPLE}-_-_-_-_- Setting up Ligolo directories... -_-_-_-_- ${NC}\n\n"

mkdir /opt/staging/ligolo
cd /opt/staging/ligolo
mkdir proxy win_amd64 win_arm64 win_armv7 win_armv6 lin_amd64 lin_arm64 lin_armv7 lin_armv6 darwin_amd64 darwin_arm64

# Get current release version of Ligolo-NG
ligolo_version=$(curl -s https://github.com/nicocha30/ligolo-ng/releases | grep linux_amd64.tar.gz -m 1 | cut -d '_' -f 3)

printf "\n ${YELLOW}-_-_-_-_- Pulling down Ligolo binaries... -_-_-_-_- ${NC}\n\n"

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Proxy... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/proxy
proxy_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_proxy_"$ligolo_version"_linux_"$arch".tar.gz"
wget $proxy_link
proxy_tarball_name=$(echo $proxy_link | cut -d '/' -f 9)
tar -xf $proxy_tarball_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Linux AMD64... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/lin_amd64
lin_amd64_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_linux_amd64.tar.gz"
wget $lin_amd64_link
lin_amd64_tarball_name=$(echo $lin_amd64_link | cut -d '/' -f 9)
tar -xf $lin_amd64_tarball_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Darwin AMD64... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/darwin_amd64
darwin_amd64_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_darwin_amd64.tar.gz"
wget $darwin_amd64_link
darwin_amd64_tarball_name=$(echo $darwin_amd64_link | cut -d '/' -f 9)
tar -xf $darwin_amd64_tarball_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Linux ARM64... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/lin_arm64
lin_arm64_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_linux_arm64.tar.gz"
wget $lin_arm64_link
lin_arm64_tarball_name=$(echo $lin_arm64_link | cut -d '/' -f 9)
tar -xf $lin_arm64_tarball_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Darwin ARM64... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/darwin_arm64
darwin_arm64_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_darwin_arm64.tar.gz"
wget $darwin_arm64_link
darwin_arm64_tarball_name=$(echo $darwin_arm64_link | cut -d '/' -f 9)
tar -xf $darwin_arm64_tarball_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Linux ARMv7... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/lin_armv7
lin_armv7_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_linux_armv7.tar.gz"
wget $lin_armv7_link
lin_armv7_tarball_name=$(echo $lin_armv7_link | cut -d '/' -f 9)
tar -xf $lin_armv7_tarball_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Linux ARMv6... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/lin_armv6
lin_armv6_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_linux_armv6.tar.gz"
wget $lin_armv6_link
lin_armv6_tarball_name=$(echo $lin_armv6_link | cut -d '/' -f 9)
tar -xf $lin_armv6_tarball_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Windows AMD64... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/win_amd64
win_amd64_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_windows_amd64.zip"
wget $win_amd64_link
win_amd64_zip_name=$(echo $win_amd64_link | cut -d '/' -f 9)
unzip $win_amd64_zip_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Windows ARM64... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/win_arm64
win_arm64_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_windows_arm64.zip"
wget $win_arm64_link
win_arm64_zip_name=$(echo $win_arm64_link | cut -d '/' -f 9)
unzip $win_arm64_zip_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Windows ARMv7... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/win_armv7
win_armv7_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_windows_armv7.zip"
wget $win_armv7_link
win_armv7_zip_name=$(echo $win_armv7_link | cut -d '/' -f 9)
unzip $win_armv7_zip_name

printf "\n ${CYAN}-_-_-_-_- Pulling down Ligolo Agent for Windows ARMv6... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/ligolo/win_armv6
win_armv6_link="https://github.com/nicocha30/ligolo-ng/releases/download/v"$ligolo_version"/ligolo-ng_agent_"$ligolo_version"_windows_armv6.zip"
wget $win_armv6_link
win_armv6_zip_name=$(echo $win_armv6_link | cut -d '/' -f 9)
unzip $win_armv6_zip_name

printf "\n ${GREEN}-_-_-_-_- Finished setting up Ligolo directories -_-_-_-_- ${NC}\n\n"

# Set up linPEAS and winPEAS directories
printf "\n ${YELLOW}-_-_-_-_- Setting up linPEAS & winPEAS directories... -_-_-_-_- ${NC}\n\n"
cd /opt/staging
mkdir /opt/staging/windows /opt/staging/linux
mkdir /opt/staging/windows/winpeas /opt/staging/linux/linpeas
peas_version=$(curl -s https://github.com/peass-ng/PEASS-ng/releases | grep -i "refs/heads/master" -m 1 | awk '{ print $5 }' | cut -d "<" -f1)
peas_link="https://github.com/peass-ng/PEASS-ng/releases/download/"$peas_version

printf "\n ${CYAN}-_-_-_-_- Pulling down linPEAS files... -_-_-_-_- ${NC}\n\n"

linpeas_scripts=("linpeas.sh" "linpeas_darwin_amd64" "linpeas_darwin_arm64" "linpeas_fat.sh" "linpeas_linux_386" "linpeas_linux_amd64" "linpeas_linux_arm")
for linpeas_file in ${linpeas_scripts[@]}; do
	wget $peas_link/$linpeas_file -o /opt/staging/linux/linpeas/$linpeas_file
	chmod +x /opt/staging/linux/linpeas/$linpeas_file 
done

printf "\n ${CYAN}-_-_-_-_- Pulling down winPEAS files... -_-_-_-_- ${NC}\n\n"

winpeas_scripts=('winPEAS.bat' 'winPEASany.exe' 'winPEASany_ofs.exe' 'winPEASx64_ofs.exe' 'winPEASx86.exe' 'winPEASx86_ofs.exe')
for winpeas_file in ${winpeas_scripts[@]}; do
	wget $peas_link/$winpeas_file -o /opt/staging/windows/winpeas/$winpeas_file
	chmod +x /opt/staging/windows/winpeas/$winpeas_file 
done

printf "\n ${GREEN}-_-_-_-_- Finished harvesting the PEAS! -_-_-_-_- ${NC}\n\n"

# Set up Linux tools directory
printf "\n ${PURPLE}-_-_-_-_- Setting up Linux tools directory... -_-_-_-_- ${NC}\n\n"

# Get pspy version
pspy_version=$(curl -s https://github.com/DominicBreuker/pspy/releases | grep releases/tag/v -m 1 | cut -d 'v' -f 3 | cut -d '"' -f 1)
pspy_link="https://github.com/DominicBreuker/pspy/releases/download/v"$pspy_version"/"
pspy_scripts=("pspy32" "pspy32s" "pspy64" "pspy64s")
for pspy_file in ${pspy_scripts[@]}; do
	wget $pspy_link/$pspy_file -o /opt/staging/linux/$pspy_file
	chmod +x /opt/staging/linux/$pspy_file 
done

printf "\n ${GREEN}-_-_-_-_- Finished setting up the Linux tools directory -_-_-_-_- ${NC}\n\n"

# Set up Windows tools directory
printf "\n ${PURPLE}-_-_-_-_- Setting up Windows tools directory... -_-_-_-_- ${NC}\n\n"

printf "\n ${CYAN}-_-_-_-_- Pulling down Ghostpack compiled binaries... -_-_-_-_- ${NC}\n\n"

# Get Ghostpack Binaries
ghostpack_files=("SharpUp.exe" "Certify.exe" "Rubeus.exe" "Seatbelt.exe")
for ghostpack_binary in ${ghostpack_files[@]}; do
	wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/$ghostpack_binary -o /opt/staging/windows/$ghostpack_binary
	chmod +x /opt/staging/windows/$ghostpack_binary 
done

# Get RunasCs
printf "\n ${CYAN}-_-_-_-_- Pulling down RunasCs... -_-_-_-_- ${NC}\n\n"

runascs_version=$(curl -s https://github.com/antonioCoco/RunasCs/releases/ | grep 'RunasCs version' -m 1 | cut -d ' ' -f 7 | cut -d '<' -f 1)
wget "https://github.com/antonioCoco/RunasCs/releases/download/v"$runascs_version"/RunasCs.zip" -o /opt/staging/windows/RunasCs.zip
cd /opt/staging/windows
unzip /opt/staging/windows/RunasCs.zip
chmod +x /opt/staging/windows/RunasCs.exe  
chmod +x /opt/staging/windows/RunasCs_net2.exe
rm /opt/staging/windows/RunasCs.zip
wget https://raw.githubusercontent.com/antonioCoco/RunasCs/master/Invoke-RunasCs.ps1 -o /opt/staging/windows/Invoke-RunasCs.ps1

# Get SharpHound CE
printf "\n ${CYAN}-_-_-_-_- Pulling down SharpHound CE... -_-_-_-_- ${NC}\n\n"

sharphound_version=$(curl -s https://github.com/BloodHoundAD/SharpHound/releases | grep BloodHoundAD/SharpHound/tree -m 1 | cut -d 'v' -f 2 | cut -d '"' -f 1)
mkdir /opt/staging/windows/sharphound
wget "https://github.com/BloodHoundAD/SharpHound/releases/download/v"$sharphound_version"/SharpHound-v"$sharphound_version".zip" -o /opt/staging/windows/sharphound/SharpHound.zip
unzip /opt/staging/windows/sharphound/SharpHound.zip -d /opt/staging/windows/sharphound 
# Leaving this so that dependencies can be transferred as needed

# Copy PowerView.ps1 for ease of access
printf "\n ${CYAN}-_-_-_-_- Pulling down PowerView.ps1... -_-_-_-_- ${NC}\n\n"
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -o /opt/staging/windows/powerview.ps1
printf "\n ${CYAN}-_-_-_-_- Pulling down PowerUp.ps1... -_-_-_-_- ${NC}\n\n"

# PowerUp is no longer being updated and can be downloaded in its latest form:
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 -o /opt/staging/windows/powerup.ps1

# Get nc64 for 64- and 32-bit systems
printf "\n ${CYAN}-_-_-_-_- Pulling down nc64 executables... -_-_-_-_- ${NC}\n\n"
nc64_version=$(curl -s https://github.com/vinsworldcom/NetCat64/releases | grep vinsworldcom/NetCat64/releases/tag -m 1 | cut -d '"' -f 6 | cut -d '/' -f 6)
wget "https://github.com/vinsworldcom/NetCat64/releases/download/"$nc64_version"/nc64.exe" -o /opt/staging/windows/nc64.exe
chmod +x /opt/staging/windows/nc64.exe
wget "https://github.com/vinsworldcom/NetCat64/releases/download/"$nc64_version"/nc64-32.exe" -o /opt/staging/windows/nc64_32bit.exe
chmod +x /opt/staging/windows/nc64_32bit.exe

# Get GodPotato and CoercedPotato
printf "\n ${CYAN}-_-_-_-_- Pulling down GodPotato Binaries... -_-_-_-_- ${NC}\n\n"
mkdir /opt/staging/windows/potato
godpotato_version=$(curl -s https://github.com/BeichenDream/GodPotato | grep BeichenDream/GodPotato/releases/tag -m 1 | cut -d 'V' -f 2 | cut -d '"' -f 1)
godpotato_files=("GodPotato-NET2.exe" "GodPotato-NET35.exe" "GodPotato-NET4.exe")
for godpotato_binary in ${godpotato_files[@]}; do
	wget https://github.com/BeichenDream/GodPotato/releases/download/V$godpotato_version/$godpotato_binary -o /opt/staging/windows/potato/$godpotato_binary
	chmod +x /opt/staging/windows/potato/$godpotato_binary 
done

printf "\n ${CYAN}-_-_-_-_- Cloning CoercedPotato... -_-_-_-_- ${NC}\n\n"
cd /opt/staging/windows/potato
git clone https://github.com/overgrowncarrot1/CoercedPotatoCompiled.git
cd CoercedPotatoCompiled 
unzip CoercedPotato.zip
cp CoercedPotato.exe /opt/staging/windows/potato/CoercedPotato.exe
chmod +x /opt/staging/windows/potato/CoercedPotato.exe
rm -rf /opt/staging/windows/potato/CoercedPotatoCompiled

# Download Mimikatz
printf "\n ${CYAN}-_-_-_-_- Pulling down Mimikatz... -_-_-_-_- ${NC}\n\n"

mkdir /opt/staging/windows/mimikatz
cd /opt/staging/windows/mimikatz
mimikatz_version=$(curl -s https://github.com/gentilkiwi/mimikatz/releases | grep gentilkiwi/mimikatz/releases/tag -m 1 | cut -d '/' -f 6 | cut -d '"' -f 1)
wget https://github.com/gentilkiwi/mimikatz/releases/download/$mimikatz_version/mimikatz_trunk.zip -o /opt/staging/windows/mimikatz/mimikatz.zip
unzip mimikatz.zip

printf "\n ${CYAN}-_-_-_-_-_-_-_-_-_- ${NC}\n\n"
printf "\n${GREEN}All done for now, happy testing!${NC}\n\n"
printf "\n ${PURPLE}-_-_-_-_-_-_-_-_-_- ${NC}\n\n"

# If you want to create a new account and duplicate the permissions of the kali account, you can run this after:
# I would run this BEFORE running PMK as PMK alters user conditions.

# Usage (as root): ./user.sh kali brady

##!/bin/bash

# KALI_USER=$1
# NEW_USER=$2
# KALI_USER_GROUPS=$(id -Gn ${KALI_USER} | sed "s/ /,/g" | sed -r 's/\<'${KALI_USER}'\>\b,?//g')
# KALI_USER_SHELL=$(awk -F : -v name=${KALI_USER} '(name == $1) { print $7 }' /etc/passwd)
# useradd --groups ${KALI_USER_GROUPS} --shell ${KALI_USER_SHELL} --create-home ${NEW_USER}
# passwd ${NEW_USER}
# cat /home/${KALI_USER}/.zshrc > /home/${NEW_USER}/.zshrc
# usermod -L -e 1 ${KALI_USER}
