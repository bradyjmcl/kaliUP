#!/bin/bash

# Color codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color (reset)

# Download the FiraCode Nerd Font for tmux
printf "\n ${CYAN}-_-_-_-_- Downloading and Installing FiraCode Nerd Fonts... -_-_-_-_- ${NC}\n\n"

mkdir ~/nerdfonttemp
wget https://github.com/ryanoasis/nerd-fonts/releases/download/v3.2.1/FiraCode.zip -O ~/nerdfonttemp/FiraCode.zip
mkdir ~/.local/share/fonts
cd ~/.local/share/fonts
unzip ~/nerdfonttemp/FiraCode.zip
rm LICENSE
rm README.md
fc-cache -f -v
rm -rf ~/nerdfonttemp

printf "\n ${GREEN}-_-_-_-_- All done! Remember to close your terminal to change your font preferences. -_-_-_-_- ${NC}\n\n"
