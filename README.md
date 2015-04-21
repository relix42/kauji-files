# kaiju-files

Configs and scripts for the kaiju machines
Each individual machine has it's own branch
This may be a horrid abuse of git

Setup to get things going on a new kaiju

git config --global push.default matching
git config --global user.name Dave Hahn
git config --global user.email dhahn@netflix.com
cd /
git init .
git remote add -t \* -f origin https://github.com/relix42/kauji-files.git
git checkout master
git pull
git checkout -b `hostname`
git push -u origin `hostname`
