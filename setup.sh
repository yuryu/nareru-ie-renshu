# install emacs
sudo yum install -y emacs

# install dstat
sudo yum install -y dstat

# install tig
sudo rpm -ivh http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.2-2.el6.rf.x86_64.rpm
sudo yum install -y tig

# install htop
echo "install htop"
sudo rpm -ivh http://ftp-srv2.kddilabs.jp/Linux/distributions/fedora/epel/6/x86_64/epel-release-6-8.noarch.rpm
sudo yum install -y htop