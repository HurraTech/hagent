# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.network "forwarded_port", guest: 10000, host: 10000, host_ip: "127.0.0.1"

  config.vm.provision "shell", inline: <<-SHELL
     apt-get update
     wget https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz 
     echo "Installing Go 1.15.2"
     sudo tar -xf ./go1.15.2.linux-amd64.tar.gz
     sudo mv go /usr/local  
     echo 'export GOROOT=/usr/local/go' | sudo tee -a /root/.bashrc
     echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' | sudo tee -a /root/.bashrc
     echo "cd /app && sudo -s su" >> /home/vagrant/.bashrc
  SHELL

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  config.vm.synced_folder "./", "/app"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  # config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
  #   vb.memory = "1024"
  # end
  #
  # View the documentation for the provider you are using for more
  # information on available options.

end
