#!/bin/bash

# This is a provisioning file
# It can be used to provision a Publisher in AliCloud

if [ "$PUBLISHER_REPO" = "" ] ; then
    PUBLISHER_REPO=ns-1-registry.cn-shenzhen.cr.aliyuncs.com/npa/publisher
fi

if [ "$PUBLISHER_IMAGE_TAG" = "" ] ; then
    PUBLISHER_IMAGE_TAG=latest
fi

if [ "$PUBLISHER_USER" = "" ] ; then
    INSTALL_USER=$(logname)
else
    INSTALL_USER=$PUBLISHER_USER
fi

if [ "$INSTALL_USER" = "" ] ; then
    echo "No username specificed. Exit!"
    exit 1
fi

if [ "$INSTALL_USER" = "root" ] ; then
    echo "Do not use the root to install the publisher. Exit!"
    exit 1
fi

HOME=`eval echo ~$INSTALL_USER`
if [ "$HOME" = "" ] ; then
    echo "Can not find the $INSTALL_USER home directory. Exit!"
    exit 1
fi

function update_packages {
        apt-get -y update
        apt-get -y upgrade
}

function install_docker_ce {
        # Install packages to allow apt to use a repository over HTTPS:
        apt-get install -y apt-transport-https ca-certificates curl software-properties-common

        # Add Docker's official GPG key:
        curl -fsSL http://mirrors.aliyun.com/docker-ce/linux/ubuntu/gpg | sudo apt-key add -

        # Update packages to find DockerCE
        add-apt-repository "deb [arch=amd64] http://mirrors.aliyun.com/docker-ce/linux/ubuntu $(lsb_release -cs) stable"
        apt-get -y update

        # Install Docker CE
        apt-get install -y docker-ce

        while ! [[ "`service docker status`" =~ "running" ]]; do sleep 1; done

        # Enable SSH user to run docker command
        usermod -a -G docker $INSTALL_USER
}


function load_publisher_image {
    # Load docker image
    # sg command will execute thit with docker group permissions (this shell doesn't have it yet because we just loaded it)
    if [ -f $HOME/publisher_docker.tgz ]; then
        sg docker -c "gunzip -c $HOME/publisher_docker.tgz | docker load"
    else
        sg docker -c "docker pull $PUBLISHER_REPO:$PUBLISHER_IMAGE_TAG"
        sg docker -c "docker tag $PUBLISHER_REPO:$PUBLISHER_IMAGE_TAG new_edge_access:latest"
    fi
}

function prepare_for_publisher_start {
    # Let's create folders for publisher and set them to be owner user (vs root)
    # If we don't create them explicitly then docker engine will create it for us (under root user)
    sudo -i -u $INSTALL_USER mkdir $HOME/resources
    sudo -i -u $INSTALL_USER mkdir $HOME/logs
}

function configure_publisher_wizard_to_start_on_user_ssh {
    # There is a problem with the docker that sometimes it starts really slow and unavailable on first login
    # We depend on Docker being ready, so we want to wait for it explicitly
        echo "while ! [[ \"\`sudo service docker status\`\" =~ \"running\" ]]; do echo \"Waiting for Docker daemon to start. It can take a minute.\"; sleep 10; 
done" >> $HOME/.bash_profile

    # Allow to run wizard under sudo without entering a password
    echo "$INSTALL_USER      ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers > /dev/null

    # Configure publisher wizard to run on each SSH
    echo "sudo rm \$HOME/npa_publisher_wizard 2>/dev/null" >> $HOME/.bash_profile
    echo "docker run -v \$HOME:/home/host_home --rm --entrypoint cp new_edge_access:latest /home/npa_publisher_wizard /home/host_home/npa_publisher_wizard" >> $HOME/.bash_profile
    echo "sudo \$HOME/npa_publisher_wizard" >> $HOME/.bash_profile
}

function configure_publisher_wizard_to_start_on_boot {
    # Extract wizard for a launch on boot
    sg docker -c "docker run -v $HOME:/home/host_home --rm --entrypoint cp new_edge_access:latest /home/npa_publisher_wizard /home/host_home/npa_publisher_wizard"
    chmod +x $HOME/npa_publisher_wizard
}

function launch_publisher {
    # ToDo: We should move this to publisher wizard
    # Configure for a publisher to start automatically
    HOST_OS_TYPE=ubuntu
    sg docker -c "docker run --restart always --network=host --privileged --memory-swappiness=0 -e HOST_OS_TYPE=$HOST_OS_TYPE -v $HOME/resources:/home/resources -v $HOME/logs:/home/logs -d new_edge_access:latest"
}

function hardening_ssh {
    # Update sshd_config
        # 5.3.4 Ensure SSH access is limited | allow users
        # 5.3.6 Ensure SSH X11 forwarding is disabled
        # 5.3.7 Ensure SSH MaxAuthTries is set to 4 or less
        # 5.3.9 Ensure SSH HostbasedAuthentication is disabled
        # 5.3.10 Ensure SSH root login is disabled
        # 5.3.11 Ensure SSH PermitEmptyPasswords is disabled
        # 5.3.13 Ensure only strong Ciphers are used
        # 5.3.14 Ensure only strong MAC algorithms are used
        # 5.3.15 Ensure only strong Key Exchange algorithms are used
        # 5.3.20 Ensure SSH AllowTcpForwarding is disabled
        # 5.3.22 Ensure SSH MaxSessions is limited to 10
        # Set TCPKeepAlive to no
        # Set ClientAliveCountMax to 1
        echo "AllowUsers $INSTALL_USER" >> /etc/ssh/sshd_config
        sed -i 's/^#*MaxAuthTries [0-9]\+/MaxAuthTries 2/' /etc/ssh/sshd_config
        sed -i 's/^#*X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
        echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
        echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
        echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
        echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
        echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
        echo "MaxSessions 10" >> /etc/ssh/sshd_config
        sed -i 's/^#*TCPKeepAlive [yes|no]\+/TCPKeepAlive no/' /etc/ssh/sshd_config
        sed -i 's/^#*ClientAliveCountMax [0-9]\+/ClientAliveCountMax 1/' /etc/ssh/sshd_config
}

function hardening_disable_root_login_to_all_devices {
    #Disable ALL root login, ssh, console, tty1...
    echo > /etc/securetty
}

function hardening_remove_root_password {
    passwd -d root
    passwd --lock root
}

function hardening_disable_ctrl_alt_del {
    systemctl mask ctrl-alt-del.target
}

# Remove Linux firmware
function hardening_remove_linux_firmware {
        kernel_version=$(uname -r)
        distro=$(echo "$kernel_version" | awk -F '-' '{print $NF}')
        if [ "$distro" != "generic" ] ; then
                apt-get remove linux-firmware -y
        fi
}

function hardening_install_cracklib {
        apt-get install cracklib-runtime -y
}

function install_network_utils {
        apt-get install -y net-tools bind9-utils
}

function configure_firewall_npa {
        # Ubuntu use ufw as firewall by default
        apt-get install -y ufw
        echo y | ufw enable
        ufw allow to 191.1.1.1/32 proto tcp port 784
        ufw allow to 191.1.1.1/32 proto udp port 785
        ufw allow in on tun0 to any port 53 proto tcp
        ufw allow in on tun0 to any port 53 proto udp
        ufw allow 22/tcp
        ufw allow in on lo
        ufw deny in from 127.0.0.0/8
        ufw deny in from ::1
        ufw reload
}

function configure_docker_daemon {
    echo -e "{\n\"bridge\": \"none\",\n\"iptables\": false\n}" > /etc/docker/daemon.json
}

function disable_coredumps {
    sh -c "echo 'kernel.core_pattern=|/bin/false' > /etc/sysctl.d/50-coredump.conf"
    sysctl -p /etc/sysctl.d/50-coredump.conf
}

function create_host_os_info_cronjob {
    echo "*/5 * * * * root cd $HOME/resources && ./npa_publisher_collect_host_os_info.sh" > /etc/cron.d/npa_publisher_collect_host_os_info
}

function create_auto_upgrade_cronjob {
        echo "*/1 * * * * root cd $HOME/resources && ./npa_publisher_auto_upgrade.sh" > /etc/cron.d/npa_publisher_auto_upgrade
}

function disable_systemd_resolved {
        rm -f /etc/resolv.conf
        ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
}

function disable_release_motd {
        chmod 644 /etc/update-motd.d/91-release-upgrade
}

function leave_password_expiry_disabled_flag {
        echo "disabled by default" > $HOME/resources/.password_expiry_disabled
}

function remove_unnecessary_utilities {
        apt-get -y remove iputils-ping
        apt-get -y remove wget
        apt-get -y remove curl
        apt-get -y remove netcat-openbsd
}

update_packages
install_network_utils
configure_firewall_npa
install_docker_ce
configure_docker_daemon

load_publisher_image
prepare_for_publisher_start
configure_publisher_wizard_to_start_on_user_ssh

# We need this currently only on AWS
configure_publisher_wizard_to_start_on_boot
create_host_os_info_cronjob
create_auto_upgrade_cronjob
disable_systemd_resolved
launch_publisher

# hardening ssh if needed
if [ "$#" -ge 1 ] && [ "$1" = "hardening_ssh_yes" ]; then
    hardening_ssh
fi

hardening_install_cracklib
hardening_disable_root_login_to_all_devices
hardening_remove_root_password
hardening_disable_ctrl_alt_del
hardening_remove_linux_firmware
disable_coredumps
disable_release_motd
leave_password_expiry_disabled_flag
remove_unnecessary_utilities
                                                                 
