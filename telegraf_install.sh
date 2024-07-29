#!/bin/bash
#Print Line to detail what this script is for
echo "This will install the Telegraf service onto your Publisher"
#Prompt user for InfluxDB/Grafana Monitoring server IP and set as PubIP variable
read -p 'Please enter your Publishers hostname, followed by Enter: ' PubHost
#Prompt user for InfluxDB/Grafana Monitoring server IP and set as PubIP variable
read -p 'Please enter your InfluxDB Monitoring Server IP Address (eg: 10.213.1.111), followed by Enter: ' PubIP
#Add Telegraf repo to apt sources list
sudo bash -c "sudo cat <<'EOF' | sudo tee /etc/apt/sources.list.d/influxdata.list
deb https://repos.influxdata.com/ubuntu $(lsb_release -cs) stable
EOF"
#Download curl - as removed post r108
sudo apt install curl -y
#Download Telegraf gpg key for repo
sudo curl -sL https://repos.influxdata.com/influxdata-archive_compat.key | sudo apt-key add -
#Update apt repo list and install Telegraf agent
sudo apt update && sudo apt install telegraf -y
#Update Telegraf Config file
cat <<EOF > /etc/telegraf/telegraf.conf
[global_tags]

# Configuration for telegraf agent
[agent]
    interval = "10s"
    debug = false
    hostname = "$PubHost"
    round_interval = true
    flush_interval = "10s"
    flush_jitter = "0s"
    collection_jitter = "0s"
    metric_batch_size = 1000
    metric_buffer_limit = 10000
    quiet = false
    logfile = ""
    omit_hostname = false

###############################################################################
#                                  OUTPUTS                                    #
###############################################################################

[[outputs.influxdb]]
    urls = ["http://$PubIP:8086"]
    database = "mydb"
    timeout = "0s"
    retention_policy = ""

###############################################################################
#                                  INPUTS                                     #
###############################################################################

[[inputs.cpu]]
    percpu = true
    totalcpu = true
    collect_cpu_time = false
    report_active = false
[[inputs.disk]]
    ignore_fs = ["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]
[[inputs.diskio]]
[[inputs.mem]]
[[inputs.net]]
[[inputs.system]]
[[inputs.swap]]
[[inputs.netstat]]
[[inputs.processes]]
[[inputs.kernel]]
EOF
#Enable Telegraf service 
sudo systemctl enable --now telegraf
#Display current status of telegraf 
sudo systemctl is-enabled telegraf
echo "Installation of Telegraf completed successfully!"
