#!/bin/bash
#Remove Existing Publisher Configuration and files
echo "!!!!!WARNING - THIS WILL DESTROY THIS PUBLISHER AND CHANGE IT INTO AN INFLUXDB/GRAFANA MONITORING SERVER!!!!!"
echo "!!!!!PLEASE ONLY CONTINUE IF YOU ARE SURE THIS IS NOT AN IN USE PRODUCTION NPA PUBLISHER!!!!!"
read -p 'Are you sure you wish to proceed? y/n: ' choice
case "$choice" in
    y|Y|Yes|yes ) echo "Yes - Continuing";;
    n|N|No|no ) echo "No - Exiting Script"; exit;;
	* ) echo "Invalid Entry - Exiting script"; exit;;
esac
sudo rm -rf /home/ubuntu/.bash_profile
sudo pkill npa_publisher
sudo docker stop $(docker ps -q)
sudo docker system prune -a -f
sudo apt remove docker-* -y
sudo apt-get autoremove --purge -y
sudo rm -rf /home/ubuntu/resources/ /home/ubuntu/logs/ /home/ubuntu/publisher* /home/ubuntu/npa* /etc/cron.d/npa*
#Add InfluxDB gpg Key for repo
sudo curl -sL https://repos.influxdata.com/influxdb.key | sudo apt-key add -
#Add InfluxDB repo to apt sources 
echo "deb https://repos.influxdata.com/ubuntu focal stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
#Install InfluxDB
sudo apt-get update && sudo apt-get install influxdb -y
#Enable InfluxDB service
sudo systemctl enable --now influxdb
#Open InfluxDB port so Publishers can send their metrics to it
sudo ufw allow 8086/tcp
echo "Successfully installed InfluxDB"

#Install Grafana for metrics visualisation
echo "Now installing Grafana"
#Install required libraries
sudo apt install -y gnupg2 software-properties-common
#Add Grafana GPG repo key
curl -fsSL https://packages.grafana.com/gpg.key| sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/grafana.gpg
#Change permissions on gpg key so apt user can utilise it
sudo chmod 644 /etc/apt/trusted.gpg.d/grafana.gpg
#Add Grafana repo to apt
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
#Install Grafana
sudo apt update && sudo apt -y install grafana
#Open Grafana Web Interface port
sudo ufw allow 3000/tcp
#Create InfluxDB Data Sources configuration file for Grafana
sudo cat <<EOF > /etc/grafana/provisioning/datasources/InfluxDB.yml
apiVersion: 1

datasources:
  - name: InfluxDB_v1
    type: influxdb
    access: proxy
    database: mydb
    user: grafana
    url: http://localhost:8086
    jsonData:
      httpMode: GET
EOF
#Modify permissions of Grafana data source so it can be loaded
sudo chown root:grafana /etc/grafana/provisioning/datasources/InfluxDB.yml
#Create system service for Grafana
sudo systemctl enable --now grafana-server
echo "InfluxDB and Grafana successfully installed - Please access via a web browser on port 3000"