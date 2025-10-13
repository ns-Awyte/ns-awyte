#!/bin/bash

# This script automates the setup of a development environment on Ubuntu,
# including Docker, Minikube, kubectl, and Helm, and then configures a Helm release.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- 1. Pre-flight Check: Verify Disk Space ---
echo "▶️ Performing pre-flight checks..."

# Define required space in Kilobytes (25GB)
REQUIRED_KB=$((25 * 1024 * 1024))

# Get available space on the root filesystem in Kilobytes
AVAILABLE_KB=$(df -k / | awk 'NR==2 {print $4}')

# Check if available space is less than required space
if [ "$AVAILABLE_KB" -lt "$REQUIRED_KB" ]; then
  echo "❌ Error: Not enough free disk space on the root filesystem ('/')."
  # Show user-friendly output
  echo "   Required: 25G"
  echo "   Available: $(df -h / | awk 'NR==2 {print $4}')"
  exit 1
else
  echo "✅ Disk space check passed. ($(df -h / | awk 'NR==2 {print $4}') available)"
fi

# --- 2. System Update & Prerequisite Installation ---
echo "Updating package lists and installing prerequisites..."
sudo apt-get update
sudo apt-get install -y unzip ca-certificates curl snapd

# --- 3. Install Docker ---
echo "⚙️  Installing Docker..."

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the Docker repository to Apt sources
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package list again to include the new Docker repo, then install
echo "Updating sources for Docker and installing..."
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "✅ Docker installed successfully."
echo "Verifying Docker installation..."
sudo docker run hello-world

# --- 4. Install Minikube ---
echo "⚙️  Installing Minikube..."
curl -LO https://github.com/kubernetes/minikube/releases/latest/download/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube && rm minikube-linux-amd64
echo "✅ Minikube installed successfully."

echo "🚀 Starting Minikube cluster... (This may take a few minutes)"
minikube start

# --- 5. Install kubectl & Helm ---
echo "⚙️  Installing kubectl and Helm via snap..."
sudo snap install kubectl --classic
sudo snap install helm --classic
echo "✅ kubectl and Helm installed successfully."

echo "Verifying kubectl connection..."
kubectl get po -A

echo "Verifying Helm installation..."
helm version

# --- 6. Download and Unzip Helm Chart ---
echo "📥 Downloading and unzipping the Netskope Helm chart..."
wget -O helm-dspm-sidecar.zip https://netskope-dspm-release.s3.us-west-2.amazonaws.com/helm-dspm-sidecar.zip
unzip -o helm-dspm-sidecar.zip # Use -o to overwrite without prompting

# --- 7. Configure and Deploy Helm Chart ---
echo "📝 Please provide the following details for the Helm deployment."

# Prompt for user input
echo -n "Enter the Sidecar Name: "
read SideCarname

echo -n "Enter your Tenant Name (e.g., 'mycompany' for mycompany.goskope.com): "
read tenant

echo -n "Enter the Registration Token (input will be hidden): "
read -s Regtoken
echo # Adds a newline after the hidden input for better formatting

# Validate that inputs are not empty
if [ -z "$SideCarname" ] || [ -z "$tenant" ] || [ -z "$Regtoken" ]; then
  echo "❌ Error: One or more inputs were empty. Aborting deployment."
  exit 1
fi

echo "🚀 Deploying the Netskope sidecar with your configuration..."

# Execute the helm command with the user-provided variables properly quoted
helm upgrade --install netskope netskope --namespace netskope --create-namespace --values netskope/values.yaml \
 --set image.tag=latest \
 --set sidecarName="${SideCarname}" \
 --set image.pullPolicy=Always \
 --set daseraMainApplicationHost="${tenant}.goskope.com" \
 --set sidecarPoolToken="${Regtoken}" \
 --set resources.sidecar.requests.cpu=3 \
 --set resources.sidecar.limits.cpu=3 \
 --set sidecarCount=1

echo "🎉 Helm chart deployed!"

# --- 8. Post-Deployment Management Menu ---
echo "Entering management mode..."

while true; do
  echo ""
  echo "What would you like to do next?"
  echo "  1) Check Pod status"
  echo "  2) Check DSPM-Sidecar Container Log (last 50 lines)"
  echo "  3) Exit"
  
  read -p "Enter your choice [1-3]: " choice

  case "$choice" in
    1)
      echo "--- Checking Pod status in 'netskope' namespace ---"
      kubectl get pods -n netskope
      echo "----------------------------------------------------"
      ;;
    2)
      echo "--- Fetching DSPM-Sidecar logs... ---"
      # This command finds the pod name automatically and tails the log
      # It may fail if no pod is found, which is expected behavior
      POD_NAME=$(kubectl get pods -n netskope -o jsonpath='{.items[?(@.metadata.labels.app\.kubernetes\.io/name=="dspm-sidecar")].metadata.name}')
      if [ -n "$POD_NAME" ]; then
        kubectl exec -it -n netskope "$POD_NAME" -- tail -50 logs/netskopedspm.log
      else
        echo "Could not find a 'dspm-sidecar' pod in the 'netskope' namespace."
      fi
      echo "---------------------------------------"
      ;;
    3)
      echo "Exiting management mode."
      break
      ;;
    *)
      echo "Invalid option. Please enter a number between 1 and 3."
      ;;
  esac
done

echo "✅ Script finished successfully."
