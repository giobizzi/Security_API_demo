# Deployment Guide - API Security Demo

## 📋 VM Instance  Specifications

### Recommended  HW
- 4 CPU cores
- 8GB RAM
- 120GB Storage

### Recommended OS
Linux OS 

## Network connection 

**Inbound Rules** (Add these to your firewall):
```
SSH          TCP    22      0.0.0.0/0
Flask API    TCP    5000    0.0.0.0/0
Splunk Web   TCP    8000    0.0.0.0/0
```

**Outbound Rules**:
```
Allow All    All    All     0.0.0.0/0
```

## 🚀 Step-by-Step Setup 

### Step 1: VM Login 

Login to the VM instance where you want to run the test application 
(suggested: Akamai Linode instance - https://cloud.linode.com)

### Step 2: Install Dependencies 
#### Requirements: 
Docker Engine, Python3, Python Venv, pip, git

#### Update system:
```bash
apt update && apt upgrade -y
```


#### Install Python and complementary tools:

```bash
apt install -y python3 python3-pip python3-venv git curl wget jq nano
```
#### Verify installations
```bash  
python3 --version

# Should see:
# Python 3.xx.x
```

---

### Step 3: Deploy Application 

#### A. Create Project Directory

```bash
mkdir -p ~/api-security-demo
cd ~/api-security-demo
```

#### B. Upload Your Files

Clone the public repository of the demo from Github

```bash
# From VM shell
cd ~/api-security-demo
git clone https://github.com/giobizzi/Security_API_demo.git 
```


#### C. Verify Files
```bash
ls -la
# Should see:
# vulnerable_api_app.py
# requirements.txt
# splunk_inputs_app.tar.gz
# postman_collection.json
```
#### D. Start Flask Application

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start Flask in background
nohup python vulnerable_api_app.py > flask.log 2>&1 &

# Verify
curl http://localhost:5000/health
# Should return: {"status":"healthy",...}

# Check logs
tail -f flask.log
# Press Ctrl+C to stop tailing
```

---

#### E. Start Splunk Container (OPTIONAL)

##### Install Docker Engine:

 Follow instructions for your distro at: https://docs.docker.com/engine/install/

N.B. Remember to the user you want to run the demo  within "docker" group 
```bash
sudo usermod -aG docker your-user-name
```
##### Launch Splunk container
```bash
# Start all services
docker run -d \
  --name splunk \
  --restart unless-stopped \
  -p 8000:8000 \
  -p 8089:8089 \
  -e SPLUNK_START_ARGS="--accept-license" \
  -e SPLUNK_PASSWORD="{PRE_SHARED_PASSWORD}" \
  -e SPLUNK_GENERAL_TERMS="--accept-sgt-current-at-splunk-com" \
  -e SPLUNK_APPS_URL="/tmp/splunk_inputs_app.tar.gz" \
  -v splunk-data:/opt/splunk/var \
  -v splunk-etc:/opt/splunk/etc \
  -v $(pwd)/security_events.log:/logs/security_events.log:ro \
  -v $(pwd)/flask.log:/logs/flask_logs.log:ro \
  -v $(pwd)/splunk_inputs_app.tar.gz:/tmp/splunk_inputs_app.tar.gz \
  splunk/splunk:latest

# Monitor startup (takes 2-3 min)
docker logs -f splunk

# Wait for: "Ansible playbook complete, status=0"
# Press Ctrl+C when done

# Check all containers
docker ps -a

# All should be "Up" or "healthy"
```

### Step 4: Verify Everything Works 

#### From Your Local Machine:

```bash
# Test Flask API
curl http://YOUR_VM_IP:5000/


# Register test user
curl -X POST http://YOUR_VM_IP:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}'
```

#### In Browser:

Open these URLs:
- Flask API: `http://YOUR_VM_IP:5000`
- Splunk: `https://YOUR_VM_IP:8000`

#### Check Splunk:

In Splunk Web UI:
```spl
index=api_security ```Application security logs```
```
```spl
index=flask   ```Web access logs```
```
Should see events from your test registration.

If no events, check:
```bash
# On VM
tail -f ~/api-security-demo/security_events.log
# Should see JSON events

# Check Splunk forwarder
docker logs splunk
```


## 🔒 Security Notes

### Current Setup (Demo-Appropriate):
- ✅ Firewall configured 
- ✅ All demo ports open (necessary for customer access)
- ⚠️ HTTP only (no SSL - OK for demo)
- ⚠️ Simple passwords (OK for demo)

### What You'd Change for Production:
> For production, we'd:
> 1. Use a node balancer with SSL termination
> 2. Private VLAN for backend communication
> 3. Setup log-term log archival
> 4. Backup service enabled (automatic snapshots)
> 5. Enable DDoS protection 
> 6. Integration with CDN for API acceleration
> 7. Setup and configure an API security gateway with proper policies