## 🎯 Overview

This demo showcases a vulnerable e-commerce API with both insecure and secure endpoints, demonstrating:

- **API1**: Broken Object Level Authorization (BOLA)
- **API2**: Broken Authentication (no rate limiting)
- **API3**: Excessive Data Exposure
- **API6**: Mass Assignment (privilege escalation)

Each vulnerability has a corresponding **secure endpoint** showing proper mitigation.

---

## 📋 Prerequisites and  environment setup

See attached **setup_guide.md** document

---

## 🎬 Demo Script 

### Part 1: Architecture Overview 

**Three-tier architecture:**

```
Client (Postman or CLI)  → Flask API → SQLite Database
                                ↓
                            Log files → Splunk (SIEM)
```

**Key points:**
- **Flask API**: Implements both vulnerable and secure endpoints
- **Splunk**: Collects and visualizes security events in real-time
- **Two users**: Alice and Bob, each with orders
- **Demonstrates**: Real-world API security 


---

### Part 2: Attack Demonstrations 

**Important**: Run attacks through **BOTH** paths to show vulnerability mitigation:

1. **Vulnerable API** - `http://localhost:5000/{REST_RESOURCE}` 
2. **Mitigated version** - `http://localhost:8000/{REST_RESOURCE}/secure`

#### Demo 1: BOLA - Broken Object Level Authorization 

**Business Impact**: Attackers can access other users' sensitive data by simply changing IDs in URLs

**Steps:**
1. Register Alice and Bob
2. **Direct Attack** (Flask):
   ```bash
   # Alice accesses Bob's order directly
   curl http://VM_IP:5000/api/orders/2 -H "Authorization: Bearer $ALICE_TOKEN"
   ```
   - **Result**: 200 OK - Alice sees Bob's order! 🚨
   - **Show logs**: `tail -f security_events.log` - See BOLA event logged

   > **Vulnerability:** The app logic doesn't check the correspondence between authenticated users and legitimate resource owner

3. **Secure Endpoint**:
   ```bash
   curl http://VM_IP:5000/api/secure/orders/2 -H "Authorization: Bearer $ALICE_TOKEN"
   ```
   - **Result**: 403 Forbidden ✅
   - **Show logs**: See "bola_blocked" event

   > **Mitigation:** The app code now verifies that the authenticated user properly own the order

   **Show in Splunk** (optional):
    1. Open https://VM_IP:8000 and log in into Splunk (user: admin, pass {PRE_SHARED_PASS})
    2. Navigate to Search tab
    3. Run SPL query: `index=api_security attack_type="bola" earliest=-1h`
    4. Show visualization of BOLA attempts over time

---

#### Demo 2: Excessive Data Exposure 

**Business Impact**: APIs leak sensitive PII unnecessarily, amplifying breach impact

**Steps:**
1. **Vulnerable endpoint**:
   ```bash
   curl http://VM_IP:8000/api/users/1 -H "Authorization: Bearer $ALICE_TOKEN"
   ```
   - **Result**: 200 OK - Alice sees her full password hash in clear text! 🚨

   > **Vulnerability:** The data access query is too broad and returns back unnecessary user information 

2. **Secure Endpoint**:
   ```bash
   curl http://VM_IP:5000/api/users/1/secure -H "Authorization: Bearer $ALICE_TOKEN"
   ```
   - **Result**: 200 OK - No password hashes returned back to client ✅
   - **Show logs**: See "excessive_data_exposure" event

   > **Mitigation:** Now the data attributes are carefully handle to return only the minimum data set that the authenticated user needs

   **Show in Splunk** (optional):
   Run SPL query: `index=api_security  attack_type="excessive_data_exposure"  earliest=-1h`

---

#### Demo 3: Mass Assignment - Privilege Escalation 

**Business Impact**: Users can modify fields they shouldn't access, escalating to admin role

**Steps:**
1. **Vulnerable endpoint**:
   ```bash
   curl -X PUT http://VM_IP:5000/api/users/1 \
     -H "Authorization: Bearer $ALICE_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"email":"alice.admin@example.com","role":"admin"}'
   ```
   - **Result**: 200 OK - Role updated to admin! 🚨
   - **Show logs**: See "privilege_escalation" event with high severity

   > **Vulnerability:** All attributes passed by client are written into backend database without any filter 

2. **Secure endpoint**:
   ```bash
   curl -X PUT http://VM_IP:5000/api/users/2/secure \
     -H "Authorization: Bearer $BOB_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"email":"bob.hacker@example.com","role":"admin"}'
   ```
   - **Result**: Role field ignored, only email updated ✅
   - **Show logs**: See "mass_assignment_blocked" event
   
   > **Mitigation:** Now the application logic filters out the dangerous role attributed before updating user's data, although it is maliciously passed by client
   
---

#### Demo 4: Broken Authentication - Brute Force

**Business Impact**: Attackers can try unlimited passwords without detection

**Steps:**
1. **Direct Attack** (Flask vulnerable endpoint):
   ```bash
   # Try 5 wrong passwords
   for i in {1..5}; do
     curl http://localhost:5000/api/auth/login \
       -H "Content-Type: application/json" \
       -d "{\"username\":\"alice\",\"password\":\"wrong$i\"}"
     echo ""
   done
   ```
   - **Result**: All attempts go through and the attacker can check the validity of each guessed password 🚨

   > **Vulnerability:** The attack would be potentially able to try as much as passwords he wants until it finds the right one (brute-force attack)
   
3. **Flask secure endpoint** (application-level rate limiting):
   ```bash
   # Only 3 attempts allowed
   for i in {1..4}; do
     curl http://localhost:5000/api/auth/login-secure \
       -H "Content-Type: application/json" \
       -d "{\"username\":\"bob\",\"password\":\"wrong$i\"}"
     echo ""
   done
   ```
   - **Result**: 4th attempt returns 429 (stricter limit) ✅

   > **Mitigation:** Now the application limits the authentication attempts to 3 in a 60 seconds time window, and after that returns back 429 errors (avoiding to provide password validity information anymore)

   **Show in Splunk** (optional):
   Run SPL query: `index=api_security  attack_type="brute_force"  earliest=-1h`
---


## 🔧 API Endpoints Reference

### Authentication
```
POST /api/auth/register          - Register new user
POST /api/auth/login             - Login (vulnerable, no rate limit)
POST /api/auth/login-secure      - Login (secure, rate limited)
```

### Users (Vulnerable)
```
GET  /api/users/:id              - Get user (exposes all data)
PUT  /api/users/:id              - Update user (mass assignment)
```

### Users (Secure)
```
GET  /api/users/:id/secure       - Get user (filtered data)
PUT  /api/users/:id/secure       - Update user (whitelisted fields)
```

### Orders (Vulnerable)
```
GET  /api/orders/:id             - Get order (no authorization)
GET  /api/orders                 - List all orders
```

### Orders (Secure)
```
GET  /api/secure/orders/:id      - Get order (with authorization)
GET  /api/secure/orders          - List user's orders only
```

### Utility
```
GET  /                           - API documentation
GET  /health                     - Health check
```

---
