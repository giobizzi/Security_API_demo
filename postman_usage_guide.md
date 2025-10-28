# Postman Collection Usage Guide


## 🚀 Quick Start

### 1. Import Collection in Postman

```bash
# File: postman_collection.json
```

1. Open Postman
2. Click **Import** → **Upload Files**
3. Select `postman_collection.json`
4. The collection is now shown into the workspace

### 2. Configure Variables

**Main variables:**
- `base_url`: `http://YOUR_VM_IP:5000` 


---

## 📂 Collection Structure

### Folder 6: Utility Endpoints - Health Checks
**Goal**: Verify correct application functionality

```
✅  Health Check     - Check if Flask applicationn is up & running

```

**Run this before starting the demo**

---

### Folder 1: Setup - Create Users
**Goal**: Register test users within app database (Alice e Bob)

**Requests:**
1. `Register Alice `  
2. `Register Bob ` 

**Auto-save variables:**
- `alice_token` - JWT token of Alice
- `bob_token` - JWT token of Bob
- `alice_id` - User ID of Alice
- `bob_id` - User ID of Bob

**Exec in order: 1 → 2**

---

### Folder 2: ATTACK - BOLA (API1)
**Goal**: "Broken Object Level Authorization" (BOLA) attack demonstration

**Demo Flow:**
1. `🔓 VULNERABLE - Alice accesses Bob's order` -> GET **/api/orders/** endpoint
   - Alice downloads info about Bob's order 🚨 VULNERABILITY PRESENT!
   - Verify: status 200, username='bob', Alice's session token used for request

2`🔒 SECURE - Alice blocked from Bob's order` GET  **/api/secure/orders/** endpoint
   - The secure endpoint sicuro blocks Alice's BOLA attempt ✅ Blocked
   - Verify: status 403 - access forbidden

---

### Folder 3: ATTACK - Excessive Data Exposure (API3)
**Goal**: Demonstrate PII leakage

**Demo Flow:**
1. `🔓 VULNERABLE - Get user with PII` -> GET **/api/users/** endpoint
   - Response include password hash, SSN, credit card
   - Verify: status 200, "password" field present

2. `🔒 SECURE - Get user filtered`  -> GET **/api/users/secure** endpoint
   - Filtered response, safe fields only 🚨 VULNERABILITY PRESENT!
   - Verify: status 200,  "password" field not returned  ✅ Does not leak sensitive user's info


### Folder 4: ATTACK - Mass Assignment (API6)
**Goal**:  Privilege escalation demonstration

**Demo Flow:**
1. `🔓 VULNERABLE - Alice escalates to admin` -> PUT **/api/users/** endpoint
   - Alice becomes admin 🚨 VULNERABILITY PRESENT!
   - Verify: status 200, Alice's role updated (use proper get endpoint below)

2. `Verify Alice is now admin` -> GET **/api/users/** endpoint
   - Confirms that Alice's role = "admin"

3. `🔒 SECURE - Role update blocked -> PUT **/api/users/secure** endpoint
   - The secure endpoint ignores "role" fields passed by client
   - Verify: status 200, role NOT updated (only other fields) ✅ Standard user cannot alter critical user's attributes

---

### Folder 5: ATTACK - Broken Authentication (API2)
**Goal**: Rate limiting demonstration

**Demo Flow:**
1. **🔓 VULNERABLE - User tries login** - 3 login attempts -> POST **/api/auth/login** endpoint
   - User's receives response and can verify guessed password validity for each (no app-level rate limit) 🚨 VULNERABILITY PRESENT!

2. **🔒 SECURE - Login endpoint with rate limiting** - 4 login attempts -> POST **/api/auth/login-secure** endpoint
   - The 4th login attempts is now blocked  with a 429 HTTP response code
   - App-level rate limit (3/min) ✅ Malitious client cannot brute-force user's credentials anymore

---

### Folder 6: Utility Endpoints
**Goal**: Admin & debugging

**Requests:**
- API Documentation  -> GET **/** endpoint
- Application Health Check -> GET **/health** endpoint

**Use:** For troubleshooting and documentation

---