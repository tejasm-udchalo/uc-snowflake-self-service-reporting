# Secrets Setup Guide

## Overview
This project uses **Streamlit Secrets** to manage sensitive credentials securely. Real credentials are **NEVER committed to Git**.

## File Structure
```
.streamlit/
├── secrets.toml          ← SAMPLE ONLY (gitignored, safe to commit as template)
└── secrets.local.toml    ← YOUR ACTUAL CREDENTIALS (gitignored, local only)
secrets.example.toml      ← Reference template for all developers
```

## Local Development Setup

### Step 1: Create Your Local Secrets File
```bash
cp .streamlit/secrets.toml .streamlit/secrets.local.toml
```

### Step 2: Edit with Your Credentials
Open `.streamlit/secrets.local.toml` and replace all placeholder values with your actual credentials:

```toml
[snowflake]
account = "xy12345-us-east-1"
user = "YOUR_USERNAME"
role = "YOUR_ROLE"
warehouse = "YOUR_WAREHOUSE"
database = "ANALYTICS"
schema = "GOLD"
private_key = """
-----BEGIN PRIVATE KEY-----
(your actual key)
-----END PRIVATE KEY-----
"""

[decryption]
AES_base64_key_v1 = "your_actual_base64_key"
AES_base64_iv_v1 = "your_actual_base64_iv"
```

### Step 3: Configure Streamlit to Use Local Secrets
Edit `.streamlit/config.toml` (or create it):
```toml
[client]
showErrorDetails = true
```

Streamlit automatically looks for `~/.streamlit/secrets.toml` or `.streamlit/secrets.toml` in the project root.

### Step 4: Run Locally
```bash
streamlit run streamlit_app.py
```

Streamlit will read from `.streamlit/secrets.toml` automatically.

---

## Streamlit Cloud Deployment

### Step 1: Do NOT Push Real Credentials
Ensure `.gitignore` excludes:
```
.streamlit/secrets.toml
.streamlit/secrets.local.toml
```

### Step 2: Configure Secrets in Streamlit Cloud

1. Push your code to GitHub (only code, no real secrets)
2. Go to [Streamlit Cloud Dashboard](https://share.streamlit.io)
3. Find your app → Click **Settings** ⚙️
4. Go to **Secrets** tab
5. Copy-paste your secrets in TOML format:
   ```toml
   [snowflake]
   account = "..."
   user = "..."
   ...
   ```
6. Click **Save**

Streamlit Cloud automatically injects these secrets as environment variables when your app runs.

---

## Generating Required Credentials

### Snowflake Private Key
```bash
# Generate unencrypted key (easier for service accounts)
openssl genrsa 2048 | openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt

# Generate encrypted key (more secure)
openssl genrsa 2048 | openssl pkcs8 -topk8 -v2 des3 -inform PEM -outform PEM
```

### AES Encryption Keys (for PII)
```bash
# Generate 32-byte key
openssl rand -base64 32

# Generate 16-byte IV
openssl rand -base64 16
```

---

## Security Best Practices

✅ **DO:**
- Keep `.streamlit/secrets.toml` and `.streamlit/secrets.local.toml` in `.gitignore`
- Use different credentials for dev/staging/production
- Rotate keys periodically
- Use Streamlit Cloud's Secrets dashboard for production
- Use service accounts with minimal required permissions

❌ **DON'T:**
- Commit real credentials to Git
- Use personal user credentials for service accounts
- Share secrets via email/Slack
- Hardcode credentials in code
- Reuse the same credentials across environments

---

## Troubleshooting

### Error: "KeyError: 'snowflake'"
The app can't find the secrets. Make sure:
- `.streamlit/secrets.toml` exists in the project root
- Streamlit is reading it: `streamlit run --logger.level=debug streamlit_app.py`
- File format is valid TOML

### Error: "Connection refused"
- Check Snowflake account ID is correct
- Verify Snowflake service account is active
- Confirm private key is valid and registered with Snowflake

### Error: "Decryption failed"
- Verify AES keys match the version in your database
- Check base64 encoding is correct
- Ensure no extra whitespace in keys

---

## Useful Commands

```bash
# Test Streamlit secrets locally (print to console - DEBUG ONLY!)
streamlit run -c "import streamlit as st; print(st.secrets)" streamlit_app.py

# Validate TOML syntax
python -m toml .streamlit/secrets.toml

# Generate test credentials
openssl rand -base64 32  # 32-byte key
openssl rand -base64 16  # 16-byte IV
```

---

## References
- [Streamlit Secrets Management](https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app/secrets-management)
- [Snowflake Key Pair Authentication](https://docs.snowflake.com/en/user-guide/key-pair-auth)
- [TOML Format Guide](https://toml.io)
