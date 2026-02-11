# 🔐 Password Hash Generator for Streamlit Authenticator

This utility script is used to generate **bcrypt hashed passwords** for use with `streamlit-authenticator`.

Since passwords **should never be stored in plain text**, this script converts a password into a secure hash which can safely be stored inside `st.secrets` or configuration files.

---

## ✅ Prerequisites

Make sure the following package is installed:

```bash
pip install streamlit-authenticator
```

---

## Script : generate_hash.py

```python
import streamlit_authenticator as stauth
password = "YOUR_PASSWORD"
hashed = stauth.Hasher().hash(password)
print(hashed)
```
---

## ▶️ How To Run

Run the script from terminal:

```bash
python generate_hash.py
```

---

## 🧾 Output Example
```swift
$2b$12$jgde/TYiTEYgYx.mTlkRcuWG5B/9sT/pgxzGylTMUOZgAphxyCvUy
```
This is the hashed password.

---

## 🔒 How To Use Hash
Store the generated hash inside Streamlit secrets:

[credentials.usernames.YOUR_USERNAME]
email = "YOUR.ID@DOMAIN.com"
first_name = "YOUR_FIRST_NAME"
last_name = "YOUR_LAST_NAME"
password = "YOUR_HASHED_PASSWORD"
roles = ["YOUR_ROLE_1", "YOUR_ROLE_2"]