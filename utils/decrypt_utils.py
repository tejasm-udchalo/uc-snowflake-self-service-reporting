import streamlit as st
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


_CIPHER_CACHE = {}


def _get_cipher(version):
    """
    Returns cached AES cipher object based on version.
    Keys & IV are fetched from Streamlit secrets.
    """

    global _CIPHER_CACHE

    if version in _CIPHER_CACHE:
        return _CIPHER_CACHE[version]

    key = base64.b64decode(
        st.secrets["decryption"][f"AES_base64_key_{version}"]
    )

    iv = base64.b64decode(
        st.secrets["decryption"][f"AES_base64_iv_{version}"]
    )

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    _CIPHER_CACHE[version] = cipher
    return cipher


def decrypt(data, version):
    """
    Decrypts full encrypted hex string.
    """

    try:
        if data is None or data == "":
            return data

        cipher = _get_cipher(version)
        decryptor = cipher.decryptor()

        decrypted_data = (
            decryptor.update(bytes.fromhex(data))
            + decryptor.finalize()
        )

        return "".join(
            char for char in decrypted_data.decode("utf-8")
            if char.isprintable()
        )

    except Exception:
        return data

def decrypt_tokenized(data, version):
    """
    Keeps first token as-is and decrypts remaining tokens.
    """

    try:
        if data is None or data == "":
            return data

        parts = str(data).split()

        # If single token, fallback to full decrypt
        if len(parts) <= 1:
            return decrypt(data, version)

        first_part = parts[0]

        decrypted_parts = [
            decrypt(part, version) for part in parts[1:]
        ]

        return first_part + " " + " ".join(decrypted_parts)

    except Exception:
        return data

# ---------------------------------------------------
# Fetch PII Mapping From Snowflake
# ---------------------------------------------------
@st.cache_data(ttl=3600)
def get_pii_mapping(_session, table_name):
    """
    Returns mapping:
    {
        COLUMN_NAME: {
            version: v1/v2
            type: FULL/TOKENIZED
        }
    }

    NOTE:
    _session used to avoid Streamlit hash error
    """

    query = f"""
        SELECT
            COLUMN_NAME,
            DECRYPTION_VERSION,
            COALESCE(DECRYPTION_TYPE, 'FULL') AS DECRYPTION_TYPE
        FROM ANALYTICS.GOLD.STREAMLIT_PII_CONFIG
        WHERE TABLE_NAME = '{table_name.upper()}'
    """

    df = _session.sql(query).to_pandas()

    mapping = {}

    for _, row in df.iterrows():
        mapping[row["COLUMN_NAME"]] = {
            "version": row["DECRYPTION_VERSION"],
            "type": row["DECRYPTION_TYPE"]
        }

    return mapping


# ---------------------------------------------------
# Apply Decryption Dynamically
# ---------------------------------------------------
def decrypt_dataframe(df, session, table_name):
    """
    Applies dynamic decryption based on Snowflake config.
    """

    pii_map = get_pii_mapping(session, table_name)

    # -------- CHANGE: Avoid modifying original dataframe --------
    df = df.copy()

    for column, config in pii_map.items():

        if column not in df.columns:
            continue

        version = config["version"]
        dtype = config["type"]

        # -------- CHANGE: TOKENIZED SUPPORT --------
        if dtype == "TOKENIZED":

            df[column] = df[column].map(
                lambda x: decrypt_tokenized(x, version)
            )

        else:

            df[column] = df[column].map(
                lambda x: decrypt(x, version)
            )

    return df