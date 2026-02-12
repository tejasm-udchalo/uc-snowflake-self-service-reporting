import streamlit as st
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from functools import lru_cache


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
        # Delegate to cached decrypt helper to avoid repeated work
        return _decrypt_cached(data, version)
    except Exception:
        return data


@lru_cache(maxsize=200000)
def _decrypt_cached(data_hex: str, version: str) -> str:
    """
    Cached low-level decrypt function. Uses hex string + version as cache key.
    Returns decrypted printable string or raises on failure.
    """
    if data_hex is None or data_hex == "":
        return data_hex

    cipher = _get_cipher(version)
    decryptor = cipher.decryptor()

    decrypted_data = (
        decryptor.update(bytes.fromhex(data_hex))
        + decryptor.finalize()
    )

    return "".join(
        char for char in decrypted_data.decode("utf-8")
        if char.isprintable()
    )

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

        # Use cached low-level decrypt for each token
        decrypted_parts = [
            _decrypt_cached(part, version) if part and part != "" else part
            for part in parts[1:]
        ]

        return first_part + " " + " ".join(decrypted_parts)

    except Exception:
        return data
    
def decrypt_split_full(data, version):
    """
    Decrypt every token separately
    """
    try:
        if data is None or data == "":
            return data

        parts = str(data).split()

        decrypted_parts = [
            _decrypt_cached(part, version) if part and part != "" else part
            for part in parts
        ]

        return " ".join(decrypted_parts)

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

        # FULL decrypt
        if dtype == "FULL":

            df[column] = df[column].map(
                lambda x: decrypt(x, version)
            )

        # TOKENIZED decrypt
        elif dtype == "TOKENIZED":

            df[column] = df[column].map(
                lambda x: decrypt_tokenized(x, version)
            )

        # SPLIT FULL decrypt
        elif dtype == "SPLIT_FULL":

            df[column] = df[column].map(
                lambda x: decrypt_split_full(x, version)
            )

    return df