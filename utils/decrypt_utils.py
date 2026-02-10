import streamlit as st
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


_CIPHER_CACHE = {}


def _get_cipher(version):

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


# ---------------------------------------------------
# Fetch PII Mapping From Snowflake
# ---------------------------------------------------
@st.cache_data(ttl=3600)
def get_pii_mapping(_session, table_name):

    query = f"""
        SELECT COLUMN_NAME, DECRYPTION_VERSION
        FROM ANALYTICS.GOLD.STREAMLIT_PII_CONFIG
        WHERE TABLE_NAME = '{table_name.upper()}'
    """

    df = _session.sql(query).to_pandas()

    return dict(zip(df["COLUMN_NAME"], df["DECRYPTION_VERSION"]))


# ---------------------------------------------------
# Apply Decryption Dynamically
# ---------------------------------------------------
def decrypt_dataframe(df, session, table_name):

    # No change needed here — Streamlit ignores caching based on _session
    pii_map = get_pii_mapping(session, table_name)

    for column, version in pii_map.items():

        if column in df.columns:

            df[column] = df[column].map(
                lambda x: decrypt(x, version)
            )

    return df