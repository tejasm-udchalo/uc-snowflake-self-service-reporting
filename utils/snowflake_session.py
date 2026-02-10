import streamlit as st
import snowflake.connector
from cryptography.hazmat.primitives import serialization


def get_snowflake_session():

    snowflake_config = st.secrets["snowflake"]

    # Read private key from file
    with open(snowflake_config["private_key_path"], "rb") as key_file:
        private_key = key_file.read()

    p_key = serialization.load_pem_private_key(
        private_key,
        password=None
    )

    pkb = p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    conn = snowflake.connector.connect(
        user=snowflake_config["user"],
        account=snowflake_config["account"],
        private_key=pkb,
        role=snowflake_config["role"],
        warehouse=snowflake_config["warehouse"],
        database=snowflake_config["database"],
        schema=snowflake_config["schema"]
    )

    return conn
