import streamlit as st
from snowflake.snowpark import Session
from cryptography.hazmat.primitives import serialization


def get_snowflake_session():

    snowflake_config = st.secrets["snowflake"]

    # Load private key from secrets
    private_key = snowflake_config["private_key"].encode()

    p_key = serialization.load_pem_private_key(
        private_key,
        password=None
    )

    pkb = p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    connection_parameters = {
        "account": snowflake_config["account"],
        "user": snowflake_config["user"],
        "private_key": pkb,
        "role": snowflake_config["role"],
        "warehouse": snowflake_config["warehouse"],
        "database": snowflake_config["database"],
        "schema": snowflake_config["schema"],
    }

    return Session.builder.configs(connection_parameters).create()
