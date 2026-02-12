import streamlit as st
from utils.snowflake_session import get_snowflake_session
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def get_active_session():

    if "sf_session" not in st.session_state:
        st.session_state.sf_session = get_snowflake_session()

    return st.session_state.sf_session


def _reconnect_session():
    logger.warning("Snowflake session expired. Reconnecting...")
    st.session_state.sf_session = get_snowflake_session()
    return st.session_state.sf_session


def execute_select(query, params=None, retries=1):

    try:
        session = get_active_session()

        if params:
            return session.sql(query, params=params).to_pandas()

        return session.sql(query).to_pandas()

    except Exception as e:

        error_msg = str(e)

        if "Authentication token has expired" in error_msg and retries > 0:
            session = _reconnect_session()

            if params:
                return session.sql(query, params=params).to_pandas()

            return session.sql(query).to_pandas()

        logger.error(f"SELECT Query Failed: {error_msg}")
        raise e


def execute_dml(query, params=None, retries=1):

    try:
        session = get_active_session()

        if params:
            return session.sql(query, params=params).collect()

        return session.sql(query).collect()

    except Exception as e:

        error_msg = str(e)

        if "Authentication token has expired" in error_msg and retries > 0:
            session = _reconnect_session()

            if params:
                return session.sql(query, params=params).collect()

            return session.sql(query).collect()

        logger.error(f"DML Query Failed: {error_msg}")
        raise e
