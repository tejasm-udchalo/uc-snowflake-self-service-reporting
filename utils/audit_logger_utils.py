import time
from datetime import datetime
import pytz
import streamlit as st


def log_audit(session, username, report_name, query, query_time,
              is_result_fetched, is_query_canceled, output_size):
    """
    Writes audit log into Snowflake with enhanced error reporting.
    Returns (success: bool, message: str)
    """

    try:
        ist = pytz.timezone("Asia/Kolkata")
        queried_at = datetime.now(ist)

        # Escape single quotes in query
        query_safe = query.replace("'", "''") if query else "UNKNOWN"

        insert_sql = f"""
        INSERT INTO ANALYTICS.GOLD.STREAMLIT_AUDIT_LOG
        (
            USERNAME,
            REPORT_NAME,
            QUERIED_AT,
            QUERY_TIME_SEC,
            IS_RESULT_FETCHED,
            IS_QUERY_CANCELED,
            QUERY_OUTPUT_SIZE_BYTES,
            QUERY_TEXT
        )
        VALUES
        (
            '{username}',
            '{report_name}',
            '{queried_at}',
            {query_time},
            {str(is_result_fetched).upper()},
            {str(is_query_canceled).upper()},
            {output_size},
            $$ {query_safe} $$
        )
        """

        # Execute insert
        session.sql(insert_sql).collect()
        
        msg = f"✅ Audit logged: {username} | {report_name} | {query_time}s"
        return True, msg

    except Exception as e:
        msg = f"❌ Audit insert failed: {str(e)}"
        return False, msg


def finalize_audit(session, session_state, success=False, canceled=False, df=None, show_ui=False):
    """
    Ensures audit is written exactly once.
    
    Args:
        session: Snowflake session
        session_state: Streamlit session state
        success: Whether query succeeded
        canceled: Whether query was canceled
        df: Query result dataframe (optional)
        show_ui: Whether to display status messages in Streamlit UI (for debugging)
    
    Returns:
        (success: bool, message: str)
    """

    if not session_state.get("audit_active"):
        msg = "⚠️ Audit not active. Skipping."
        if show_ui:
            st.info(msg)
        return False, msg

    try:
        end_time = time.time()
        start_time = session_state.get("audit_start_time", end_time)
        query_time = round(end_time - start_time, 2)

        output_size = 0
        if df is not None:
            try:
                output_size = int(df.memory_usage(deep=True).sum())
            except Exception as e:
                output_size = 0

        # Log to Snowflake
        insert_success, insert_msg = log_audit(
            session,
            session_state.get("username", "UNKNOWN"),
            session_state.get("audit_report_name", "UNKNOWN"),
            session_state.get("audit_query_sql", "UNKNOWN"),
            query_time,
            success,
            canceled,
            output_size
        )

        # Mark audit as completed to prevent duplicate logging
        session_state["audit_active"] = False

        if show_ui:
            if insert_success:
                st.success(insert_msg)
            else:
                st.error(insert_msg)

        return insert_success, insert_msg

    except Exception as e:
        msg = f"❌ finalize_audit failed: {str(e)}"
        if show_ui:
            st.error(msg)
        return False, msg

    finally:
        session_state.audit_active = False
        print("Audit flag reset to False.\n")

