import time
from datetime import datetime
import pytz


def log_audit(session, username, report_name, query, query_time,
              is_result_fetched, is_query_canceled, output_size):
    """
    Writes audit log into Snowflake
    Safe failure handling
    """
    
    try:
        ist = pytz.timezone("Asia/Kolkata")
        queried_at = datetime.now(ist)

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
            $$ {query} $$
        )
        """

        session.sql(insert_sql).collect()

    except Exception:
        pass


def finalize_audit(session, session_state, success=False, canceled=False, df=None):
    """
    Ensures audit is written exactly once
    """

    if not session_state.get("audit_active"):
        return

    try:
        end_time = time.time()
        start_time = session_state.get("audit_start_time", end_time)

        query_time = round(end_time - start_time, 2)

        output_size = 0
        if df is not None:
            try:
                output_size = int(df.memory_usage(deep=True).sum())
            except:
                output_size = 0

        log_audit(
            session,
            session_state.get("username"),
            session_state.get("audit_report_name"),
            session_state.get("audit_query_sql"),
            query_time,
            success,
            canceled,
            output_size
        )

    finally:
        session_state.audit_active = False
