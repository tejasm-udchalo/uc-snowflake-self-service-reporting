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

        # ---------------- DEBUG PRINTS ----------------
        print("=== AUDIT LOGGING START ===")
        print("USERNAME:", username)
        print("REPORT_NAME:", report_name)
        print("QUERY_TIME_SEC:", query_time)
        print("IS_RESULT_FETCHED:", is_result_fetched)
        print("IS_QUERY_CANCELED:", is_query_canceled)
        print("OUTPUT_SIZE_BYTES:", output_size)
        print("ORIGINAL QUERY:", query)

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

        print("INSERT SQL TO EXECUTE:", insert_sql)

        session.sql(insert_sql).collect()

        print("=== AUDIT LOGGING SUCCESS ===\n")

    except Exception:
        print("⚠️ Audit logging failed:", e)
        pass


def finalize_audit(session, session_state, success=False, canceled=False, df=None):
    """
    Ensures audit is written exactly once
    """

    if not session_state.get("audit_active"):
        print("Audit not active. Skipping.")
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
                print("⚠️ Failed to calculate output size:", e)
                output_size = 0

        print("Finalizing audit...")
        print(f"Success={success}, Canceled={canceled}, Output size={output_size}")

        log_audit(
            session,
            session_state.get("username", "UNKNOWN"),
            session_state.get("audit_report_name", "UNKNOWN"),
            session_state.get("audit_query_sql", "UNKNOWN"),
            query_time,
            success,
            canceled,
            output_size
        )

    finally:
        session_state.audit_active = False
        print("Audit flag reset to False.\n")

