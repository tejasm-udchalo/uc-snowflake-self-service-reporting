import streamlit as st
from utils.snowflake_session import get_snowflake_session
from utils.decrypt_utils import decrypt_dataframe
from utils.audit_logger_utils import finalize_audit
import concurrent.futures
import streamlit_authenticator as stauth
import time
import traceback

# ---------------- PAGE CONFIG ---------------- #
st.set_page_config(page_title="Snowflake Reporting", layout="wide")

# ---------------- LOAD CONFIG FROM SECRETS ---------------- #

def load_config_from_secrets():
    credentials = {"usernames": {}}
    try:
        users = st.secrets["credentials"]["usernames"]
        for username, user_data in users.items():
            credentials["usernames"][username] = {
                "email": user_data["email"],
                "first_name": user_data["first_name"],
                "last_name": user_data["last_name"],
                "password": user_data["password"],
                "roles": list(user_data["roles"]),
                "failed_login_attempts": 0,
                "logged_in": False
            }

        config = {
            "credentials": credentials,
            "cookie": {
                "name": st.secrets["cookie"]["name"],
                "key": st.secrets["cookie"]["key"],
                "expiry_days": st.secrets["cookie"]["expiry_days"]
            }
        }

        return config

    except Exception as e:
        raise


# Load config only once into session
if "auth_config" not in st.session_state:
    st.session_state.auth_config = load_config_from_secrets()

config = st.session_state.auth_config

authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days']
)

try:
    auth = authenticator.login('main')
except Exception as e:
    st.error(e)

# -------- FORGOT PASSWORD -------- #

with st.sidebar.expander("🔑 Forgot Password"):
    try:
        username, email, new_password = authenticator.forgot_password()

        if username:
            st.success("New password generated. Share securely with user.")
            st.info(f"Temporary Password: {new_password}")
            # Save updated config
            st.session_state.auth_config = config
        elif username is False:
            st.error("Username not found")

    except Exception as e:
        st.error(e)

# All the authentication info is stored in the session_state
if st.session_state["authentication_status"]:
    # User is connected
    st.session_state["username"] = st.session_state.get("name")
    authenticator.logout('Logout', 'main')
elif st.session_state["authentication_status"] == False:
    st.error('Username/password is incorrect')
    # Stop the rendering if the user isn't connected
    st.stop()
elif st.session_state["authentication_status"] == None:
    st.warning('Please enter your username and password')
    # Stop the rendering if the user isn't connected
    st.stop()

# ===== PERFORMANCE OPTIMIZATION 1: Cache Snowflake Session =====
# This prevents reconnecting to Snowflake on every rerun
# Using @st.cache_resource ensures the session persists across reruns
@st.cache_resource
def get_session():
    return get_snowflake_session()

session = get_session()

# Custom CSS
st.markdown("""
<style>
div[data-testid="stMarkdownContainer"] p {
    margin-bottom: 4px;
}

hr {
    margin-top: 0px !important;
    margin-bottom: 4px !important;
}

.logic-select {
    display: flex;
    justify-content: center;
    margin-top: -8px;
    margin-bottom: -8px;
}
</style>
""", unsafe_allow_html=True)

st.title("Snowflake Self Service Reporting Portal")

# ===== PERFORMANCE OPTIMIZATION 2: Cache Report List =====
# Reports don't change often, so cache them to avoid repeated queries
@st.cache_data
def get_reports():
    df = session.sql("""
        SELECT report_name, table_name
        FROM ANALYTICS.GOLD.STREAMLIT_REPORT_CONFIG
    """).to_pandas()
    return df

reports_df = get_reports()

# Initialize session state for report selection (prevents unnecessary state changes)
if "selected_report" not in st.session_state:
    st.session_state.selected_report = reports_df["REPORT_NAME"].iloc[0]

# Report selection with callback (on_change prevents full rerun from dropdown changes)
report_name = st.selectbox(
    "**Select Report**",
    reports_df["REPORT_NAME"],
    index=list(reports_df["REPORT_NAME"]).index(st.session_state.selected_report),
    key="report_selectbox",
    on_change=lambda: setattr(st.session_state, "selected_report", st.session_state.report_selectbox)
)

# Get table name for selected report
table_name = reports_df[
    reports_df["REPORT_NAME"] == report_name
]["TABLE_NAME"].values[0]

# ===== PERFORMANCE OPTIMIZATION 3: Cache Column Names =====
# Column names are queried per table, cache them so we don't fetch when same table is selected
@st.cache_data
def get_columns(table_name):
    parts = table_name.split(".")

    if len(parts) == 3:
        database, schema, table = parts
    elif len(parts) == 2:
        database = session.get_current_database()
        schema, table = parts
    else:
        database = session.get_current_database()
        schema = session.get_current_schema()
        table = parts[0]

    query = f"""
        SELECT COLUMN_NAME
        FROM {database.upper()}.INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = '{schema.upper()}'
        AND TABLE_NAME = '{table.upper()}'
        ORDER BY ORDINAL_POSITION
    """

    df = session.sql(query).to_pandas()
    return df["COLUMN_NAME"].tolist()

columns = get_columns(table_name)

# Filter Builder UI
st.subheader("Filters")

if "filters" not in st.session_state:
    st.session_state.filters = [{}]

filters_sql = []
validation_error = False

# Column Headings
h1, h2, h3, h4 = st.columns([4, 4, 4, 1])
h1.markdown("**Column**")
h2.markdown("**Operator**")
h3.markdown("**Value**")
h4.markdown("")

st.divider()

# Build filter rows dynamically
for i in range(len(st.session_state.filters)):

    # AND / OR selector for filters after the first
    if i > 0:
        c_left, c_mid, c_right = st.columns([4, 2, 6])
        with c_mid:
            logic = st.selectbox(
                "",
                ["AND", "OR"],
                key=f"logic_{i}",
            )
    else:
        logic = None

    col1, col2, col3, col4 = st.columns([4, 4, 4, 1], vertical_alignment="bottom")

    with col1:
        column = st.selectbox("", columns, key=f"column_{i}")

    with col2:
        operator = st.selectbox(
            "",
            ["=", ">", "<", ">=", "<=", "LIKE", "IN", "IS NULL", "IS NOT NULL"],
            key=f"operator_{i}"
        )

    with col3:
        disable_value = operator in ["IS NULL", "IS NOT NULL"]
        value = st.text_input(
            "",
            key=f"value_{i}",
            disabled=disable_value,
            placeholder="Comma separated values for IN"
        )

    with col4:
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        if i > 0:
            if st.button("✕", key=f"remove_{i}"):
                st.session_state.filters.pop(i)
                for key in [f"logic_{i}", f"column_{i}", f"operator_{i}", f"value_{i}"]:
                    if key in st.session_state:
                        del st.session_state[key]
                st.rerun()

    # Build SQL for this filter
    if column and operator:
        condition_sql = ""

        if operator in ["IS NULL", "IS NOT NULL"]:
            condition_sql = f"{column} {operator}"

        elif operator == "IN":
            if value.strip() == "":
                validation_error = True
            else:
                values = [v.strip() for v in value.split(",") if v.strip()]
                in_clause = ", ".join([f"'{v}'" for v in values])
                condition_sql = f"{column} IN ({in_clause})"

        elif operator == "LIKE":
            if value.strip() == "":
                validation_error = True
            else:
                like_value = value.strip()
                # Add % automatically if user did not provide
                if "%" not in like_value:
                    like_value = f"%{like_value}%"
                condition_sql = f"{column} LIKE '{like_value}'"

        else:
            if value.strip() == "":
                validation_error = True
            else:
                condition_sql = f"{column} {operator} '{value}'"

        if condition_sql:
            if i == 0:
                filters_sql.append(condition_sql)
            else:
                filters_sql.append(f"{logic} {condition_sql}")

# Add filter button
if st.button("➕ Add Filter"):
    st.session_state.filters.append({})
    st.rerun()

# Run / Cancel Query Section
st.divider()
st.text("")

if "audit_active" not in st.session_state:
    st.session_state.audit_active = False
if "audit_start_time" not in st.session_state:
    st.session_state.audit_start_time = None
if "audit_query_sql" not in st.session_state:
    st.session_state.audit_query_sql = None
if "audit_report_name" not in st.session_state:
    st.session_state.audit_report_name = None

# Initialize query tracking
if "query_future" not in st.session_state:
    st.session_state.query_future = None
if "query_running" not in st.session_state:
    st.session_state.query_running = False
if "query_sql" not in st.session_state:
    st.session_state.query_sql = None

col_run, col_cancel = st.columns([0.5, 0.5])
with col_run:
    run_clicked = st.button("Run Query", use_container_width=True)

with col_cancel:
    cancel_clicked = st.button(
        "Cancel Query",
        disabled=not st.session_state.query_running,
        use_container_width=True
    )

# Handle cancel query
if cancel_clicked and st.session_state.query_future:
    st.session_state.query_future.cancel()
    st.session_state.query_running = False
    st.session_state.query_future = None

    try:
        finalize_audit(session, st.session_state, canceled=True)
    except Exception:
        pass

    st.warning("❌ Query was cancelled by user.")
    st.stop()

# Handle run query
if run_clicked:
    if validation_error:
        st.error("⚠️ Please provide value for all required filters.")
        st.stop()

    where_clause = " ".join(filters_sql)
    query = f"SELECT * FROM {table_name}"
    if where_clause:
        query += f" WHERE {where_clause}"

    st.session_state.query_sql = query
    st.session_state.query_running = True
    st.session_state.audit_active = True
    st.session_state.audit_start_time = time.time()
    st.session_state.audit_query_sql = query
    st.session_state.audit_report_name = report_name
    st.rerun()  # Rerun to update UI and show enabled cancel button

# Execute query if running
if st.session_state.query_running and st.session_state.query_future is None:
    query = st.session_state.query_sql
    
    def execute_query(q):
        return session.sql(q).to_pandas()

    with st.spinner("Running query... ⏳"):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(execute_query, query)
            st.session_state.query_future = future
            try:
                # 3 minutes timeout enforced
                df = future.result(timeout=180)
                st.session_state.query_running = False
                st.session_state.query_future = None

                # Dynamic PII Decrypt
                df = decrypt_dataframe(df, session, table_name)
                st.dataframe(df)

                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button("Download CSV", csv, file_name=f"{report_name}.csv")

                # Log audit
                try:
                    finalize_audit(session, st.session_state, success=True, df=df)
                except Exception:
                    pass

            except concurrent.futures.TimeoutError:
                st.session_state.query_running = False
                st.session_state.query_future = None

                # Log audit
                try:
                    finalize_audit(session, st.session_state, canceled=True)
                except Exception:
                    pass

                st.error("⚠️ Query execution took too long (>3 minutes) and was cancelled. Please refine your filters.")

            except Exception as e:
                st.session_state.query_running = False
                st.session_state.query_future = None

                # Log audit
                try:
                    finalize_audit(session, st.session_state, success=False)
                except Exception:
                    pass
