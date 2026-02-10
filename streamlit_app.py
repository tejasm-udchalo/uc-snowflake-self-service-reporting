import streamlit as st
from utils.snowflake_session import get_snowflake_session
from utils.decrypt_utils import decrypt_dataframe
import concurrent.futures

# -----------------------------
# Custom CSS
# -----------------------------
st.markdown("""
<style>

div[data-testid="stMarkdownContainer"] p {
    margin-bottom: 4px;
}

hr {
    margin-top: 0px !important;
    margin-bottom: 4px !important;
}

/* Compact AND / OR selector styling */
.logic-select {
    display: flex;
    justify-content: center;
    margin-top: -8px;
    margin-bottom: -8px;
}

</style>
""", unsafe_allow_html=True)

st.title("Snowflake Self Service Reporting Portal")

session = get_snowflake_session()

# -----------------------------
# Fetch Report List
# -----------------------------
@st.cache_data
def get_reports():
    df = session.sql("""
        SELECT report_name, table_name
        FROM ANALYTICS.GOLD.STREAMLIT_REPORT_CONFIG
    """).to_pandas()
    return df

reports_df = get_reports()

report_name = st.selectbox(
    "**Select Report**",
    reports_df["REPORT_NAME"]
)

table_name = reports_df[
    reports_df["REPORT_NAME"] == report_name
]["TABLE_NAME"].values[0]

# -----------------------------
# Fetch Column Names
# -----------------------------
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

# -----------------------------
# Filter Builder
# -----------------------------
st.subheader("Filters")

if "filters" not in st.session_state:
    st.session_state.filters = [{}]

filters_sql = []
validation_error = False

# ----------- Column Headings -----------
h1, h2, h3, h4 = st.columns([4, 4, 4, 1])
h1.markdown("**Column**")
h2.markdown("**Operator**")
h3.markdown("**Value**")
h4.markdown("")

st.divider()

# ----------- Filter Rows -----------
for i in range(len(st.session_state.filters)):

    # AND / OR selector between filters (not first filter)
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

    # -----------------------------
    # Build SQL per filter
    # -----------------------------
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

            # ✅ Add % automatically if user did not provide
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

# -----------------------------
# Add Filter Button
# -----------------------------
if st.button("➕ Add Filter"):
    st.session_state.filters.append({})
    st.rerun()

# -----------------------------
# Run / Cancel Query
# -----------------------------
st.divider()
st.text("")

# ----------- Initialize query tracking -----------
if "query_future" not in st.session_state:
    st.session_state.query_future = None
if "query_running" not in st.session_state:
    st.session_state.query_running = False

col_run, col_cancel = st.columns([0.5, 0.5])
with col_run:
    run_clicked = st.button("Run Query", use_container_width=True)

with col_cancel:
    cancel_clicked = st.button(
        "Cancel Query",
        disabled=not st.session_state.query_running,  # Enabled only if query is running
        use_container_width=True

    )

# -----------------------------
# Handle Cancel Query
# -----------------------------
if cancel_clicked and st.session_state.query_future:
    st.session_state.query_future.cancel()  # attempts to cancel the thread
    st.session_state.query_running = False
    st.session_state.query_future = None
    st.warning("❌ Query was cancelled by user.")
    st.stop()

# -----------------------------
# Handle Run Query
# -----------------------------
if run_clicked:
    if validation_error:
        st.error("⚠️ Please provide value for all required filters.")
        st.stop()

    where_clause = " ".join(filters_sql)
    query = f"SELECT * FROM {table_name}"
    if where_clause:
        query += f" WHERE {where_clause}"

    st.session_state.query_running = True

    def execute_query(q):
        return session.sql(q).to_pandas()

    with st.spinner("Running query... ⏳"):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(execute_query, query)
            st.session_state.query_future = future
            try:
                # ------------------ Recent Change ------------------
                # 3 minutes timeout enforced
                df = future.result(timeout=180)
                # ---------------------------------------------------
                st.session_state.query_running = False
                st.session_state.query_future = None

                # Dynamic PII Decrypt
                df = decrypt_dataframe(df, session, table_name)
                st.dataframe(df)

                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button("Download CSV", csv, file_name=f"{report_name}.csv")

            except concurrent.futures.TimeoutError:
                st.session_state.query_running = False
                st.session_state.query_future = None
                st.error("⚠️ Query execution took too long (>3 minutes) and was cancelled. Please refine your filters.")

            except Exception as e:
                st.session_state.query_running = False
                st.session_state.query_future = None
                st.error(f"⚠️ An error occurred while running the query: {e}")