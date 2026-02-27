import os
import streamlit as st
import pandas as pd
from neo4j import GraphDatabase
from streamlit_agraph import agraph, Node, Edge, Config

# ==============================================================================
# PROJECT CLOUDSCAPE 2026: ENTERPRISE SOC DASHBOARD
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. PAGE CONFIGURATION & INITIALIZATION
# ------------------------------------------------------------------------------
st.set_page_config(
    page_title="Cloudscape | Enterprise Mesh",
    page_icon="🕸️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for SOC Dark Mode aesthetic
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; }
    .css-1d391kg { padding-top: 1rem; }
    h1, h2, h3 { color: #00FF41; }
    .metric-card {
        background-color: #1E2329;
        border-radius: 5px;
        padding: 15px;
        border-left: 5px solid #00FF41;
    }
    .metric-card-danger { border-left: 5px solid #FF003C; }
    </style>
""", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# 2. NEO4J DATABASE DRIVER (CACHED)
# ------------------------------------------------------------------------------
@st.cache_resource
def get_database_driver():
    """Initializes and caches the Neo4j connection pool to prevent UI lag."""
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "Cloudscape2026!")
    
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        return driver
    except Exception as e:
        st.error(f"Failed to connect to Neo4j Graph Engine: {e}")
        st.stop()

driver = get_database_driver()

# ------------------------------------------------------------------------------
# 3. ADVANCED CYPHER QUERIES
# ------------------------------------------------------------------------------
@st.cache_data(ttl=60)
def fetch_global_metrics():
    """Fetches high-level metrics for the top KPI row."""
    query = """
    MATCH (t:Tenant)
    WITH count(t) as total_tenants
    MATCH (n) WHERE NOT n:Tenant
    WITH total_tenants, count(n) as total_assets
    MATCH ()-[r:CAN_ASSUME_ROLE]->() WHERE r.is_internal_mesh = true
    RETURN total_tenants, total_assets, count(r) as cross_account_trusts
    """
    with driver.session() as session:
        result = session.run(query).single()
        if result:
            return result.data()
        return {"total_tenants": 0, "total_assets": 0, "cross_account_trusts": 0}

@st.cache_data(ttl=60)
def fetch_cross_account_vulnerabilities():
    """Finds exact paths where an external entity can assume an internal IAM role."""
    query = """
    MATCH (source:Identity)-[r:CAN_ASSUME_ROLE]->(target:IAMRole)
    WHERE r.is_internal_mesh = true
    RETURN 
        source.arn AS Attacker_Origin, 
        r.source_project AS Source_Tenant,
        target.arn AS Compromised_Role,
        r.target_project AS Target_Tenant
    """
    with driver.session() as session:
        result = session.run(query)
        return pd.DataFrame([r.data() for r in result])

def fetch_graph_topology(selected_tenant):
    """Dynamically builds the visual nodes and edges based on UI filters."""
    nodes = []
    edges = []
    
    # Base query filters by tenant if one is selected
    match_clause = "MATCH (n)-[r]->(m)"
    where_clause = ""
    if selected_tenant != "GLOBAL MESH (All Tenants)":
        where_clause = f" WHERE (n.id = '{selected_tenant}' OR m.id = '{selected_tenant}' OR type(r) = 'BELONGS_TO')"
        
    query = f"{match_clause}{where_clause} RETURN n, r, m LIMIT 300"
    
    with driver.session() as session:
        results = session.run(query)
        
        # Track added IDs to prevent duplicate nodes in the visualizer
        added_node_ids = set()
        
        for record in results:
            n = record["n"]
            m = record["m"]
            r = record["r"]
            
            # Process Source Node
            n_id = str(n.element_id)
            if n_id not in added_node_ids:
                n_label = list(n.labels)[0] if n.labels else "Unknown"
                n_title = n.get("name") or n.get("arn") or n.get("id") or "Node"
                color = "#00FF41" if n_label == "Tenant" else "#0078D7" if n_label == "VPC" else "#F39C12"
                nodes.append(Node(id=n_id, label=n_title, size=25, color=color))
                added_node_ids.add(n_id)
                
            # Process Target Node
            m_id = str(m.element_id)
            if m_id not in added_node_ids:
                m_label = list(m.labels)[0] if m.labels else "Unknown"
                m_title = m.get("name") or m.get("arn") or m.get("id") or "Node"
                color = "#00FF41" if m_label == "Tenant" else "#0078D7" if m_label == "VPC" else "#F39C12"
                nodes.append(Node(id=m_id, label=m_title, size=25, color=color))
                added_node_ids.add(m_id)
                
            # Process Edge
            edge_color = "#FF003C" if type(r).__name__ == "CAN_ASSUME_ROLE" else "#FFFFFF"
            edges.append(Edge(source=n_id, target=m_id, label=type(r).__name__, color=edge_color))
            
    return nodes, edges

# ------------------------------------------------------------------------------
# 4. FRONTEND UI LAYOUT
# ------------------------------------------------------------------------------
st.title("🕸️ Cloudscape: Enterprise Graph Correlation")

# Sidebar Controls
st.sidebar.header("Command Center")
st.sidebar.markdown("Filter the graph topology by logical tenant boundaries.")

# Fetch active tenants for the dropdown
with driver.session() as session:
    tenant_records = session.run("MATCH (t:Tenant) RETURN t.id AS id").value()
tenant_options = ["GLOBAL MESH (All Tenants)"] + tenant_records
selected_tenant = st.sidebar.selectbox("Scope", tenant_options)

if st.sidebar.button("Force Refresh Data"):
    st.cache_data.clear()

# Global KPI Row
metrics = fetch_global_metrics()
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <h3>Active Tenants</h3>
        <h2>{metrics['total_tenants']}</h2>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <h3>Discovered Assets</h3>
        <h2>{metrics['total_assets']}</h2>
    </div>
    """, unsafe_allow_html=True)

with col3:
    # Highlight cross-account trusts as dangerous
    card_class = "metric-card-danger" if metrics['cross_account_trusts'] > 0 else "metric-card"
    st.markdown(f"""
    <div class="{card_class}">
        <h3>Cross-Account Trusts</h3>
        <h2>{metrics['cross_account_trusts']}</h2>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Main Content Tabs
tab1, tab2 = st.tabs(["Interactive Topology Graph", "Attack Path Forensics"])

with tab1:
    st.subheader(f"Mesh Visualization: {selected_tenant}")
    nodes, edges = fetch_graph_topology(selected_tenant)
    
    if nodes and edges:
        # AGraph Configuration for physics-based layout
        config = Config(
            width=1000,
            height=600,
            directed=True,
            physics=True,
            hierarchical=False,
            nodeHighlightBehavior=True,
            highlightColor="#FF003C",
            collapsible=True
        )
        agraph(nodes=nodes, edges=edges, config=config)
    else:
        st.info("No network data found. Please run the `python main.py --mode full` CLI command first.")

with tab2:
    st.subheader("🚨 Critical Identity Risks (Cross-Account)")
    st.markdown("These paths represent IAM trusts that cross logical project boundaries. If the Source Tenant is compromised, the Attacker can pivot directly into the Target Tenant.")
    
    vuln_df = fetch_cross_account_vulnerabilities()
    if not vuln_df.empty:
        st.dataframe(vuln_df, use_container_width=True)
    else:
        st.success("No cross-account vulnerabilities detected in the current mesh.")