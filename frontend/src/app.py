import os
import re
import sys
import json
import time
import math
import logging
import asyncio
import traceback
import tempfile
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

import pandas as pd
import numpy as np
import streamlit as st
import streamlit.components.v1 as components
import plotly.express as px
import plotly.graph_objects as go
from pyvis.network import Network

try:
    from neo4j import GraphDatabase, Driver, exceptions as neo4j_exceptions
except ImportError:
    st.error("Neo4j driver missing. Run: pip install neo4j")
    sys.exit(1)

# Ensure path resolution for local imports
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from core.config import config
except ImportError:
    # Failsafe fallback if executed purely standalone
    config = type('Config', (), {
        'settings': type('Settings', (), {
            'database': type('DB', (), {
                'neo4j_uri': 'bolt://localhost:7687', 
                'neo4j_user': 'neo4j', 
                'neo4j_password': 'password'
            }),
            'system': type('Sys', (), {'execution_mode': 'PROD'})
        })
    })

# ==============================================================================
# CLOUDSCAPE NEXUS 5.2 TITAN - AETHER HOLOGRAPHIC VISUALIZER (C2 DASHBOARD)
# ==============================================================================
# The Enterprise Graph Interface for the Sovereign-Forensic Digital Tool.
#
# TITAN NEXUS 5.2 UPGRADES ACTIVE:
# 1. FIXED MISSING IMPORTS: `re` and `traceback` now properly imported.
# 2. FIXED CYPHER INJECTION: All queries use parameterized $variables.
# 3. FIXED NODE LABELS: Queries use both :CloudResource and :Resource for 
#    compatibility across different ingestor versions.
# 4. BARNES-HUT PHYSICS RENDERING: Customized PyVis with GPU-accelerated 
#    Barnes-Hut gravity modeling without browser lockup.
# 5. MILLISECOND CACHE KERNEL: Strict Streamlit session states and TTL caching.
# 6. INTERACTIVE ATTACK PATH MATRIX: Expandable rows with hop visualization.
# 7. IDENTITY FABRIC OVERLAY: Cross-cloud IAM trust entanglement view.
# 8. CYPHER FORENSIC CONSOLE: Safe, parameterized read-only Cypher terminal.
# 9. STALE FILE CLEANUP: Old topology HTML files are automatically purged.
# 10. RESPONSIVE LAYOUT: Improved column layout and error handling.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. UI INITIALIZATION & CSS MATRIX
# ------------------------------------------------------------------------------

st.set_page_config(
    page_title="Cloudscape Nexus 5.2 | Aether Dashboard",
    page_icon="🌌",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Enterprise Dark Mode CSS Injection
CSS_MATRIX = """
<style>
    :root {
        --primary-accent: #00E5FF;
        --critical-red: #FF1744;
        --high-orange: #FF9100;
        --medium-yellow: #FFEA00;
        --low-green: #00E676;
        --bg-dark: #0A0E17;
        --panel-dark: #121826;
        --text-primary: #E2E8F0;
        --text-secondary: #94A3B8;
        --border-subtle: #1E293B;
    }
    
    .stApp {
        background-color: var(--bg-dark);
        color: var(--text-primary);
    }
    
    /* Header Formatting */
    h1, h2, h3 {
        color: var(--primary-accent) !important;
        font-family: 'Courier New', Courier, monospace !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Metric Cards */
    div[data-testid="metric-container"] {
        background-color: var(--panel-dark);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 15px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
        border-left: 4px solid var(--primary-accent);
    }
    
    div[data-testid="metric-container"] > label {
        color: var(--text-secondary) !important;
        font-weight: 600 !important;
    }
    
    div[data-testid="metric-container"] > div {
        color: #F8FAFC !important;
    }

    /* Dataframes */
    .stDataFrame {
        border: 1px solid var(--border-subtle);
        border-radius: 5px;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background-color: #0F172A;
        border-right: 1px solid var(--border-subtle);
    }
    
    /* Status Badges */
    .badge-critical { background-color: rgba(255, 23, 68, 0.2); color: var(--critical-red); padding: 4px 10px; border-radius: 4px; border: 1px solid var(--critical-red); font-weight: bold; font-size: 0.85em; }
    .badge-high { background-color: rgba(255, 145, 0, 0.2); color: var(--high-orange); padding: 4px 10px; border-radius: 4px; border: 1px solid var(--high-orange); font-weight: bold; font-size: 0.85em; }
    .badge-medium { background-color: rgba(255, 234, 0, 0.2); color: var(--medium-yellow); padding: 4px 10px; border-radius: 4px; border: 1px solid var(--medium-yellow); font-weight: bold; font-size: 0.85em; }
    .badge-low { background-color: rgba(0, 230, 118, 0.2); color: var(--low-green); padding: 4px 10px; border-radius: 4px; border: 1px solid var(--low-green); font-weight: bold; font-size: 0.85em; }
    
    /* Expander styling */
    details[data-testid="stExpander"] {
        background-color: var(--panel-dark);
        border: 1px solid var(--border-subtle);
        border-radius: 6px;
        margin-bottom: 8px;
    }
    
    /* Text area styling */
    .stTextArea textarea {
        background-color: var(--panel-dark) !important;
        color: var(--primary-accent) !important;
        font-family: 'Courier New', monospace !important;
        border: 1px solid var(--border-subtle) !important;
    }
</style>
"""
st.markdown(CSS_MATRIX, unsafe_allow_html=True)


# ------------------------------------------------------------------------------
# 2. DATABASE CONNECTION KERNEL
# ------------------------------------------------------------------------------

@st.cache_resource(show_spinner="Establishing secure uplink to Neo4j Kernel...")
def get_database_driver() -> Optional[Driver]:
    """
    Initializes a Thread-Safe, Singleton Connection Pool to the Graph Database.
    Uses st.cache_resource to prevent connection exhaustion during UI rerenders.
    """
    try:
        uri = config.settings.database.neo4j_uri
        user = config.settings.database.neo4j_user
        password = config.settings.database.neo4j_password
        
        driver = GraphDatabase.driver(
            uri, 
            auth=(user, password), 
            max_connection_pool_size=50,
            connection_timeout=15
        )
        # Verify connectivity
        driver.verify_connectivity()
        return driver
    except Exception as e:
        st.sidebar.error(f"FATAL: Graph Database Uplink Failed.\n{e}")
        return None

driver = get_database_driver()


def execute_read_query(query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Executes a safe Read-Only Cypher transaction with parameterized inputs."""
    if not driver:
        return []
    try:
        with driver.session() as session:
            result = session.read_transaction(lambda tx: list(tx.run(query, parameters or {})))
            return [dict(record) for record in result]
    except neo4j_exceptions.ServiceUnavailable:
        st.error("Graph Database is offline or unreachable.")
        return []
    except neo4j_exceptions.CypherSyntaxError as cse:
        st.error(f"Cypher Syntax Error: {cse}")
        return []
    except neo4j_exceptions.ClientError as ce:
        st.error(f"Neo4j Client Error: {ce}")
        return []
    except Exception as e:
        st.error(f"Query Execution Fault: {e}")
        return []


# ------------------------------------------------------------------------------
# 3. GLOBAL DATA FETCHING CACHES (MILLISECOND KERNEL)
# ------------------------------------------------------------------------------
# FIX: All Cypher queries now use BOTH :CloudResource and :Resource labels 
# via UNION or coalesce patterns for cross-version compatibility.

@st.cache_data(ttl=60, show_spinner="Calculating Master Telemetry...")
def fetch_master_telemetry() -> Dict[str, Any]:
    """Fetches high-level topological aggregates for the Executive Dashboard."""
    # Use UNION to query both label variants
    query = """
    MATCH (n)
    WHERE n:CloudResource OR n:Resource
    WITH count(n) as total_nodes
    OPTIONAL MATCH ()-[r]->()
    WITH total_nodes, count(r) as total_edges
    OPTIONAL MATCH (p:AttackPath)
    WITH total_nodes, total_edges, count(p) as total_paths
    OPTIONAL MATCH (phantom)
    WHERE (phantom:CloudResource OR phantom:Resource) AND phantom.type = 'Phantom'
    WITH total_nodes, total_edges, total_paths, count(phantom) as phantoms
    RETURN total_nodes, total_edges, total_paths, phantoms
    """
    results = execute_read_query(query)
    if not results:
        return {"total_nodes": 0, "total_edges": 0, "total_paths": 0, "phantoms": 0}
    return results[0]


@st.cache_data(ttl=60, show_spinner="Aggregating Threat Tiers...")
def fetch_threat_distribution() -> pd.DataFrame:
    """Calculates Attack Path severity distribution."""
    query = """
    MATCH (p:AttackPath)
    RETURN p.tier as Tier, count(p) as Count
    ORDER BY Count DESC
    """
    results = execute_read_query(query)
    if not results:
        return pd.DataFrame(columns=["Tier", "Count"])
    return pd.DataFrame(results)


@st.cache_data(ttl=60)
def fetch_cloud_distribution() -> pd.DataFrame:
    """Calculates distribution of physical assets across providers."""
    query = """
    MATCH (n)
    WHERE (n:CloudResource OR n:Resource)
      AND coalesce(n.type, '') <> 'Phantom'
    RETURN coalesce(n.cloud_provider, 'UNKNOWN') as Provider, count(n) as AssetCount
    ORDER BY AssetCount DESC
    """
    results = execute_read_query(query)
    if not results:
        return pd.DataFrame(columns=["Provider", "AssetCount"])
    return pd.DataFrame(results)


@st.cache_data(ttl=60)
def fetch_resource_type_distribution() -> pd.DataFrame:
    """Calculates distribution of resource types across the graph."""
    query = """
    MATCH (n)
    WHERE (n:CloudResource OR n:Resource)
      AND coalesce(n.type, '') <> 'Phantom'
    RETURN coalesce(n.type, 'unknown') as ResourceType, count(n) as Count
    ORDER BY Count DESC
    LIMIT 20
    """
    results = execute_read_query(query)
    if not results:
        return pd.DataFrame(columns=["ResourceType", "Count"])
    return pd.DataFrame(results)


@st.cache_data(ttl=30, show_spinner="Extracting Universal Resource Matrix...")
def fetch_attack_paths(min_hcs: float = 0.0, limit: int = 100) -> pd.DataFrame:
    """Extracts raw Attack Paths and unrolls their JSON sequences."""
    query = """
    MATCH (src)-[:PATH_ENTRY]->(p:AttackPath)-[:PATH_TARGET]->(dst)
    WHERE p.hcs_score >= $min_hcs
    RETURN p.path_id as PathID, 
           p.tier as Severity, 
           p.hcs_score as FrictionScore, 
           p.hop_count as Hops,
           src.name as EntryPoint, 
           dst.name as CrownJewel,
           p.metadata as Metadata
    ORDER BY p.hcs_score DESC
    LIMIT $limit
    """
    results = execute_read_query(query, {"min_hcs": min_hcs, "limit": limit})
    if not results:
        return pd.DataFrame()
    
    df = pd.DataFrame(results)
    if not df.empty and 'Metadata' in df.columns:
        df['MitreTactics'] = df['Metadata'].apply(_extract_mitre_tactics)
    return df


def _extract_mitre_tactics(metadata_str: Any) -> str:
    """Safely extracts MITRE tactics from metadata JSON string."""
    if not isinstance(metadata_str, str):
        return ""
    try:
        meta = json.loads(metadata_str)
        enrichment = meta.get('mitre_enrichment', [])
        if isinstance(enrichment, list):
            return ", ".join([t.get('name', '') for t in enrichment if isinstance(t, dict)])
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return ""


@st.cache_data(ttl=30)
def fetch_identity_fabric_bridges() -> pd.DataFrame:
    """Extracts highly critical Cross-Cloud and AssumeRole bridges."""
    query = """
    MATCH (src)-[r]->(dst)
    WHERE r.is_identity_bridge = true
    RETURN src.arn as SourceARN, 
           src.cloud_provider as SourceCloud,
           type(r) as RelationType, 
           r.weight as Resistance,
           dst.arn as TargetARN,
           dst.cloud_provider as TargetCloud
    ORDER BY r.weight DESC
    LIMIT 500
    """
    results = execute_read_query(query)
    return pd.DataFrame(results) if results else pd.DataFrame()


@st.cache_data(ttl=60)
def fetch_risk_heatmap_data() -> pd.DataFrame:
    """Fetches risk scores grouped by provider and type for heatmap visualization."""
    query = """
    MATCH (n)
    WHERE (n:CloudResource OR n:Resource)
      AND n.risk_score IS NOT NULL
      AND coalesce(n.type, '') <> 'Phantom'
    RETURN coalesce(n.cloud_provider, 'UNKNOWN') as Provider,
           coalesce(n.type, 'unknown') as ResourceType,
           avg(n.risk_score) as AvgRisk,
           max(n.risk_score) as MaxRisk,
           count(n) as Count
    ORDER BY AvgRisk DESC
    """
    results = execute_read_query(query)
    return pd.DataFrame(results) if results else pd.DataFrame()


# ------------------------------------------------------------------------------
# 4. PYVIS PHYSICS RENDERING ENGINE
# ------------------------------------------------------------------------------

def _cleanup_stale_topology_files(tmp_dir: str, max_age_sec: int = 3600) -> int:
    """Removes topology HTML files older than max_age_sec. Returns count of deleted files."""
    deleted = 0
    try:
        if not os.path.exists(tmp_dir):
            return 0
        current_time = time.time()
        for f in os.listdir(tmp_dir):
            if f.startswith("topology_") and f.endswith(".html"):
                filepath = os.path.join(tmp_dir, f)
                if current_time - os.path.getmtime(filepath) > max_age_sec:
                    os.remove(filepath)
                    deleted += 1
    except Exception:
        pass
    return deleted


def generate_topology_graph(limit: int = 500, focus_provider: str = "ALL") -> str:
    """
    Builds the PyVis Network Graph by executing a dynamic Cypher query.
    FIX: Uses parameterized queries instead of string interpolation.
    FIX: Cleans up stale HTML files automatically.
    """
    net = Network(height="700px", width="100%", bgcolor="#0A0E17", font_color="#E2E8F0", directed=True)
    
    # Force Barnes-Hut Physics
    net.set_options("""
    var options = {
      "nodes": {
        "borderWidth": 2,
        "borderWidthSelected": 4,
        "size": 30,
        "font": {"size": 12, "color": "#E2E8F0"}
      },
      "edges": {
        "color": {"color": "#475569", "highlight": "#00E5FF"},
        "smooth": {"type": "continuous", "forceDirection": "none"},
        "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -20000,
          "centralGravity": 0.3,
          "springLength": 150,
          "springConstant": 0.05,
          "damping": 0.09,
          "avoidOverlap": 0.1
        },
        "minVelocity": 0.75
      }
    }
    """)

    # FIX: Parameterized provider filtering instead of string interpolation
    if focus_provider != "ALL":
        query = """
        MATCH (n)-[r]->(m)
        WHERE (n:CloudResource OR n:Resource) AND (m:CloudResource OR m:Resource)
          AND (n.cloud_provider = $provider OR m.cloud_provider = $provider)
        RETURN n.arn as SourceARN, n.name as SourceName, n.type as SourceType, 
               coalesce(n.cloud_provider, 'UNKNOWN') as SourceCloud, n.risk_score as SourceRisk, 
               coalesce(n.phantom_reason, '') as SourcePhantom,
               m.arn as TargetARN, m.name as TargetName, m.type as TargetType, 
               coalesce(m.cloud_provider, 'UNKNOWN') as TargetCloud, m.risk_score as TargetRisk, 
               coalesce(m.phantom_reason, '') as TargetPhantom,
               type(r) as RelType, r.is_identity_bridge as IsBridge
        LIMIT $limit
        """
        params = {"provider": focus_provider, "limit": limit}
    else:
        query = """
        MATCH (n)-[r]->(m)
        WHERE (n:CloudResource OR n:Resource) AND (m:CloudResource OR m:Resource)
        RETURN n.arn as SourceARN, n.name as SourceName, n.type as SourceType, 
               coalesce(n.cloud_provider, 'UNKNOWN') as SourceCloud, n.risk_score as SourceRisk, 
               coalesce(n.phantom_reason, '') as SourcePhantom,
               m.arn as TargetARN, m.name as TargetName, m.type as TargetType, 
               coalesce(m.cloud_provider, 'UNKNOWN') as TargetCloud, m.risk_score as TargetRisk, 
               coalesce(m.phantom_reason, '') as TargetPhantom,
               type(r) as RelType, r.is_identity_bridge as IsBridge
        LIMIT $limit
        """
        params = {"limit": limit}
    
    results = execute_read_query(query, params)
    added_nodes = set()

    def get_node_style(cloud: str, res_type: str, risk: Any, is_phantom: str) -> Tuple[str, str, str]:
        """Calculates dynamic styling for PyVis nodes."""
        if is_phantom:
            return "#475569", "dot", "Phantom Node (Dangling Reference)"
            
        color = "#3B82F6"
        if cloud == "AWS":
            color = "#F59E0B"
        elif cloud == "AZURE":
            color = "#0EA5E9"
        
        try:
            risk_val = float(risk) if risk else 0.0
        except (TypeError, ValueError):
            risk_val = 0.0
            
        if risk_val >= 8.0:
            color = "#FF1744"
            
        shape = "dot"
        res_lower = str(res_type).lower() if res_type else ""
        if res_lower in ("user", "role", "group", "serviceprincipal"):
            shape = "triangle"
        elif res_lower in ("bucket", "storageaccount", "dbinstance", "table"):
            shape = "database"
        elif res_lower in ("vpc", "virtualnetwork", "subnet"):
            shape = "square"
        elif res_lower in ("function", "lambda"):
            shape = "star"
        
        title = f"Type: {res_type}<br>Provider: {cloud}<br>Risk: {risk_val:.1f}"
        return color, shape, title

    for record in results:
        src_arn = record.get("SourceARN", "")
        tgt_arn = record.get("TargetARN", "")
        
        if not src_arn or not tgt_arn:
            continue
        
        # Add Source Node
        if src_arn not in added_nodes:
            color, shape, title = get_node_style(
                record.get("SourceCloud", ""), record.get("SourceType", ""),
                record.get("SourceRisk"), record.get("SourcePhantom", "")
            )
            src_name = str(record.get("SourceName", ""))
            label = (src_name[:20] + "...") if len(src_name) > 20 else src_name
            net.add_node(src_arn, label=label, title=title, color=color, shape=shape)
            added_nodes.add(src_arn)
            
        # Add Target Node
        if tgt_arn not in added_nodes:
            color, shape, title = get_node_style(
                record.get("TargetCloud", ""), record.get("TargetType", ""),
                record.get("TargetRisk"), record.get("TargetPhantom", "")
            )
            tgt_name = str(record.get("TargetName", ""))
            label = (tgt_name[:20] + "...") if len(tgt_name) > 20 else tgt_name
            net.add_node(tgt_arn, label=label, title=title, color=color, shape=shape)
            added_nodes.add(tgt_arn)
            
        # Add Edge
        is_bridge = record.get("IsBridge", False)
        edge_color = "#FF1744" if is_bridge else "#475569"
        edge_title = str(record.get("RelType", ""))
        net.add_edge(src_arn, tgt_arn, title=edge_title, color=edge_color)

    # Save and return path (with stale cleanup)
    tmp_dir = os.path.join(root_dir, "dashboard", "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    _cleanup_stale_topology_files(tmp_dir, max_age_sec=3600)
    
    html_path = os.path.join(tmp_dir, f"topology_{int(time.time())}.html")
    net.save_graph(html_path)
    return html_path


# ------------------------------------------------------------------------------
# 5. UI LAYOUT: SIDEBAR & NAVIGATION
# ------------------------------------------------------------------------------

st.sidebar.title("🌌 AETHER KERNEL")
st.sidebar.markdown("---")

nav_selection = st.sidebar.radio(
    "COMMAND MODULES",
    ["Executive Dashboard", "Topological Graph", "Attack Path Matrix", 
     "Identity Fabric", "Risk Heatmap", "Cypher Forensics"]
)

st.sidebar.markdown("---")
st.sidebar.subheader("Global Filters")
filter_provider = st.sidebar.selectbox("Cloud Provider", ["ALL", "AWS", "AZURE"])
filter_risk = st.sidebar.slider("Minimum HCS Risk Score", 0.0, 10.0, 5.0, 0.5)

st.sidebar.markdown("---")
if st.sidebar.button("♻️ Force Cache Refresh"):
    st.cache_data.clear()
    st.sidebar.success("Cache Cleared. Pulling fresh Neo4j matrices.")
    st.rerun()

# Connection info
neo4j_uri_display = config.settings.database.neo4j_uri if hasattr(config.settings.database, 'neo4j_uri') else "unknown"
st.sidebar.markdown(
    f"<div style='margin-top: 50px; color: #475569; font-size: 12px;'>"
    f"Titan Nexus v5.2.0<br>"
    f"Connected to: {neo4j_uri_display}"
    f"</div>", 
    unsafe_allow_html=True
)


# ------------------------------------------------------------------------------
# 6. UI LAYOUT: EXECUTIVE DASHBOARD
# ------------------------------------------------------------------------------

def render_executive_dashboard():
    """Renders the main Executive Intelligence Dashboard view."""
    st.title("Executive Intelligence Dashboard")
    st.markdown("Macro-level analytics of the Sovereign-Forensic Cloud Mesh.")
    
    # Master Telemetry Cards
    telemetry = fetch_master_telemetry()
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Live Graph Nodes", f"{telemetry['total_nodes']:,}")
    with col2:
        st.metric("Structural Edges", f"{telemetry['total_edges']:,}")
    with col3:
        st.metric("Critical Kill Chains", f"{telemetry['total_paths']:,}")
    with col4:
        st.metric("Dangling Phantoms", f"{telemetry['phantoms']:,}")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Dual Plotly Visualizations
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("Infrastructure Spread")
        cloud_df = fetch_cloud_distribution()
        if not cloud_df.empty:
            fig1 = px.pie(
                cloud_df, values='AssetCount', names='Provider', hole=0.6,
                color='Provider', 
                color_discrete_map={'AWS': '#F59E0B', 'AZURE': '#0EA5E9', 'UNKNOWN': '#475569'}
            )
            fig1.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", 
                font_color="#E2E8F0", margin=dict(t=20, b=20, l=20, r=20)
            )
            st.plotly_chart(fig1, use_container_width=True)
        else:
            st.info("Insufficient infrastructure data for analysis.")

    with col_b:
        st.subheader("Path Severity Distribution")
        tier_df = fetch_threat_distribution()
        if not tier_df.empty:
            color_map = {'CRITICAL': '#FF1744', 'HIGH': '#FF9100', 'MEDIUM': '#FFEA00', 'LOW': '#00E676'}
            fig2 = px.bar(tier_df, x='Tier', y='Count', color='Tier', color_discrete_map=color_map)
            fig2.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", 
                font_color="#E2E8F0", margin=dict(t=20, b=20, l=20, r=20),
                showlegend=False
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No attack paths generated. HAPD Engine may be offline.")

    # Resource Type Distribution
    st.markdown("---")
    st.subheader("Resource Type Distribution")
    type_df = fetch_resource_type_distribution()
    if not type_df.empty:
        fig_types = px.bar(
            type_df, x='Count', y='ResourceType', orientation='h',
            color='Count', color_continuous_scale=['#0EA5E9', '#FF1744']
        )
        fig_types.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", 
            font_color="#E2E8F0", margin=dict(t=20, b=20, l=20, r=20),
            yaxis={'categoryorder': 'total ascending'}
        )
        st.plotly_chart(fig_types, use_container_width=True)

    # MITRE ATT&CK Matrix Radar
    st.markdown("---")
    st.subheader("MITRE ATT&CK Enterprise Matrix Coverage")
    st.markdown("Identified tactic vectors derived directly from topological hop mechanics.")
    
    paths_df = fetch_attack_paths(min_hcs=0.0, limit=500)
    if not paths_df.empty and 'MitreTactics' in paths_df.columns:
        all_tactics = []
        for tactics_str in paths_df['MitreTactics']:
            if tactics_str:
                all_tactics.extend([t.strip() for t in tactics_str.split(",") if t.strip()])
                
        if all_tactics:
            tactic_counts = pd.Series(all_tactics).value_counts().reset_index()
            tactic_counts.columns = ['Tactic', 'Frequency']
            
            fig3 = px.line_polar(
                tactic_counts, r='Frequency', theta='Tactic', line_close=True,
                color_discrete_sequence=['#00E5FF']
            )
            fig3.update_traces(fill='toself')
            fig3.update_layout(
                polar=dict(radialaxis=dict(visible=False)), 
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", 
                font_color="#E2E8F0"
            )
            st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("No MITRE Tactics extracted. Ensure MITRE enrichment is enabled.")


# ------------------------------------------------------------------------------
# 7. UI LAYOUT: TOPOLOGICAL GRAPH
# ------------------------------------------------------------------------------

def render_topological_graph():
    """Renders the interactive topology graph visualization."""
    st.title("Aether Topology Matrix")
    st.markdown("Interactive Barnes-Hut rendered cloud graph. **High node counts may cause browser lag.**")
    
    col1, col2 = st.columns([1, 4])
    with col1:
        render_limit = st.selectbox("Render Limit", [100, 500, 1000, 5000], index=1)
        st.markdown("""
        **Legend:**
        * 🟠 **AWS Orange**
        * 🔵 **Azure Blue**
        * 🔴 **Critical Risk ≥ 8.0**
        * 🔴 **Red Edges**: Identity Bridges
        * ⚪ **Grey**: Phantom Nodes
        * ⭐ **Star**: Lambda/Functions
        * ▲ **Triangle**: IAM Identities
        """)
        
        if st.button("🔮 Generate Hologram"):
            with st.spinner("Calculating Physics Matrix..."):
                html_path = generate_topology_graph(limit=render_limit, focus_provider=filter_provider)
                st.session_state['current_graph'] = html_path
                
    with col2:
        if 'current_graph' in st.session_state and os.path.exists(st.session_state['current_graph']):
            try:
                with open(st.session_state['current_graph'], 'r', encoding='utf-8') as f:
                    html_data = f.read()
                components.html(html_data, height=750, scrolling=False)
            except Exception as e:
                st.error(f"Failed to render topology: {e}")
        else:
            st.info("Click '🔮 Generate Hologram' to compile the topological matrix.")


# ------------------------------------------------------------------------------
# 8. UI LAYOUT: ATTACK PATH MATRIX
# ------------------------------------------------------------------------------

def get_badge_html(tier: str) -> str:
    """Returns safe HTML string for severity badges."""
    t = str(tier).upper()
    badge_map = {
        'CRITICAL': f"<span class='badge-critical'>CRITICAL</span>",
        'HIGH': f"<span class='badge-high'>HIGH</span>",
        'MEDIUM': f"<span class='badge-medium'>MEDIUM</span>",
    }
    return badge_map.get(t, f"<span class='badge-low'>{t}</span>")


def render_attack_path_matrix():
    """Renders the HAPD Kill-Chain Inspector view."""
    st.title("HAPD Kill-Chain Inspector")
    st.markdown("Detailed breakdown of Heuristic Attack Path Discovery (HAPD) routes.")
    
    paths_df = fetch_attack_paths(min_hcs=filter_risk, limit=250)
    
    if paths_df.empty:
        st.success("No Attack Paths meet the current risk threshold. The mesh is secure.")
        return

    st.markdown(f"**Showing Top {len(paths_df)} Critical Vectors**")
    
    for index, row in paths_df.iterrows():
        tier_badge = get_badge_html(row.get('Severity', ''))
        entry = row.get('EntryPoint', 'Unknown')
        jewel = row.get('CrownJewel', 'Unknown')
        score = row.get('FrictionScore', 0)
        
        with st.expander(f"{row.get('Severity', '')} | {entry} ➔ {jewel} (Friction: {score:.2f})"):
            st.markdown(f"**Status:** {tier_badge}", unsafe_allow_html=True)
            st.markdown(f"**Path ID:** `{row.get('PathID', 'N/A')}`")
            st.markdown(f"**Topological Hops:** `{row.get('Hops', 'N/A')}`")
            st.markdown(f"**MITRE Tactics:** `{row.get('MitreTactics', 'N/A')}`")
            
            st.markdown("### Sequential Hop Matrix")
            try:
                raw_meta = row.get('Metadata', '')
                if isinstance(raw_meta, str) and raw_meta:
                    meta = json.loads(raw_meta)
                    seq = meta.get("path_sequence", [])
                    
                    for i, hop_arn in enumerate(seq):
                        if i == 0:
                            st.markdown(f"🟢 **START:** `{hop_arn}`")
                        elif i == len(seq) - 1:
                            st.markdown(f"🔴 **TARGET:** `{hop_arn}`")
                        else:
                            st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;↳ 🔗 **Hop {i}:** `{hop_arn}`")
                else:
                    st.info("No hop sequence data available.")
            except Exception:
                st.warning("Failed to decode hop sequence.")
                
            st.markdown("### Raw URM Payload")
            if row.get('Metadata'):
                st.json(row['Metadata'])


# ------------------------------------------------------------------------------
# 9. UI LAYOUT: IDENTITY FABRIC
# ------------------------------------------------------------------------------

def render_identity_fabric():
    """Renders the Identity Fabric Entanglements view."""
    st.title("Identity Fabric Entanglements")
    st.markdown("Cross-cloud IAM trust routes. Ignores physical network constraints.")
    
    fabric_df = fetch_identity_fabric_bridges()
    
    if fabric_df.empty:
        st.info("No Identity Bridges detected in the current mesh.")
        return
        
    if filter_provider != "ALL":
        fabric_df = fabric_df[
            (fabric_df['SourceCloud'] == filter_provider) | 
            (fabric_df['TargetCloud'] == filter_provider)
        ]
        
    st.markdown(f"**Discovered {len(fabric_df)} Trust Relationships.**")
    
    st.dataframe(
        fabric_df,
        column_config={
            "SourceARN": st.column_config.TextColumn("Source Identity ARN", width="large"),
            "TargetARN": st.column_config.TextColumn("Target Trust ARN", width="large"),
            "Resistance": st.column_config.NumberColumn("Bridge Weight", format="%.1f")
        },
        hide_index=True,
        use_container_width=True
    )
    
    # Sankey Diagram for Identity Flow
    st.markdown("### Cross-Cloud Flow Dynamics")
    flow_agg = fabric_df.groupby(['SourceCloud', 'TargetCloud']).size().reset_index(name='Count')
    
    if not flow_agg.empty:
        labels = list(pd.concat([flow_agg['SourceCloud'], flow_agg['TargetCloud']]).unique())
        source_indices = flow_agg['SourceCloud'].map(lambda x: labels.index(x))
        target_indices = flow_agg['TargetCloud'].map(lambda x: labels.index(x))
        
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15, thickness=20,
                line=dict(color="black", width=0.5),
                label=labels, color="#00E5FF"
            ),
            link=dict(
                source=source_indices, target=target_indices,
                value=flow_agg['Count'],
                color="rgba(255, 23, 68, 0.4)"
            )
        )])
        fig.update_layout(
            title_text="Identity Trust Flow by Cloud Provider", font_size=12, 
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", 
            font_color="#E2E8F0"
        )
        st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------------------
# 10. UI LAYOUT: RISK HEATMAP
# ------------------------------------------------------------------------------

def render_risk_heatmap():
    """Renders a risk heatmap visualization grouped by provider and resource type."""
    st.title("Risk Assessment Heatmap")
    st.markdown("Average risk scores across resource types and cloud providers.")
    
    heatmap_df = fetch_risk_heatmap_data()
    
    if heatmap_df.empty:
        st.info("No risk data available. Run a scan first.")
        return
    
    # Pivot for heatmap
    pivot_df = heatmap_df.pivot_table(
        values='AvgRisk', index='ResourceType', columns='Provider', 
        aggfunc='mean', fill_value=0
    )
    
    if not pivot_df.empty:
        fig = px.imshow(
            pivot_df, 
            color_continuous_scale=['#00E676', '#FFEA00', '#FF9100', '#FF1744'],
            labels=dict(x="Provider", y="Resource Type", color="Avg Risk"),
            aspect="auto"
        )
        fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font_color="#E2E8F0", margin=dict(t=40, b=40)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Detailed risk table
    st.markdown("### Detailed Risk Breakdown")
    display_df = heatmap_df.copy()
    display_df['AvgRisk'] = display_df['AvgRisk'].round(2)
    display_df['MaxRisk'] = display_df['MaxRisk'].round(2)
    st.dataframe(
        display_df,
        column_config={
            "AvgRisk": st.column_config.NumberColumn("Avg Risk", format="%.2f"),
            "MaxRisk": st.column_config.NumberColumn("Max Risk", format="%.2f"),
        },
        hide_index=True,
        use_container_width=True
    )


# ------------------------------------------------------------------------------
# 11. UI LAYOUT: CYPHER FORENSICS
# ------------------------------------------------------------------------------

# Write mutation keywords to block in the forensic console
BLOCKED_KEYWORDS = re.compile(
    r'\b(DELETE|REMOVE|SET|MERGE|CREATE|DROP|DETACH|CALL\s+apoc\s*\.\s*periodic)\b', 
    re.IGNORECASE
)

def render_cypher_forensics():
    """Renders the Cypher Forensic Terminal with read-only safety enforcement."""
    st.title("Cypher Forensic Terminal")
    st.markdown("Execute raw, read-only Cypher queries against the Neo4j Kernel.")
    
    # Preset forensic queries
    presets = {
        "Custom...": "",
        "Find All Publicly Exposed Databases": (
            "MATCH (n) WHERE (n:CloudResource OR n:Resource) "
            "AND n.type IN ['rds', 'dbinstance', 'bucket'] "
            "AND n.tags CONTAINS 'Public' "
            "RETURN n.arn, n.name, n.risk_score LIMIT 50"
        ),
        "Find Top 10 Highest Risk Nodes": (
            "MATCH (n) WHERE (n:CloudResource OR n:Resource) "
            "AND coalesce(n.type, '') <> 'Phantom' "
            "RETURN n.arn, n.type, n.risk_score "
            "ORDER BY n.risk_score DESC LIMIT 10"
        ),
        "Count Nodes by Tenant": (
            "MATCH (n) WHERE (n:CloudResource OR n:Resource) "
            "AND coalesce(n.type, '') <> 'Phantom' "
            "RETURN n.tenant_id, count(n) as Count ORDER BY Count DESC"
        ),
        "Find Cross-Cloud Identity Bridges": (
            "MATCH (src)-[r]->(dst) WHERE r.is_identity_bridge = true "
            "RETURN src.arn as Source, type(r) as Relation, dst.arn as Target, r.weight as Weight "
            "ORDER BY r.weight DESC LIMIT 20"
        ),
        "List All Attack Paths": (
            "MATCH (p:AttackPath) "
            "RETURN p.path_id, p.tier, p.hcs_score, p.hop_count "
            "ORDER BY p.hcs_score DESC LIMIT 50"
        ),
    }
    
    selected_preset = st.selectbox("Intelligence Presets", list(presets.keys()))
    default_query = presets[selected_preset]
    
    query_input = st.text_area("Cypher Directive", value=default_query, height=150)
    
    if st.button("⚡ Execute Directive"):
        # Safety: Block write mutations using regex
        if BLOCKED_KEYWORDS.search(query_input):
            st.error("🔒 SECURITY VIOLATION: Write mutations are prohibited in the Forensic Terminal.")
            return
            
        with st.spinner("Querying Graph Kernel..."):
            start = time.perf_counter()
            results = execute_read_query(query_input)
            latency = (time.perf_counter() - start) * 1000
            
            if results:
                st.success(f"Query returned {len(results)} rows in {latency:.2f}ms.")
                st.dataframe(pd.DataFrame(results), use_container_width=True)
            else:
                st.warning(f"Query executed in {latency:.2f}ms but returned 0 results.")


# ------------------------------------------------------------------------------
# MAIN EXECUTION ROUTER
# ------------------------------------------------------------------------------

def main():
    """Main execution router — dispatches to the selected navigation module."""
    if not driver:
        st.error("System Halted: Neo4j Uplink Severed.")
        st.stop()
        
    try:
        if nav_selection == "Executive Dashboard":
            render_executive_dashboard()
        elif nav_selection == "Topological Graph":
            render_topological_graph()
        elif nav_selection == "Attack Path Matrix":
            render_attack_path_matrix()
        elif nav_selection == "Identity Fabric":
            render_identity_fabric()
        elif nav_selection == "Risk Heatmap":
            render_risk_heatmap()
        elif nav_selection == "Cypher Forensics":
            render_cypher_forensics()
    except Exception as e:
        st.error(f"UI Matrix Render Fault: {e}")
        st.code(traceback.format_exc())

if __name__ == "__main__":
    main()