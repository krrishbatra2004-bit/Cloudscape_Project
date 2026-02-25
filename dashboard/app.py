import streamlit as st
import pandas as pd
import json
import plotly.express as px
import sys
import subprocess
from pathlib import Path
from datetime import datetime

# ==========================================
# BOOTSTRAP: MODULE PATH RESOLUTION
# ==========================================
root_path = Path(__file__).resolve().parent.parent
if str(root_path) not in sys.path:
    sys.path.append(str(root_path))

try:
    from core.config import settings
    from neo4j import GraphDatabase
except ImportError as e:
    st.error(f"Critical Module Error: {e}")
    st.stop()

# ==========================================
# BACKEND: SECURITY INTELLIGENCE ENGINE
# ==========================================
class SOCBackend:
    """Enterprise Security Interface for Neo4j Graph Analysis."""
    
    def __init__(self):
        try:
            self.driver = GraphDatabase.driver(
                settings.NEO4J_URI, 
                auth=(settings.NEO4J_USER, settings.NEO4J_PASS)
            )
        except Exception as e:
            st.error(f"Neo4j Connection Failed: {e}")

    def get_risk_metrics(self):
        """Calculates security KPIs directly from the Knowledge Graph."""
        metrics = {}
        with self.driver.session() as session:
            # 1. Public Exposure Count (Weak Point #1)
            pub_query = """
            MATCH (ip:IPRange {cidr: '0.0.0.0/0'})-[:ALLOWS_TRAFFIC_TO]->(sg:SecurityGroup)<-[:SECURED_BY]-(i:Instance)
            RETURN count(DISTINCT i) as count
            """
            metrics['exposed_instances'] = session.run(pub_query).single()['count']

            # 2. Total Asset Counts
            count_query = "MATCH (n) RETURN labels(n)[0] as type, count(n) as count"
            result = session.run(count_query)
            metrics['counts'] = {record["type"]: record["count"] for record in result}
            
            # 3. Lateral Movement Risk
            # Counts SGs that trust other SGs
            trust_query = "MATCH (s1:SecurityGroup)-[:ALLOWS_TRAFFIC_TO]->(s2:SecurityGroup) RETURN count(*) as count"
            metrics['trust_relationships'] = session.run(trust_query).single()['count']

        return metrics

    def get_attack_paths(self):
        """Discovers the top 5 most dangerous ingress-to-resource paths."""
        with self.driver.session() as session:
            query = """
            MATCH path = (ip:IPRange {cidr: '0.0.0.0/0'})-[:ALLOWS_TRAFFIC_TO]->(sg1:SecurityGroup)-[:ALLOWS_TRAFFIC_TO*0..1]->(sg2:SecurityGroup)<-[:SECURED_BY]-(target:Instance)
            RETURN 
                target.id as TargetID,
                target.private_ip as IP,
                nodes(path)[1].name as EntrySG,
                length(path) as RiskHops
            ORDER BY RiskHops DESC LIMIT 5
            """
            return pd.DataFrame([dict(record) for record in session.run(query)])

    def get_latest_audit(self):
        """Reads the high-fidelity forensic manifest from E: Drive."""
        latest_path = settings.MANIFEST_DIR / "aws_latest.json"
        if latest_path.exists():
            with open(latest_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None

    def close(self):
        self.driver.close()

# ==========================================
# FRONTEND: SOC DASHBOARD UI
# ==========================================
def run_soc_ui():
    st.set_page_config(page_title="Cloudscape | SOC", page_icon="🛡️", layout="wide")
    backend = SOCBackend()

    # --- SIDEBAR: SYSTEM STATUS ---
    st.sidebar.title("🛡️ SOC COMMAND")
    st.sidebar.markdown(f"**VPC Environment:** `Production` ")
    st.sidebar.markdown(f"**Vault Persistence:** `E:/Drive` ")
    st.sidebar.markdown("---")
    
    if st.sidebar.button("🚨 Run Forensic Re-Scan"):
        with st.spinner("Executing Security Pipeline..."):
            result = subprocess.run([sys.executable, str(root_path / "main.py")], capture_output=True, text=True)
            if result.returncode == 0:
                st.sidebar.success("Pipeline Sync Successful")
                st.rerun()
            else:
                st.sidebar.error("Pipeline Failure")

    # --- HEADER & KEY RISK INDICATORS ---
    st.title("Cloudscape Security Operations Center")
    st.caption(f"Real-time Blast Radius & Vulnerability Mapping | Region: {settings.AWS_REGION}")

    risk_data = backend.get_risk_metrics()
    
    m1, m2, m3, m4 = st.columns(4)
    # Highlight exposed instances in red if > 0
    m1.metric("Publicly Exposed Nodes", risk_data['exposed_instances'], 
              delta="High Risk" if risk_data['exposed_instances'] > 0 else "Secure",
              delta_color="inverse")
    m2.metric("Trust Paths", risk_data['trust_relationships'], help="SG-to-SG Lateral Movement Paths")
    m3.metric("IAM Identities", risk_data['counts'].get("IAMRole", 0))
    m4.metric("Isolated Segments", risk_data['counts'].get("Subnet", 0))

    st.markdown("---")

    # --- MAIN VIEW: VULNERABILITY & ANALYSIS ---
    col_graph, col_risk = st.columns([2, 1])

    with col_graph:
        st.subheader("🌐 Network Reachability Topology")
        st.info("Visualizing ingress paths from '0.0.0.0/0' to private compute nodes.")
        
        # Plotly chart showing asset distribution
        df_metrics = pd.DataFrame(list(risk_data['counts'].items()), columns=['Type', 'Count'])
        fig = px.bar(df_metrics, x='Type', y='Count', color='Type', 
                     title="Infrastructure Distribution by Node Type",
                     template="plotly_dark")
        st.plotly_chart(fig, use_container_width=True)

    with col_risk:
        st.subheader("🔥 Top Attack Paths")
        st.warning("Nodes below are reachable from the Public Internet via Security Group trust.")
        attack_df = backend.get_attack_paths()
        if not attack_df.empty:
            st.dataframe(attack_df, use_container_width=True, hide_index=True)
        else:
            st.success("No multi-hop attack paths detected.")

    st.markdown("---")

    # --- LOWER TABS: AUDIT & DATA ---
    tab_audit, tab_iam, tab_manifest = st.tabs(["📑 Security Audit", "🔑 Identity Analysis", "📄 Raw Manifest"])

    with tab_audit:
        st.subheader("VPC / Subnet Configuration")
        manifest = backend.get_latest_audit()
        if manifest:
            net_data = manifest.get('network', {})
            # VPC Table
            vpcs = pd.DataFrame(net_data.get('vpcs', []))[['VpcId', 'CidrBlock', 'State']] if net_data.get('vpcs') else pd.DataFrame()
            st.write("**Active VPCs**")
            st.table(vpcs)
            
            # SG Table
            sgs = pd.DataFrame(net_data.get('security_groups', []))[['GroupId', 'GroupName', 'Description']] if net_data.get('security_groups') else pd.DataFrame()
            st.write("**Firewall Groups (Security Groups)**")
            st.dataframe(sgs, use_container_width=True)

    with tab_iam:
        st.subheader("IAM Privilege Context")
        if manifest:
            roles = manifest.get('identity', {}).get('roles', [])
            st.write(f"Total Roles Found: {len(roles)}")
            st.json(roles)

    with tab_manifest:
        st.subheader("Immutable Forensic Log (E: Drive)")
        st.write(f"Source: `{settings.MANIFEST_DIR}/aws_latest.json`")
        st.json(manifest)

    backend.close()

if __name__ == "__main__":
    run_app = run_soc_ui()