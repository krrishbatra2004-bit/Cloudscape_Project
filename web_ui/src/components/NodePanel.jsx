import useStore from '../stores/useStore';
import Button from '@cloudscape-design/components/button';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';

// =============================================================================
// HUMAN-FRIENDLY DESCRIPTIONS
// Written for people who are NOT cloud engineers.
// =============================================================================

const TYPE_DESCRIPTIONS = {
  // AWS resource types
  ec2:            "A virtual computer running in Amazon's cloud — like a remote PC that runs applications 24/7.",
  s3:             "A cloud storage locker — stores files, backups, and data (like a Dropbox in the cloud).",
  rds:            "A managed database — a digital filing cabinet that stores structured data (customer records, transactions, etc.).",
  iam:            "An identity & access rule — controls WHO can access WHAT in the cloud (like a security badge system).",
  lambda:         "A small piece of code that runs automatically when triggered — like a motion-sensor light that turns on by itself.",
  vpc:            "A virtual private network — an isolated section of the cloud, like a fenced-off area in a data center.",
  subnet:         "A subdivision inside a VPC — like rooms inside a building, each with its own rules.",
  sg:             "A security group — acts like a firewall, deciding which traffic is allowed in or out.",
  role:           "A permission set — a collection of allowed actions (like a key ring with specific keys).",
  policy:         "A permission document — the written rules that define what a role can do.",
  user:           "A cloud user account — a person or service that can sign into the cloud.",
  group:          "A user group — a team of users who share the same permissions.",
  bucket:         "Same as S3 — a storage container for files in the cloud.",
  instance:       "Same as EC2 — a virtual machine/computer.",
  // Azure resource types
  vm:             "A virtual machine in Microsoft Azure — a remote computer running apps in Microsoft's cloud.",
  "resource-group": "An Azure resource group — a folder that organizes related cloud resources together.",
  "storage-account": "An Azure storage account — a container for storing files, blobs, and data in Microsoft's cloud.",
  "app-service":  "An Azure web app host — runs websites and web applications in the cloud.",
  "sql-database": "An Azure SQL database — a managed database for structured data.",
  "key-vault":    "An Azure Key Vault — a secure safe for storing passwords, encryption keys, and certificates.",
  nsg:            "A network security group — Azure's version of a firewall that filters network traffic.",
  vnet:           "An Azure virtual network — an isolated private network, similar to AWS VPC.",
  // Generic / simulation types
  firewall:       "A network firewall — blocks unauthorized traffic from reaching your systems.",
  router:         "A network router — directs data traffic between different parts of the network.",
  loadbalancer:   "A load balancer — distributes incoming traffic across multiple servers so no single one gets overwhelmed.",
  dns:            "A DNS service — translates human-readable names (like google.com) into computer addresses.",
  container:      "A lightweight app package — bundles code with everything needed to run it (like a shipping container for software).",
  cluster:        "A cluster — a group of computers working together as one system for reliability and speed.",
  gateway:        "A network gateway — the entry/exit point connecting your private cloud network to the internet.",
  unknown:        "A cloud resource whose specific type couldn't be determined.",
};

const PROVIDER_DESCRIPTIONS = {
  aws:           "Amazon Web Services — the world's largest cloud provider",
  azure:         "Microsoft Azure — Microsoft's enterprise cloud platform",
  gcp:           "Google Cloud Platform — Google's cloud infrastructure",
  digitalocean:  "DigitalOcean — a developer-friendly cloud provider",
  unknown:       "Unknown cloud provider",
};

const RISK_DESCRIPTIONS = {
  critical: "CRITICAL — This resource has severe security issues and could be actively exploitable. Immediate attention required.",
  high:     "HIGH — This resource has significant security weaknesses that attackers could discover and exploit.",
  medium:   "MEDIUM — This resource has moderate security concerns. Should be reviewed and hardened.",
  low:      "LOW — This resource appears well-configured with minimal security risk.",
  safe:     "SAFE — No known security issues detected. This resource follows best practices.",
};

function getRiskLevel(score) {
  if (score > 90) return 'critical';
  if (score > 70) return 'high';
  if (score > 40) return 'medium';
  if (score > 10) return 'low';
  return 'safe';
}

function getRiskColor(score) {
  if (score > 80) return 'text-status-error';
  if (score > 50) return 'text-status-warning';
  return 'text-status-success';
}

export default function NodePanel() {
  const { selectedNode, setSelectedNode } = useStore();

  if (!selectedNode) return null;

  const handleClose = () => setSelectedNode(null);
  const nodeType = (selectedNode.type || 'unknown').toLowerCase();
  const provider = (selectedNode.provider || 'unknown').toLowerCase();
  const riskScore = selectedNode.riskScore || 0;
  const riskLevel = getRiskLevel(riskScore);

  return (
    <div className="node-panel">
      <SpaceBetween size="m">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box variant="h2" margin="none">Resource Details</Box>
          <Button variant="inline-icon" iconName="close" onClick={handleClose} />
        </div>

        {/* Name & Type */}
        <div>
          <Box variant="small" color="text-status-inactive">Name</Box>
          <Box variant="p" margin="none" fontSize="heading-m">
            {selectedNode.name || 'Unnamed Resource'}
          </Box>
        </div>

        <div>
          <Box variant="small" color="text-status-inactive">Type</Box>
          <Box variant="p" margin="none">
            <Badge color="blue">{nodeType.toUpperCase()}</Badge>
          </Box>
          <Box variant="small" color="text-body-secondary" margin={{ top: 'xxs' }}>
            {TYPE_DESCRIPTIONS[nodeType] || TYPE_DESCRIPTIONS['unknown']}
          </Box>
        </div>

        {/* Provider */}
        <div>
          <Box variant="small" color="text-status-inactive">Cloud Provider</Box>
          <Box variant="p" margin="none">
            <span style={{ textTransform: 'uppercase', fontWeight: 'bold' }}>
              {selectedNode.provider || 'N/A'}
            </span>
          </Box>
          <Box variant="small" color="text-body-secondary" margin={{ top: 'xxs' }}>
            {PROVIDER_DESCRIPTIONS[provider] || PROVIDER_DESCRIPTIONS['unknown']}
          </Box>
        </div>

        {/* Risk Score */}
        <div>
          <Box variant="small" color="text-status-inactive">Security Risk Score</Box>
          <Box variant="h1" color={getRiskColor(riskScore)} margin="none">
            {riskScore}/100
          </Box>
          <Box variant="small" color="text-body-secondary" margin={{ top: 'xxs' }}>
            {RISK_DESCRIPTIONS[riskLevel]}
          </Box>
        </div>

        {/* ID */}
        <div>
          <Box variant="small" color="text-status-inactive">Resource ID / ARN</Box>
          <Box variant="code" margin="none" fontSize="body-s">
            {selectedNode.id}
          </Box>
          <Box variant="small" color="text-body-secondary" margin={{ top: 'xxs' }}>
            This is the unique identifier used to locate this resource in the cloud.
          </Box>
        </div>

        {/* Permissions */}
        {selectedNode.permissions && selectedNode.permissions.length > 0 && (
          <div>
            <Box variant="small" color="text-status-inactive">Permissions Detected</Box>
            <ul style={{ margin: 0, paddingLeft: '20px' }}>
              {selectedNode.permissions.map(p => <li key={p}>{p}</li>)}
            </ul>
            <Box variant="small" color="text-body-secondary" margin={{ top: 'xxs' }}>
              These are the actions this resource is allowed to perform — too many permissions can be a security risk.
            </Box>
          </div>
        )}

      </SpaceBetween>
    </div>
  );
}
