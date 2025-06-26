# Advanced Workflows

Complex security assessment workflows using RedQuanta MCP for enterprise environments.

## Multi-Phase Reconnaissance

### Comprehensive Network Discovery

```bash
# Phase 1: Network Mapping
node dist/cli.js workflow_enum 10.0.0.0/8 \
  --scope network \
  --depth comprehensive \
  --output-format sarif \
  --report-file network-discovery.sarif

# Phase 2: Service Enumeration
node dist/cli.js masscan_scan 10.0.0.0/8 \
  --ports 1-65535 \
  --rate 1000 \
  --output-format json

# Phase 3: Detailed Service Analysis
node dist/cli.js nmap_scan 10.0.1.0/24 \
  --scan-type version \
  --scripts "default,vuln" \
  --timing 4
```

### Automated Workflow Chain
```javascript
// advanced-recon.js
const { RedQuantaMCP } = require('redquanta-mcp');

async function comprehensiveRecon(target) {
  const mcp = new RedQuantaMCP();
  
  // Phase 1: Quick Discovery
  const quickScan = await mcp.tools.nmap_scan({
    target: target,
    scanType: 'ping',
    timing: '5'
  });
  
  if (!quickScan.success) {
    throw new Error('Target unreachable');
  }
  
  // Phase 2: Port Discovery
  const portScan = await mcp.tools.masscan_scan({
    target: target,
    ports: '1-65535',
    rate: '5000'
  });
  
  // Phase 3: Service Enumeration
  const openPorts = extractPorts(portScan.data);
  const serviceScan = await mcp.tools.nmap_scan({
    target: target,
    ports: openPorts.join(','),
    scanType: 'version',
    scripts: 'default'
  });
  
  // Phase 4: Vulnerability Assessment
  const vulnScan = await mcp.tools.nmap_scan({
    target: target,
    ports: openPorts.join(','),
    scripts: 'vuln'
  });
  
  return {
    discovery: quickScan,
    ports: portScan,
    services: serviceScan,
    vulnerabilities: vulnScan
  };
}
```

## Web Application Security Assessment

### Complete Web App Testing Workflow

```bash
# Phase 1: Initial Discovery
node dist/cli.js ddg_search "site:target.com" \
  --max-results 100 \
  --output-format json

# Phase 2: Directory Discovery
node dist/cli.js ffuf_fuzz \
  --url "https://target.com/FUZZ" \
  --wordlist common-directories.txt \
  --extensions "php,html,js,json"

# Phase 3: Vulnerability Scanning
node dist/cli.js nikto_scan \
  --target "https://target.com" \
  --output-format json \
  --tuning x

# Phase 4: Custom Testing
curl -X POST http://localhost:5891/tools/workflow_scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://target.com",
    "scope": "web",
    "depth": "comprehensive",
    "include": ["sqli", "xss", "auth", "session"]
  }'
```

### Automated Web Assessment
```python
# web-assessment.py
import requests
import json
import time

class WebAssessment:
    def __init__(self, base_url="http://localhost:5891"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def comprehensive_scan(self, target_url):
        workflow = {
            "target": target_url,
            "phases": [
                self.discovery_phase(target_url),
                self.enumeration_phase(target_url),
                self.vulnerability_phase(target_url),
                self.exploitation_phase(target_url)
            ]
        }
        
        return self.execute_workflow(workflow)
    
    def discovery_phase(self, target):
        """Information gathering and reconnaissance"""
        tasks = [
            {
                "tool": "ddg_search",
                "params": {
                    "query": f"site:{target}",
                    "max_results": 50
                }
            },
            {
                "tool": "ffuf_fuzz", 
                "params": {
                    "url": f"{target}/FUZZ",
                    "wordlist": "common-dirs.txt",
                    "filter_codes": "404,403"
                }
            }
        ]
        return tasks
    
    def enumeration_phase(self, target):
        """Service and technology enumeration"""
        return [
            {
                "tool": "nikto_scan",
                "params": {
                    "target": target,
                    "tuning": "1,2,3,4,5,6,7,8,9,a,b,c"
                }
            }
        ]
    
    def vulnerability_phase(self, target):
        """Vulnerability identification"""
        return [
            {
                "tool": "workflow_scan",
                "params": {
                    "target": target,
                    "scope": "web",
                    "tests": ["injection", "auth", "session", "crypto"]
                }
            }
        ]
    
    def exploitation_phase(self, target):
        """Proof of concept development"""
        return [
            {
                "tool": "custom_exploit",
                "params": {
                    "target": target,
                    "payloads": "verified_vulns.json"
                }
            }
        ]
```

## Enterprise Infrastructure Assessment

### Large-Scale Network Assessment

```yaml
# enterprise-assessment.yml
assessment:
  name: "Enterprise Infrastructure Assessment"
  scope:
    - external_perimeter: "203.0.113.0/24"
    - internal_networks: 
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    - web_applications:
      - "*.company.com"
      - "*.company.net"
  
  phases:
    1_reconnaissance:
      duration: "2 days"
      activities:
        - osint_gathering
        - dns_enumeration
        - subdomain_discovery
        - network_mapping
    
    2_enumeration:
      duration: "3 days"
      activities:
        - port_scanning
        - service_identification
        - web_crawling
        - technology_fingerprinting
    
    3_vulnerability_assessment:
      duration: "5 days"
      activities:
        - automated_scanning
        - manual_testing
        - configuration_review
        - weak_authentication
    
    4_exploitation:
      duration: "3 days"
      activities:
        - proof_of_concept
        - privilege_escalation
        - lateral_movement
        - data_access_verification
    
    5_post_exploitation:
      duration: "2 days"
      activities:
        - persistence_testing
        - data_extraction_simulation
        - cleanup_operations
        - documentation
```

### Automated Enterprise Workflow
```typescript
// enterprise-workflow.ts
import { RedQuantaClient } from './redquanta-client';

interface AssessmentConfig {
  externalNetworks: string[];
  internalNetworks: string[];
  webApplications: string[];
  excludedHosts: string[];
  maxConcurrency: number;
}

class EnterpriseAssessment {
  private client: RedQuantaClient;
  private config: AssessmentConfig;
  
  constructor(config: AssessmentConfig) {
    this.client = new RedQuantaClient();
    this.config = config;
  }
  
  async runFullAssessment(): Promise<AssessmentReport> {
    const report = new AssessmentReport();
    
    // Phase 1: External Reconnaissance
    const externalRecon = await this.externalReconnaissance();
    report.addPhase('external_recon', externalRecon);
    
    // Phase 2: Internal Discovery
    const internalDiscovery = await this.internalNetworkDiscovery();
    report.addPhase('internal_discovery', internalDiscovery);
    
    // Phase 3: Service Enumeration
    const serviceEnum = await this.serviceEnumeration();
    report.addPhase('service_enumeration', serviceEnum);
    
    // Phase 4: Vulnerability Assessment
    const vulnAssessment = await this.vulnerabilityAssessment();
    report.addPhase('vulnerability_assessment', vulnAssessment);
    
    // Phase 5: Web Application Testing
    const webAppTesting = await this.webApplicationTesting();
    report.addPhase('web_application_testing', webAppTesting);
    
    return report.generate();
  }
  
  private async externalReconnaissance(): Promise<ReconResults> {
    const tasks = this.config.externalNetworks.map(network => ({
      tool: 'nmap_scan',
      params: {
        target: network,
        scanType: 'syn',
        timing: '4',
        ports: '80,443,22,21,25,53,110,995,993,143'
      }
    }));
    
    return await this.executeConcurrent(tasks);
  }
  
  private async internalNetworkDiscovery(): Promise<DiscoveryResults> {
    const results = [];
    
    for (const network of this.config.internalNetworks) {
      // Quick ping sweep
      const pingResults = await this.client.tools.nmap_scan({
        target: network,
        scanType: 'ping',
        timing: '5'
      });
      
      // Extract live hosts
      const liveHosts = this.extractLiveHosts(pingResults);
      
      // Detailed scanning of live hosts
      for (const host of liveHosts) {
        const hostScan = await this.client.tools.masscan_scan({
          target: host,
          ports: '1-65535',
          rate: '1000'
        });
        
        results.push(hostScan);
      }
    }
    
    return results;
  }
  
  private async serviceEnumeration(): Promise<ServiceResults> {
    // Implementation for service enumeration
    return new ServiceResults();
  }
  
  private async vulnerabilityAssessment(): Promise<VulnResults> {
    // Implementation for vulnerability assessment
    return new VulnResults();
  }
  
  private async webApplicationTesting(): Promise<WebAppResults> {
    const results = [];
    
    for (const app of this.config.webApplications) {
      // Directory discovery
      const dirScan = await this.client.tools.ffuf_fuzz({
        url: `${app}/FUZZ`,
        wordlist: 'common-directories.txt',
        extensions: 'php,html,js,asp,aspx'
      });
      
      // Nikto scan
      const niktoScan = await this.client.tools.nikto_scan({
        target: app
      });
      
      // Custom web tests
      const customTests = await this.client.tools.workflow_scan({
        target: app,
        scope: 'web',
        depth: 'comprehensive'
      });
      
      results.push({
        target: app,
        directory_scan: dirScan,
        nikto_scan: niktoScan,
        custom_tests: customTests
      });
    }
    
    return new WebAppResults(results);
  }
}
```

## Continuous Security Monitoring

### Automated Vulnerability Detection

```bash
#!/bin/bash
# continuous-monitoring.sh

TARGETS_FILE="targets.txt"
REPORT_DIR="reports/$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

while IFS= read -r target; do
    echo "Scanning $target..."
    
    # Quick vulnerability scan
    node dist/cli.js workflow_scan "$target" \
        --scope network \
        --depth light \
        --output-format sarif \
        --report-file "$REPORT_DIR/$target-scan.sarif"
    
    # Check for new vulnerabilities
    if [ -f "baseline/$target-baseline.sarif" ]; then
        node scripts/compare-results.js \
            "baseline/$target-baseline.sarif" \
            "$REPORT_DIR/$target-scan.sarif" \
            > "$REPORT_DIR/$target-delta.json"
    fi
    
done < "$TARGETS_FILE"

# Generate consolidated report
node scripts/generate-summary.js "$REPORT_DIR" \
    > "$REPORT_DIR/summary-report.html"

# Send alerts for critical findings
node scripts/send-alerts.js "$REPORT_DIR/summary-report.html"
```

### Integration with Security Tools

```python
# security-integration.py
import asyncio
from typing import List, Dict
import json

class SecurityIntegration:
    def __init__(self):
        self.integrations = {
            'splunk': SplunkIntegration(),
            'sentinel': SentinelIntegration(),
            'qradar': QRadarIntegration(),
            'elastic': ElasticIntegration()
        }
    
    async def distribute_findings(self, findings: List[Dict]):
        """Distribute findings to all integrated security tools"""
        tasks = []
        
        for name, integration in self.integrations.items():
            task = asyncio.create_task(
                integration.send_findings(findings),
                name=f"send_to_{name}"
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            name: result for name, result in zip(
                self.integrations.keys(), results
            )
        }
    
    async def correlate_with_existing(self, new_findings: List[Dict]):
        """Correlate new findings with existing security events"""
        correlation_results = {}
        
        for name, integration in self.integrations.items():
            existing_events = await integration.query_recent_events()
            correlations = self.find_correlations(new_findings, existing_events)
            correlation_results[name] = correlations
        
        return correlation_results

class SplunkIntegration:
    async def send_findings(self, findings: List[Dict]):
        # Implementation for Splunk integration
        pass
    
    async def query_recent_events(self):
        # Query Splunk for recent security events
        pass
```

## Red Team Simulation

### Advanced Persistent Threat Simulation

```yaml
# apt-simulation.yml
simulation:
  name: "APT29 Simulation"
  duration: "2 weeks"
  
  phases:
    initial_compromise:
      techniques:
        - spear_phishing_attachment
        - watering_hole_attacks
        - supply_chain_compromise
      tools:
        - custom_malware
        - legitimate_tools
        - living_off_the_land
    
    persistence:
      techniques:
        - registry_run_keys
        - scheduled_tasks
        - service_installation
        - dll_hijacking
      validation:
        - reboot_survival
        - user_logout_survival
        - av_evasion
    
    privilege_escalation:
      techniques:
        - token_impersonation
        - process_injection
        - kernel_exploits
        - weak_service_permissions
      targets:
        - local_admin
        - domain_admin
        - enterprise_admin
    
    defense_evasion:
      techniques:
        - process_hollowing
        - reflective_dll_loading
        - anti_analysis
        - timestomp
      validations:
        - av_bypass
        - edr_bypass
        - siem_evasion
    
    credential_access:
      techniques:
        - lsass_dumping
        - dcsync
        - kerberoasting
        - password_spraying
      tools:
        - mimikatz
        - bloodhound
        - rubeus
        - crackmapexec
    
    lateral_movement:
      techniques:
        - wmi_execution
        - powershell_remoting
        - rdp_hijacking
        - dcom_execution
      targets:
        - domain_controllers
        - file_servers
        - database_servers
        - backup_systems
    
    collection:
      data_types:
        - financial_data
        - customer_information
        - intellectual_property
        - email_archives
      techniques:
        - file_enumeration
        - email_collection
        - screenshot_capture
        - keylogging
    
    exfiltration:
      channels:
        - dns_tunneling
        - https_c2
        - cloud_storage
        - removable_media
      techniques:
        - data_compression
        - data_encryption
        - steganography
        - legitimate_services
```

### Automated Red Team Framework
```python
# red-team-framework.py
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class RedTeamFramework:
    def __init__(self, config: Dict):
        self.config = config
        self.logger = self.setup_logging()
        self.active_sessions = {}
        
    async def execute_campaign(self, campaign_config: Dict) -> Dict:
        """Execute a complete red team campaign"""
        campaign_id = self.generate_campaign_id()
        
        try:
            # Phase 1: Initial Compromise
            initial_access = await self.initial_compromise(campaign_config)
            
            if not initial_access['success']:
                return {'status': 'failed', 'phase': 'initial_compromise'}
            
            # Phase 2: Establish Persistence
            persistence = await self.establish_persistence(initial_access)
            
            # Phase 3: Escalate Privileges
            privilege_escalation = await self.escalate_privileges(persistence)
            
            # Phase 4: Move Laterally
            lateral_movement = await self.lateral_movement(privilege_escalation)
            
            # Phase 5: Collect Data
            data_collection = await self.collect_data(lateral_movement)
            
            # Phase 6: Exfiltrate Data (Simulated)
            exfiltration = await self.simulate_exfiltration(data_collection)
            
            return {
                'campaign_id': campaign_id,
                'status': 'completed',
                'phases': {
                    'initial_access': initial_access,
                    'persistence': persistence,
                    'privilege_escalation': privilege_escalation,
                    'lateral_movement': lateral_movement,
                    'data_collection': data_collection,
                    'exfiltration': exfiltration
                }
            }
            
        except Exception as e:
            self.logger.error(f"Campaign {campaign_id} failed: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    async def initial_compromise(self, config: Dict) -> Dict:
        """Simulate initial compromise techniques"""
        techniques = [
            self.spear_phishing_simulation,
            self.web_application_exploit,
            self.vulnerable_service_exploitation
        ]
        
        for technique in techniques:
            result = await technique(config)
            if result['success']:
                return result
        
        return {'success': False, 'message': 'All initial compromise techniques failed'}
```

## Compliance and Reporting

### Automated Compliance Checking

```bash
# compliance-check.sh
#!/bin/bash

# PCI DSS Compliance Check
echo "=== PCI DSS Compliance Assessment ==="
node dist/cli.js workflow_scan payment.company.com \
    --compliance pci-dss \
    --output-format sarif \
    --report-file reports/pci-compliance.sarif

# OWASP Top 10 Assessment
echo "=== OWASP Top 10 Assessment ==="
node dist/cli.js workflow_scan app.company.com \
    --tests owasp-top10 \
    --depth comprehensive \
    --output-format json

# Infrastructure Security Baseline
echo "=== Infrastructure Security Baseline ==="
node dist/cli.js workflow_enum internal-network \
    --scope infrastructure \
    --baseline cis-controls \
    --report-file reports/infrastructure-baseline.sarif
```

### Executive Reporting

```typescript
// executive-reporting.ts
interface ExecutiveReport {
  executiveSummary: string;
  riskAssessment: RiskMatrix;
  keyFindings: Finding[];
  recommendations: Recommendation[];
  complianceStatus: ComplianceStatus;
  costBenefitAnalysis: CostBenefit;
}

class ExecutiveReportGenerator {
  generateReport(findings: Finding[]): ExecutiveReport {
    return {
      executiveSummary: this.generateExecutiveSummary(findings),
      riskAssessment: this.calculateRiskMatrix(findings),
      keyFindings: this.identifyKeyFindings(findings),
      recommendations: this.generateRecommendations(findings),
      complianceStatus: this.assessCompliance(findings),
      costBenefitAnalysis: this.calculateCostBenefit(findings)
    };
  }
  
  private generateExecutiveSummary(findings: Finding[]): string {
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    
    return `
    Security Assessment Summary:
    - ${findings.length} total findings identified
    - ${criticalCount} critical vulnerabilities requiring immediate attention
    - ${highCount} high-severity issues requiring prompt remediation
    - Overall security posture: ${this.calculateSecurityPosture(findings)}
    `;
  }
}
```

## Next Steps

- [Common Workflows](common-workflows.md)
- [Enterprise Setup](../tutorials/enterprise-setup.md)
- [Plugin Development](../development/plugin-development.md)