"""Built-in library of declarative network exposure rules."""

from reconforge.assessment.models import ExposureRuleDefinition, RuleCondition
from reconforge.core.enums import FindingCategory, FindingState, SeverityLevel

BUILTIN_RULES: list[ExposureRuleDefinition] = [
    ExposureRuleDefinition(
        id="EXP-CLEARTEXT-TELNET",
        name="Cleartext Telnet Service Exposed",
        description=(
            "Unencrypted Telnet remote terminal service detected. Telnet transmits all session data, "
            "including authentication credentials, commands, and responses, in plain text without encryption."
        ),
        severity=SeverityLevel.HIGH,
        category=FindingCategory.CLEARTEXT_PROTOCOL,
        default_state=FindingState.CONFIRMED,
        conditions=RuleCondition(
            ports=[23],
            service_names=["telnet"],
            require_all=False,
        ),
        remediation=(
            "Disable and remove the Telnet daemon immediately ('systemctl disable --now telnet.socket'). "
            "Migrate all remote terminal access to OpenSSH (SSHv2) with key-based authentication."
        ),
        references=[
            "CWE-319: Cleartext Transmission of Sensitive Information",
            "NIST SP 800-53: SC-8 Transmission Confidentiality and Integrity",
        ],
        tags=["encryption", "cleartext", "telnet", "network"],
    ),
    ExposureRuleDefinition(
        id="EXP-CLEARTEXT-FTP",
        name="Cleartext FTP Service Exposed",
        description=(
            "Unencrypted File Transfer Protocol (FTP) listener detected. Traditional FTP transmits credentials "
            "and transferred files in plain text, rendering sessions vulnerable to network interception."
        ),
        severity=SeverityLevel.MEDIUM,
        category=FindingCategory.CLEARTEXT_PROTOCOL,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[21],
            service_names=["ftp"],
            require_all=False,
        ),
        remediation=(
            "Migrate file transfer operations to SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS). "
            "If FTP must remain, enforce explicit TLS encryption ('ssl_enable=YES')."
        ),
        references=[
            "CWE-319: Cleartext Transmission of Sensitive Information",
        ],
        tags=["encryption", "cleartext", "ftp"],
    ),
    ExposureRuleDefinition(
        id="EXP-CLEARTEXT-HTTP",
        name="Unencrypted HTTP Web Service Exposed",
        description=(
            "Unencrypted HTTP web service detected without mandatory TLS encryption. Plaintext HTTP traffic "
            "is susceptible to content alteration, eavesdropping, and session credential theft."
        ),
        severity=SeverityLevel.LOW,
        category=FindingCategory.CLEARTEXT_PROTOCOL,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[80, 8080],
            service_names=["http"],
            require_all=False,
        ),
        remediation=(
            "Deploy valid TLS certificates, redirect all plaintext HTTP traffic to HTTPS (HTTP 301), "
            "and configure HTTP Strict Transport Security (HSTS) headers."
        ),
        references=[
            "CWE-319: Cleartext Transmission of Sensitive Information",
        ],
        tags=["encryption", "cleartext", "http", "web"],
    ),
    ExposureRuleDefinition(
        id="EXP-MGMT-SSH",
        name="Administrative SSH Interface Exposed",
        description=(
            "Administrative Secure Shell (SSH) listener exposed on the network. Accessible management interfaces "
            "expand the target attack surface to credential stuffing and SSH protocol vulnerabilities."
        ),
        severity=SeverityLevel.MEDIUM,
        category=FindingCategory.INSECURE_MANAGEMENT,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[22, 2222],
            service_names=["ssh"],
            require_all=False,
        ),
        remediation=(
            "Restrict SSH access to trusted management IP subnets or jump hosts using firewalls. Disable password "
            "authentication ('PasswordAuthentication no') and root login ('PermitRootLogin no')."
        ),
        references=[
            "CIS Control 4.1: Establish and Maintain a Secure Configuration Process",
            "CWE-1188: Insecure Default Initialization of Resource",
        ],
        tags=["management", "ssh", "remote-access"],
    ),
    ExposureRuleDefinition(
        id="EXP-DB-REDIS",
        name="Exposed Redis In-Memory Datastore",
        description=(
            "Redis in-memory cache/datastore listener detected. Redis instances are designed for trusted private "
            "environments; network exposure can lead to unauthenticated remote code execution or data theft."
        ),
        severity=SeverityLevel.HIGH,
        category=FindingCategory.DATABASE_EXPOSURE,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[6379],
            service_names=["redis"],
            require_all=False,
        ),
        remediation=(
            "Bind Redis to localhost or private network interfaces only ('bind 127.0.0.1'). Enable protected mode "
            "('protected-mode yes') and enforce strong client authentication ('requirepass')."
        ),
        references=[
            "CWE-284: Improper Access Control",
            "OWASP Top 10: A01:2021-Broken Access Control",
        ],
        tags=["database", "redis", "nosql", "unauthenticated-exposure"],
    ),
    ExposureRuleDefinition(
        id="EXP-DB-MYSQL",
        name="Exposed MySQL / MariaDB Database Server",
        description=(
            "MySQL or MariaDB relational database server exposed on standard port 3306. Directly reachable databases "
            "increase the likelihood of brute-force attacks and vulnerability exploitation."
        ),
        severity=SeverityLevel.MEDIUM,
        category=FindingCategory.DATABASE_EXPOSURE,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[3306],
            service_names=["mysql", "mariadb"],
            require_all=False,
        ),
        remediation=(
            "Bind MySQL to private VPC or loopback interfaces ('bind-address = 127.0.0.1'). Restrict external ingress "
            "using firewall rules and enforce transport encryption ('require_secure_transport = ON')."
        ),
        references=[
            "CWE-284: Improper Access Control",
        ],
        tags=["database", "mysql", "sql"],
    ),
    ExposureRuleDefinition(
        id="EXP-DB-POSTGRES",
        name="Exposed PostgreSQL Database Server",
        description=(
            "PostgreSQL relational database listener exposed on port 5432. Direct exposure allows unauthorized "
            "connection attempts and authentication brute-forcing."
        ),
        severity=SeverityLevel.MEDIUM,
        category=FindingCategory.DATABASE_EXPOSURE,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[5432],
            service_names=["postgresql"],
            require_all=False,
        ),
        remediation=(
            "Restrict client connections to trusted IP ranges in 'pg_hba.conf'. Enforce TLS encryption and place "
            "database hosts within private application subnets."
        ),
        references=[
            "CWE-284: Improper Access Control",
        ],
        tags=["database", "postgresql", "sql"],
    ),
    ExposureRuleDefinition(
        id="EXP-DB-MONGODB",
        name="Exposed MongoDB Database Server",
        description=(
            "MongoDB NoSQL database listener detected on port 27017. Open MongoDB instances are frequent targets "
            "for automated scanning, data extortion, and ransomware attacks."
        ),
        severity=SeverityLevel.HIGH,
        category=FindingCategory.DATABASE_EXPOSURE,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[27017],
            service_names=["mongodb"],
            require_all=False,
        ),
        remediation=(
            "Enable mandatory authentication ('security.authorization: enabled'), bind to local or internal interfaces "
            "('net.bindIp: 127.0.0.1'), and configure network ingress filters."
        ),
        references=[
            "CWE-306: Missing Authentication for Critical Function",
        ],
        tags=["database", "mongodb", "nosql"],
    ),
    ExposureRuleDefinition(
        id="EXP-DB-ELASTIC",
        name="Exposed Elasticsearch Cluster Endpoint",
        description=(
            "Elasticsearch REST API listener exposed on port 9200. Exposed endpoints can allow unauthenticated "
            "read/write access to search indices, cluster configurations, and sensitive operational data."
        ),
        severity=SeverityLevel.HIGH,
        category=FindingCategory.DATABASE_EXPOSURE,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[9200],
            service_names=["elasticsearch"],
            require_all=False,
        ),
        remediation=(
            "Enable security features ('xpack.security.enabled: true'), enforce TLS for HTTP and transport layers, "
            "and restrict access to application servers."
        ),
        references=[
            "CWE-284: Improper Access Control",
        ],
        tags=["database", "elasticsearch", "search"],
    ),
    ExposureRuleDefinition(
        id="EXP-MGMT-DOCKER",
        name="Unauthenticated Docker Daemon Socket Exposed",
        description=(
            "Docker Engine daemon API socket exposed on TCP ports 2375/2376. Unrestricted access to the Docker "
            "daemon allows full container deployment with host volume mounting, resulting in complete root host compromise."
        ),
        severity=SeverityLevel.CRITICAL,
        category=FindingCategory.INSECURE_MANAGEMENT,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[2375, 2376],
            products=["Docker"],
            require_all=False,
        ),
        remediation=(
            "Never expose the Docker daemon over unauthenticated TCP. Enforce mutual TLS authentication ('tlsverify=true') "
            "or communicate exclusively via the local UNIX socket ('/var/run/docker.sock') over SSH."
        ),
        references=[
            "CWE-306: Missing Authentication for Critical Function",
            "CIS Docker Benchmark 2.1",
        ],
        tags=["management", "docker", "critical", "containers"],
    ),
    ExposureRuleDefinition(
        id="EXP-MGMT-K8S",
        name="Kubernetes Control Plane Interface Exposed",
        description=(
            "Kubernetes API server, Kubelet, or etcd listener exposed on ports 6443, 10250, or 2379. Public access "
            "can allow cluster discovery, reconnaissance, or unauthorized workload operations."
        ),
        severity=SeverityLevel.HIGH,
        category=FindingCategory.INSECURE_MANAGEMENT,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[6443, 10250, 2379],
            require_all=False,
        ),
        remediation=(
            "Disable anonymous access to the API server and Kubelet, enforce RBAC authentication, and restrict "
            "control plane ports to internal management CIDRs."
        ),
        references=[
            "CIS Kubernetes Benchmark 1.2",
            "CWE-284: Improper Access Control",
        ],
        tags=["management", "kubernetes", "cloud-native"],
    ),
    ExposureRuleDefinition(
        id="EXP-MGMT-VNC",
        name="Exposed Virtual Network Computing (VNC) Server",
        description=(
            "VNC graphical remote desktop service detected on port 5900/5901. Traditional VNC protocols lack "
            "transport encryption and employ weak authentication mechanisms."
        ),
        severity=SeverityLevel.HIGH,
        category=FindingCategory.INSECURE_MANAGEMENT,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[5900, 5901],
            service_names=["vnc"],
            require_all=False,
        ),
        remediation=(
            "Tunnel VNC connections through encrypted SSH or VPN tunnels. Mandate strong passwords or replace with "
            "modern encrypted remote desktop solutions."
        ),
        references=[
            "CWE-319: Cleartext Transmission of Sensitive Information",
        ],
        tags=["management", "vnc", "remote-desktop"],
    ),
    ExposureRuleDefinition(
        id="EXP-MGMT-RDP",
        name="Exposed Microsoft Remote Desktop Protocol (RDP)",
        description=(
            "Microsoft RDP listener detected on port 3389. Directly accessible RDP endpoints are high-value targets "
            "for automated credential brute-forcing, password spraying, and ransomware ingress."
        ),
        severity=SeverityLevel.MEDIUM,
        category=FindingCategory.INSECURE_MANAGEMENT,
        default_state=FindingState.POTENTIAL_EXPOSURE,
        conditions=RuleCondition(
            ports=[3389],
            service_names=["ms-wbt-server", "rdp"],
            require_all=False,
        ),
        remediation=(
            "Do not expose RDP directly to external networks. Mandate Remote Desktop Gateway with Multi-Factor "
            "Authentication (MFA) and enforce Network Level Authentication (NLA)."
        ),
        references=[
            "CWE-284: Improper Access Control",
        ],
        tags=["management", "rdp", "remote-desktop"],
    ),
    ExposureRuleDefinition(
        id="EXP-TLS-EXPIRED",
        name="Expired TLS / SSL Certificate",
        description=(
            "The presented X.509 SSL/TLS certificate has passed its validity expiration date. Expired certificates "
            "compromise trust verification and cause security warnings."
        ),
        severity=SeverityLevel.MEDIUM,
        category=FindingCategory.TLS_CONFIGURATION,
        default_state=FindingState.CONFIRMED,
        conditions=RuleCondition(
            tls_conditions={"expired": True},
        ),
        remediation=(
            "Renew and deploy updated TLS certificates. Implement automated certificate renewal protocols (e.g. ACME) "
            "with continuous expiration monitoring."
        ),
        references=[
            "CWE-298: Improper Validation of Certificate Expiration",
        ],
        tags=["tls", "certificate", "crypto"],
    ),
    ExposureRuleDefinition(
        id="EXP-TLS-SELFSIGNED",
        name="Self-Signed TLS / SSL Certificate",
        description=(
            "The presented X.509 SSL/TLS certificate is self-signed and not signed by a recognized Certificate Authority (CA). "
            "Self-signed certificates cannot provide reliable server identity verification."
        ),
        severity=SeverityLevel.LOW,
        category=FindingCategory.TLS_CONFIGURATION,
        default_state=FindingState.CONFIRMED,
        conditions=RuleCondition(
            tls_conditions={"self_signed": True},
        ),
        remediation=(
            "Replace self-signed certificates with certificates issued by a trusted public CA or managed internal enterprise PKI."
        ),
        references=[
            "CWE-295: Improper Certificate Validation",
        ],
        tags=["tls", "certificate", "crypto"],
    ),
    ExposureRuleDefinition(
        id="EXP-TLS-LEGACY",
        name="Obsolete Legacy TLS / SSL Protocol Version",
        description=(
            "The server negotiated or supports deprecated cryptographic protocols (SSLv3, TLS 1.0, or TLS 1.1). "
            "Legacy protocols possess structural vulnerabilities to cryptographic downgrade and decryption attacks."
        ),
        severity=SeverityLevel.HIGH,
        category=FindingCategory.TLS_CONFIGURATION,
        default_state=FindingState.CONFIRMED,
        conditions=RuleCondition(
            tls_conditions={
                "disallowed_protocols": ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
            },
        ),
        remediation=(
            "Disable SSLv3, TLS 1.0, and TLS 1.1 in service TLS configurations. Enforce TLS 1.2 and TLS 1.3 as the "
            "minimum acceptable protocol versions."
        ),
        references=[
            "RFC 8996: Deprecating TLS 1.0 and TLS 1.1",
            "CWE-326: Inadequate Encryption Strength",
        ],
        tags=["tls", "protocol", "crypto", "deprecated"],
    ),
    ExposureRuleDefinition(
        id="EXP-INFO-BANNER",
        name="Detailed Software Version Disclosure in Banner",
        description=(
            "Network protocol banner reveals specific underlying software product, minor/patch version, or host operating system. "
            "Detailed version disclosures facilitate targeted exploit selection by adversaries."
        ),
        severity=SeverityLevel.INFORMATIONAL,
        category=FindingCategory.INFORMATION_DISCLOSURE,
        default_state=FindingState.INFORMATIONAL,
        conditions=RuleCondition(
            banner_pattern=r"(?i)(ubuntu|debian|centos|redhat|apache/\d\.\d|nginx/\d\.\d|openssh_\d\.\d)",
        ),
        remediation=(
            "Configure the service daemon to suppress granular version tokens and operating system identifiers in public banners "
            "(e.g. 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx)."
        ),
        references=[
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        ],
        tags=["information-disclosure", "banner", "reconnaissance"],
    ),
]
