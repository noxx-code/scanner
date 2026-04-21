"""
Template loader and compiler - loads YAML templates and compiles them for execution.
"""

import os
import glob
import yaml
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from loguru import logger
from cachetools import LRUCache

from .models import (
    Template, TemplateInfo, HTTPRequest, DNSRequest, NetworkRequest,
    SSLRequest, Severity
)


class TemplateValidationError(Exception):
    """Raised when template validation fails."""
    pass


class TemplateLoader:
    """Loads and validates YAML templates from filesystem."""
    
    def __init__(self, cache_size: int = 1000):
        """
        Initialize template loader.
        
        Args:
            cache_size: Maximum number of templates to cache
        """
        self.cache: LRUCache = LRUCache(maxsize=cache_size)
        self.cache_hits = 0
        self.cache_misses = 0
        self.loaded_templates: Dict[str, Template] = {}
        self.errors: List[Dict[str, Any]] = []
    
    def load_templates(
        self,
        paths: List[str],
        include_tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
    ) -> Tuple[List[Template], List[Dict[str, Any]]]:
        """
        Load templates from paths with filtering.
        
        Args:
            paths: List of files, directories, or glob patterns
            include_tags: Only include templates with these tags
            exclude_tags: Exclude templates with these tags
        
        Returns:
            Tuple of (loaded_templates, errors)
        """
        self.errors = []
        
        # Phase 1: Expand paths
        expanded_paths = self._expand_paths(paths)
        logger.info(f"Found {len(expanded_paths)} template files")
        
        # Phase 2: Load and parse
        templates = []
        for template_path in expanded_paths:
            try:
                template = self.load_single(template_path)
                
                if template is None:
                    continue
                
                # Apply tag filters
                if not self._matches_filters(template.info.tags, include_tags, exclude_tags):
                    continue
                
                templates.append(template)
                self.loaded_templates[template.id] = template
            
            except TemplateValidationError as e:
                error_info = {
                    "path": template_path,
                    "error": str(e),
                    "type": "validation"
                }
                self.errors.append(error_info)
                logger.error(f"Validation failed for {template_path}: {e}")
            
            except Exception as e:
                error_info = {
                    "path": template_path,
                    "error": str(e),
                    "type": "parsing"
                }
                self.errors.append(error_info)
                logger.error(f"Failed to parse {template_path}: {e}")
        
        if self.errors:
            logger.warning(f"{len(self.errors)} templates failed to load")
        
        logger.info(f"Loaded {len(templates)} valid templates")
        
        return templates, self.errors
    
    def load_single(self, template_path: str) -> Optional[Template]:
        """
        Load and validate a single template.
        
        Args:
            template_path: Path to template file
        
        Returns:
            Parsed template or None if invalid
        """
        # Check cache
        cache_key = self._get_cache_key(template_path)
        
        if cache_key in self.cache:
            self.cache_hits += 1
            logger.debug(f"Cache hit for {template_path}")
            return self.cache[cache_key]
        
        self.cache_misses += 1
        
        # Load YAML
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template file not found: {template_path}")
        
        with open(template_path, 'r', encoding='utf-8') as f:
            raw_yaml = f.read()
        
        try:
            template_dict = yaml.safe_load(raw_yaml)
        except yaml.YAMLError as e:
            raise TemplateValidationError(f"Invalid YAML: {e}")
        
        if template_dict is None:
            raise TemplateValidationError("Empty template file")
        
        # Validate required fields
        if "id" not in template_dict:
            raise TemplateValidationError("Missing required field: id")
        
        if "info" not in template_dict:
            raise TemplateValidationError("Missing required field: info")
        
        # Validate template structure
        self._validate_template_structure(template_dict)
        
        # Parse template
        template = self._parse_template(template_dict)
        
        # Cache
        self.cache[cache_key] = template
        
        return template
    
    def _expand_paths(self, paths: List[str]) -> List[str]:
        """
        Expand paths to list of template files.
        
        Supports:
        - Glob patterns: *.yaml
        - Directories: path/to/templates/
        - Files: path/to/template.yaml
        """
        expanded = []
        
        for path in paths:
            if "*" in path or "?" in path:
                # Glob pattern
                matches = glob.glob(path, recursive=True)
                expanded.extend(matches)
            
            elif os.path.isdir(path):
                # Directory - find all YAML files
                for ext in ['*.yaml', '*.yml']:
                    pattern = os.path.join(path, '**', ext)
                    matches = glob.glob(pattern, recursive=True)
                    expanded.extend(matches)
            
            elif os.path.isfile(path):
                # File
                expanded.append(path)
            
            else:
                logger.warning(f"Path not found: {path}")
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for path in expanded:
            if path not in seen:
                seen.add(path)
                unique.append(path)
        
        return unique
    
    def _validate_template_structure(self, template_dict: Dict[str, Any]) -> None:
        """Validate template has at least one request type."""
        has_requests = False
        
        for req_type in ['http', 'dns', 'network', 'ssl', 'javascript', 'file']:
            if req_type in template_dict and template_dict[req_type]:
                if isinstance(template_dict[req_type], list):
                    has_requests = len(template_dict[req_type]) > 0
                    if has_requests:
                        break
        
        if not has_requests:
            raise TemplateValidationError("No requests defined in template")
        
        # Validate severity
        info = template_dict.get("info", {})
        severity = info.get("severity", "info")
        
        valid_severities = {s.value for s in Severity}
        if severity not in valid_severities:
            raise TemplateValidationError(f"Invalid severity: {severity}")
    
    def _parse_template(self, template_dict: Dict[str, Any]) -> Template:
        """Parse template dictionary into Template object."""
        
        # Parse info
        info_dict = template_dict.get("info", {})
        info = TemplateInfo(
            name=info_dict.get("name", ""),
            author=info_dict.get("author", ""),
            description=info_dict.get("description", ""),
            severity=Severity(info_dict.get("severity", "info")),
            tags=info_dict.get("tags", []),
            reference=info_dict.get("reference"),
            remediation=info_dict.get("remediation"),
            cvss_score=info_dict.get("cvss_score"),
            cvss_vector=info_dict.get("cvss_vector"),
        )
        
        # Parse requests
        http_requests = self._parse_http_requests(template_dict.get("http", []))
        dns_requests = self._parse_dns_requests(template_dict.get("dns", []))
        network_requests = self._parse_network_requests(template_dict.get("network", []))
        ssl_requests = self._parse_ssl_requests(template_dict.get("ssl", []))
        
        # Create template
        template = Template(
            id=template_dict["id"],
            info=info,
            http=http_requests,
            dns=dns_requests,
            network=network_requests,
            ssl=ssl_requests,
            flow=template_dict.get("flow"),
        )
        
        return template
    
    def _parse_http_requests(self, http_specs: List[Dict[str, Any]]) -> List[HTTPRequest]:
        """Parse HTTP request specifications."""
        requests = []
        
        for spec in http_specs:
            # Ensure path is a list
            paths = spec.get("path", [])
            if isinstance(paths, str):
                paths = [paths]
            
            request = HTTPRequest(
                name=spec.get("name"),
                method=spec.get("method", "GET").upper(),
                path=paths,
                headers=spec.get("headers", {}),
                body=spec.get("body"),
                cookies=spec.get("cookies", {}),
                auth=spec.get("auth"),
                redirects=spec.get("redirects", 5),
                timeout=spec.get("timeout", 10),
                payloads=spec.get("payloads", {}),
                matchers=spec.get("matchers", []),
                matchers_condition=spec.get("matchers-condition", "and"),
                extractors=spec.get("extractors", []),
            )
            requests.append(request)
        
        return requests
    
    def _parse_dns_requests(self, dns_specs: List[Dict[str, Any]]) -> List[DNSRequest]:
        """Parse DNS request specifications."""
        requests = []
        
        for spec in dns_specs:
            request = DNSRequest(
                name=spec.get("name"),
                type=spec.get("type", "A"),
                class_=spec.get("class", "IN"),
                resolvers=spec.get("resolvers", []),
                matchers=spec.get("matchers", []),
                matchers_condition=spec.get("matchers-condition", "and"),
                extractors=spec.get("extractors", []),
            )
            requests.append(request)
        
        return requests
    
    def _parse_network_requests(self, net_specs: List[Dict[str, Any]]) -> List[NetworkRequest]:
        """Parse network request specifications."""
        requests = []
        
        for spec in net_specs:
            request = NetworkRequest(
                name=spec.get("name"),
                host=spec.get("host", ""),
                port=spec.get("port", 0),
                input_data=spec.get("input"),
                matchers=spec.get("matchers", []),
                matchers_condition=spec.get("matchers-condition", "and"),
                extractors=spec.get("extractors", []),
            )
            requests.append(request)
        
        return requests
    
    def _parse_ssl_requests(self, ssl_specs: List[Dict[str, Any]]) -> List[SSLRequest]:
        """Parse SSL request specifications."""
        requests = []
        
        for spec in ssl_specs:
            request = SSLRequest(
                name=spec.get("name"),
                address=spec.get("address", ""),
                min_version=spec.get("min_version", "tls12"),
                matchers=spec.get("matchers", []),
                matchers_condition=spec.get("matchers-condition", "and"),
                extractors=spec.get("extractors", []),
            )
            requests.append(request)
        
        return requests
    
    def _matches_filters(
        self,
        tags: List[str],
        include_tags: Optional[List[str]],
        exclude_tags: Optional[List[str]],
    ) -> bool:
        """Check if template tags match include/exclude filters."""
        
        # Check exclude first
        if exclude_tags:
            for exclude_tag in exclude_tags:
                if exclude_tag in tags:
                    return False
        
        # Check include
        if include_tags:
            for include_tag in include_tags:
                if include_tag in tags:
                    return True
            return False
        
        # No include filter, so include by default
        return True
    
    def _get_cache_key(self, template_path: str) -> str:
        """Generate cache key for template."""
        try:
            mtime = os.path.getmtime(template_path)
        except OSError:
            mtime = 0
        
        content = f"{template_path}:{mtime}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total = self.cache_hits + self.cache_misses
        hit_rate = (self.cache_hits / total * 100) if total > 0 else 0
        
        return {
            "cache_size": len(self.cache),
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate": f"{hit_rate:.1f}%",
            "total_templates": len(self.loaded_templates),
        }
