"""
HTTP protocol executor - handles HTTP requests and vulnerability checking.
"""

import asyncio
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import aiohttp
from loguru import logger

from ..core.models import HTTPRequest, Response, Result, ExecutionContext, Severity


class HTTPExecutor:
    """Execute HTTP-based vulnerability checks."""
    
    def __init__(self, options: Any):
        """
        Initialize HTTP executor.
        
        Args:
            options: Execution options with timeout, verify_ssl, proxy, etc.
        """
        self.options = options
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self) -> None:
        """Initialize HTTP client session."""
        connector = aiohttp.TCPConnector(
            ssl=self.options.verify_ssl,
            limit_per_host=5,
            limit=100,
        )
        
        timeout = aiohttp.ClientTimeout(total=self.options.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": self.options.user_agent},
        )
    
    async def close(self) -> None:
        """Close HTTP client session."""
        if self.session:
            await self.session.close()
    
    async def execute(
        self,
        request: HTTPRequest,
        target: str,
        context: ExecutionContext,
    ) -> List[Result]:
        """
        Execute HTTP request against target.
        
        Args:
            request: HTTP request specification
            target: Target URL
            context: Execution context
        
        Returns:
            List of results
        """
        results = []
        
        # Expand payloads into combinations
        payload_combinations = self._expand_payloads(request.payloads)
        
        if not payload_combinations:
            payload_combinations = [{}]
        
        # Execute for each payload combination
        for payload_set in payload_combinations:
            
            # Generate request variations
            for path_template in request.path:
                result = await self._execute_single(
                    request, target, path_template, payload_set, context
                )
                results.append(result)
        
        return results
    
    async def _execute_single(
        self,
        request: HTTPRequest,
        target: str,
        path_template: str,
        payload_set: Dict[str, str],
        context: ExecutionContext,
    ) -> Result:
        """Execute single HTTP request with retries."""
        
        # Resolve variables in path
        resolved_path = self._resolve_variables(path_template, {
            "base_url": self._extract_base_url(target),
            "hostname": self._extract_hostname(target),
            "port": str(self._extract_port(target)),
            **payload_set,
            **context.previous_results,
        })
        
        # Build full URL
        if resolved_path.startswith("http://") or resolved_path.startswith("https://"):
            request_url = resolved_path
        else:
            request_url = target + resolved_path
        
        # Resolve headers
        resolved_headers = {}
        for header_name, header_template in request.headers.items():
            resolved_value = self._resolve_variables(header_template, {
                **payload_set,
                **context.previous_results,
            })
            resolved_headers[header_name] = resolved_value
        
        # Resolve body
        resolved_body = None
        if request.body:
            resolved_body = self._resolve_variables(request.body, {
                **payload_set,
                **context.previous_results,
            })
        
        # Execute with retries
        response = None
        last_error = None
        
        for retry in range(context.retries):
            try:
                response = await self._make_request(
                    request.method,
                    request_url,
                    resolved_headers,
                    resolved_body,
                    request.redirects,
                )
                break
            
            except Exception as e:
                last_error = e
                
                if retry < context.retries - 1:
                    # Exponential backoff: 100ms, 200ms, 400ms
                    backoff_ms = 100 * (2 ** retry)
                    await asyncio.sleep(backoff_ms / 1000.0)
                else:
                    logger.debug(f"Request failed after {context.retries} retries: {e}")
        
        # Handle failure
        if response is None:
            return Result(
                template_id=context.template_id,
                target=target,
                matched=False,
                error=str(last_error),
                request_url=request_url,
            )
        
        # Evaluate matchers
        from ..operators.matchers import MatcherEngine
        engine = MatcherEngine()
        matched, match_data = engine.evaluate(
            response,
            request.matchers,
            request.matchers_condition,
        )
        
        # Extract data if matched
        extracted_data = {}
        if matched:
            from ..operators.extractors import ExtractorEngine
            extractor_engine = ExtractorEngine()
            extracted_data = extractor_engine.evaluate(response, request.extractors)
        
        # Create result
        result = Result(
            template_id=context.template_id,
            target=target,
            matched=matched,
            response=response,
            extracted_data=extracted_data,
            request_url=request_url,
            severity=Severity.INFO,  # Will be set by caller
        )
        
        return result
    
    async def _make_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str],
        redirects: int,
    ) -> Response:
        """Make HTTP request and return response."""
        
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        start_time = time.time()
        
        try:
            async with self.session.request(
                method,
                url,
                headers=headers,
                data=body,
                allow_redirects=True,
                ssl=self.options.verify_ssl,
            ) as resp:
                body_bytes = await resp.read()
                body_text = body_bytes.decode('utf-8', errors='ignore')
                
                duration_ms = (time.time() - start_time) * 1000
                
                response = Response(
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=body_text,
                    body_bytes=body_bytes,
                    cookies=dict(resp.cookies),
                    request_url=str(resp.url),
                    request_method=method,
                    request_headers=headers,
                    request_body=body or "",
                    duration_ms=duration_ms,
                    protocol="http",
                )
                
                return response
        
        except asyncio.TimeoutError:
            raise TimeoutError(f"Request timeout: {url}")
        
        except Exception as e:
            raise RuntimeError(f"HTTP request failed: {e}")
    
    def _expand_payloads(self, payloads_dict: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Expand payloads into Cartesian product.
        
        Example:
            {"payload1": ["a", "b"], "payload2": ["1", "2"]}
            -> [{"payload1": "a", "payload2": "1"}, {"payload1": "a", "payload2": "2"}, ...]
        """
        if not payloads_dict:
            return []
        
        # Get all payload lists
        payload_names = []
        payload_lists = []
        
        for name, values in payloads_dict.items():
            if isinstance(values, str) and values.startswith("file://"):
                # Load from file
                file_path = values.replace("file://", "")
                try:
                    with open(file_path, 'r') as f:
                        values = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    logger.error(f"Failed to load payload file {file_path}: {e}")
                    values = []
            
            elif isinstance(values, str):
                values = [values]
            
            payload_names.append(name)
            payload_lists.append(values)
        
        # Compute Cartesian product
        combinations = []
        if payload_lists:
            import itertools
            product = itertools.product(*payload_lists)
            
            for value_tuple in product:
                combination = {}
                for i, name in enumerate(payload_names):
                    combination[name] = str(value_tuple[i])
                combinations.append(combination)
        
        return combinations
    
    def _resolve_variables(self, template: str, variables: Dict[str, Any]) -> str:
        """
        Replace {{variable}} with values.
        
        Example:
            "{{BaseURL}}/path" -> "http://example.com/path"
        """
        result = template
        
        # Find all {{variable}} patterns
        import re
        pattern = r'\{\{(\w+)\}\}'
        matches = re.findall(pattern, result)
        
        for var_name in matches:
            placeholder = "{{" + var_name + "}}"
            
            if var_name in variables:
                value = variables[var_name]
                string_value = str(value)
                result = result.replace(placeholder, string_value)
            else:
                logger.warning(f"Variable not found: {var_name}")
        
        return result
    
    def _extract_base_url(self, url: str) -> str:
        """Extract base URL from target."""
        if url.startswith("http://") or url.startswith("https://"):
            return url
        else:
            return f"http://{url}"
    
    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL."""
        if url.startswith("http://") or url.startswith("https://"):
            parsed = urlparse(url)
            return parsed.netloc.split(":")[0]
        else:
            return url.split(":")[0]
    
    def _extract_port(self, url: str) -> int:
        """Extract port from URL."""
        if url.startswith("http://") or url.startswith("https://"):
            parsed = urlparse(url)
            if parsed.port:
                return parsed.port
            return 443 if parsed.scheme == "https" else 80
        
        if ":" in url:
            try:
                return int(url.split(":")[-1])
            except ValueError:
                pass
        
        return 80
