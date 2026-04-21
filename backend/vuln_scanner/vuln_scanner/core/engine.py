"""
Main execution engine that orchestrates concurrent scanning.
"""

import asyncio
import random
from typing import List, Dict, Any, Optional, AsyncGenerator
from collections import defaultdict
from loguru import logger

from ..core.models import Template, Result, ExecutionContext, ScannerOptions, Severity
from ..protocols.http_executor import HTTPExecutor


class HostErrorCache:
    """Track errors per host to prevent hammering failed targets."""
    
    def __init__(self, max_errors: int = 10, window_seconds: int = 300):
        self.max_errors = max_errors
        self.window_seconds = window_seconds
        self.errors: Dict[str, List[float]] = defaultdict(list)
    
    def increment_error(self, hostname: str) -> None:
        """Record an error for hostname."""
        import time
        self.errors[hostname].append(time.time())
        
        # Clean old errors
        self._cleanup(hostname)
    
    def should_skip(self, hostname: str) -> bool:
        """Check if hostname should be skipped."""
        self._cleanup(hostname)
        return len(self.errors[hostname]) >= self.max_errors
    
    def _cleanup(self, hostname: str) -> None:
        """Remove old errors outside window."""
        import time
        cutoff_time = time.time() - self.window_seconds
        self.errors[hostname] = [
            t for t in self.errors[hostname]
            if t > cutoff_time
        ]


class RateLimiter:
    """Token bucket rate limiting."""
    
    def __init__(self, rate: float):
        """
        Initialize rate limiter.
        
        Args:
            rate: Requests per second (0 = unlimited)
        """
        self.rate = rate
        self.tokens: Dict[str, float] = {}
        self.last_update: Dict[str, float] = {}
    
    async def wait(self, key: str) -> None:
        """Wait until rate limit allows."""
        if self.rate <= 0:
            return
        
        import time
        
        now = time.time()
        
        if key not in self.tokens:
            self.tokens[key] = 1.0
            self.last_update[key] = now
            return
        
        # Refill tokens
        elapsed = now - self.last_update[key]
        self.tokens[key] = min(1.0, self.tokens[key] + elapsed * self.rate)
        self.last_update[key] = now
        
        # Wait if needed
        if self.tokens[key] < 1.0:
            wait_time = (1.0 - self.tokens[key]) / self.rate
            await asyncio.sleep(wait_time)
            self.tokens[key] = 0.0
        else:
            self.tokens[key] -= 1.0


class ScanningEngine:
    """Main execution engine for vulnerability scanning."""
    
    def __init__(self, options: ScannerOptions):
        """
        Initialize scanning engine.
        
        Args:
            options: Scanner configuration options
        """
        self.options = options
        self.http_executor: Optional[HTTPExecutor] = None
        self.rate_limiter = RateLimiter(options.rate_limit)
        self.host_error_cache = HostErrorCache()
        self.dedup_cache = set()
        self.results_count = 0
    
    async def initialize(self) -> None:
        """Initialize executors and resources."""
        self.http_executor = HTTPExecutor(self.options)
        await self.http_executor.initialize()
        logger.info("Scanning engine initialized")
    
    async def close(self) -> None:
        """Clean up resources."""
        if self.http_executor:
            await self.http_executor.close()
        logger.info("Scanning engine closed")
    
    async def scan(
        self,
        templates: List[Template],
        targets: List[str],
    ) -> AsyncGenerator[Result, None]:
        """
        Execute scanning workflow.
        
        Args:
            templates: List of templates to execute
            targets: List of targets to scan
        
        Yields:
            Results as they are generated
        """
        
        # Phase 1: Create work items
        work_items = []
        for template in templates:
            for target in targets:
                # Skip if host has too many errors
                hostname = self._extract_hostname(target)
                if self.host_error_cache.should_skip(hostname):
                    logger.debug(f"Skipping target (too many errors): {target}")
                    continue
                
                work_items.append((template, target))
        
        # Shuffle for load balancing
        random.shuffle(work_items)
        
        logger.info(f"Starting scan: {len(work_items)} work items, {self.options.concurrency} workers")
        
        # Phase 2: Execute with worker pool
        work_queue: asyncio.Queue = asyncio.Queue()
        
        for item in work_items:
            await work_queue.put(item)
        
        # Create workers
        workers = [
            asyncio.create_task(self._worker_loop(i, work_queue))
            for i in range(self.options.concurrency)
        ]
        
        # Collect results
        pending_results = set()
        for worker in workers:
            pending_results.add(worker)
        
        while pending_results:
            done, pending_results = await asyncio.wait(
                pending_results,
                return_when=asyncio.FIRST_COMPLETED
            )
            
            for task in done:
                try:
                    # Get results from worker
                    async for result in task:
                        yield result
                except Exception as e:
                    logger.error(f"Worker error: {e}")
        
        logger.info(f"Scan completed: {self.results_count} results")
    
    async def _worker_loop(
        self,
        worker_id: int,
        work_queue: asyncio.Queue,
    ) -> AsyncGenerator[Result, None]:
        """
        Main loop for worker task.
        
        Args:
            worker_id: Worker identifier
            work_queue: Queue of work items
        
        Yields:
            Results from executed templates
        """
        
        logger.debug(f"Worker {worker_id} started")
        
        while True:
            try:
                # Get work item with timeout
                template, target = await asyncio.wait_for(
                    work_queue.get(),
                    timeout=5.0
                )
            
            except asyncio.TimeoutError:
                # Queue is empty
                if work_queue.empty():
                    break
                else:
                    continue
            
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                break
            
            try:
                # Execute template
                results = await self._execute_template(template, target)
                
                # Yield results
                for result in results:
                    if not self.options.deduplicate or not self._is_duplicate(result):
                        self.results_count += 1
                        yield result
            
            except Exception as e:
                hostname = self._extract_hostname(target)
                self.host_error_cache.increment_error(hostname)
                logger.debug(f"Template execution failed: {e}")
            
            finally:
                work_queue.task_done()
        
        logger.debug(f"Worker {worker_id} finished")
    
    async def _execute_template(self, template: Template, target: str) -> List[Result]:
        """
        Execute template against target.
        
        Args:
            template: Template to execute
            target: Target URL
        
        Returns:
            List of results
        """
        
        results = []
        hostname = self._extract_hostname(target)
        
        # Create execution context
        context = ExecutionContext(
            target=target,
            target_url=target,
            template_id=template.id,
            variables={
                "BaseURL": target,
                "Hostname": hostname,
            },
            timeout=self.options.timeout,
            retries=self.options.retries,
            proxy=self.options.proxy,
            rate_limiter=self.rate_limiter,
        )
        
        # Execute HTTP requests
        for http_request in template.http:
            try:
                # Rate limiting
                await self.rate_limiter.wait(template.id)
                
                # Execute
                if self.http_executor:
                    request_results = await self.http_executor.execute(
                        http_request, target, context
                    )
                    
                    # Enhance results with template info
                    for result in request_results:
                        result.template_id = template.id
                        result.template_name = template.info.name
                        result.severity = template.info.severity
                        result.template_info = template.info
                        results.append(result)
            
            except Exception as e:
                logger.debug(f"Error executing HTTP request: {e}")
                self.host_error_cache.increment_error(hostname)
        
        return results
    
    def _is_duplicate(self, result: Result) -> bool:
        """Check if result is duplicate."""
        dedup_key = result.get_dedup_key()
        
        if dedup_key in self.dedup_cache:
            return True
        
        self.dedup_cache.add(dedup_key)
        return False
    
    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL."""
        if url.startswith("http://") or url.startswith("https://"):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.split(":")[0]
        else:
            return url.split(":")[0]
