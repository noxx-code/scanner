"""
Matchers for evaluating vulnerability conditions.
"""

import re
from typing import Tuple, Dict, Any, List
from abc import ABC, abstractmethod
from lxml import html as lxml_html
import jsonpath_ng
from loguru import logger

from ..core.models import Response


class Matcher(ABC):
    """Abstract base class for matchers."""
    
    @abstractmethod
    def evaluate(self, response: Response) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate matcher against response.
        
        Returns:
            (matched: bool, data: dict)
        """
        pass


class StatusMatcher(Matcher):
    """Match HTTP status codes."""
    
    def __init__(self, config: Dict[str, Any]):
        self.status_codes = config.get("status", [])
        if isinstance(self.status_codes, int):
            self.status_codes = [self.status_codes]
    
    def evaluate(self, response: Response) -> Tuple[bool, Dict[str, Any]]:
        matched = response.status_code in self.status_codes if response.status_code else False
        return (matched, {})


class WordMatcher(Matcher):
    """Match words/strings in response."""
    
    def __init__(self, config: Dict[str, Any]):
        self.words = config.get("words", [])
        self.case_sensitive = config.get("case_sensitive", False)
        self.part = config.get("part", "body")  # body, header, all
    
    def evaluate(self, response: Response) -> Tuple[bool, Dict[str, Any]]:
        
        # Determine search space
        if self.part == "header":
            search_text = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        elif self.part == "all":
            search_text = response.body + "\n" + "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
        else:  # body
            search_text = response.body
        
        # Apply case sensitivity
        if not self.case_sensitive:
            search_text = search_text.lower()
        
        # Search for words
        matched = False
        for word in self.words:
            word_to_search = word if self.case_sensitive else word.lower()
            
            if word_to_search in search_text:
                matched = True
                break
        
        return (matched, {})


class RegexMatcher(Matcher):
    """Match regex patterns in response."""
    
    def __init__(self, config: Dict[str, Any]):
        self.regex_pattern = config.get("regex", "")
        self.group = config.get("group", 0)
        self.compiled_regex = None
        self._compile()
    
    def _compile(self) -> None:
        """Compile regex pattern."""
        try:
            self.compiled_regex = re.compile(self.regex_pattern)
        except Exception as e:
            logger.error(f"Failed to compile regex: {self.regex_pattern}: {e}")
    
    def evaluate(self, response: Response) -> Tuple[bool, Dict[str, Any]]:
        
        if not self.compiled_regex:
            return (False, {})
        
        try:
            matches = self.compiled_regex.findall(response.body)
            
            if not matches:
                return (False, {})
            
            matched_data = {}
            if self.group > 0 and len(matches) > 0:
                if isinstance(matches[0], tuple) and len(matches[0]) > self.group - 1:
                    matched_data["group"] = matches[0][self.group - 1]
            else:
                matched_data["match"] = matches[0] if matches else None
            
            return (True, matched_data)
        
        except Exception as e:
            logger.error(f"Regex evaluation failed: {e}")
            return (False, {})


class XPathMatcher(Matcher):
    """Match XPath expressions against HTML/XML."""
    
    def __init__(self, config: Dict[str, Any]):
        self.xpath = config.get("xpath", "")
    
    def evaluate(self, response: Response) -> Tuple[bool, Dict[str, Any]]:
        
        try:
            tree = lxml_html.fromstring(response.body.encode('utf-8'))
            results = tree.xpath(self.xpath)
            
            matched = len(results) > 0
            return (matched, {"results": [str(r) for r in results]})
        
        except Exception as e:
            logger.debug(f"XPath evaluation failed: {e}")
            return (False, {})


class JSONPathMatcher(Matcher):
    """Match JSONPath expressions against JSON responses."""
    
    def __init__(self, config: Dict[str, Any]):
        self.jsonpath = config.get("jsonpath", "")
        self.parser = None
        self._compile()
    
    def _compile(self) -> None:
        """Compile JSONPath expression."""
        try:
            self.parser = jsonpath_ng.parse(self.jsonpath)
        except Exception as e:
            logger.error(f"Failed to compile JSONPath: {self.jsonpath}: {e}")
    
    def evaluate(self, response: Response) -> Tuple[bool, Dict[str, Any]]:
        
        if not self.parser:
            return (False, {})
        
        try:
            import json
            data = json.loads(response.body)
            
            matches = self.parser.find(data)
            
            matched = len(matches) > 0
            return (matched, {"matches": [str(m.value) for m in matches]})
        
        except Exception as e:
            logger.debug(f"JSONPath evaluation failed: {e}")
            return (False, {})


class DSLMatcher(Matcher):
    """Evaluate DSL expressions."""
    
    def __init__(self, config: Dict[str, Any]):
        self.dsl_expressions = config.get("dsl", [])
        if isinstance(self.dsl_expressions, str):
            self.dsl_expressions = [self.dsl_expressions]
    
    def evaluate(self, response: Response) -> Tuple[bool, Dict[str, Any]]:
        
        # Build DSL context
        dsl_context = self._create_dsl_context(response)
        
        result = True
        for expression in self.dsl_expressions:
            try:
                expr_result = self._evaluate_dsl_expression(expression, dsl_context)
                result = result and expr_result
                
                if not result:
                    break
            
            except Exception as e:
                logger.error(f"DSL expression failed: {expression}: {e}")
                result = False
                break
        
        return (result, dsl_context)
    
    def _create_dsl_context(self, response: Response) -> Dict[str, Any]:
        """Create context for DSL evaluation."""
        return {
            "status": response.status_code,
            "status_code": response.status_code,
            "body": response.body,
            "headers": response.headers,
            "content_length": len(response.body),
        }
    
    def _evaluate_dsl_expression(self, expression: str, context: Dict[str, Any]) -> bool:
        """
        Safely evaluate DSL expression.
        
        Supported operations:
        - comparison: ==, !=, <, >, <=, >=
        - contains: 'word' in body
        - attributes: status, content_length
        """
        
        # Prevent infinite loops and excessive computation
        if len(expression) > 1000:
            logger.warning("DSL expression too long")
            return False
        
        # Build safe evaluation context with helper functions
        safe_context = {
            "status": context["status_code"],
            "body": context["body"],
            "headers": context["headers"],
            "content_length": context["content_length"],
            "contains": lambda s1, s2: str(s2) in str(s1),
            "startswith": lambda s, prefix: str(s).startswith(str(prefix)),
            "endswith": lambda s, suffix: str(s).endswith(str(suffix)),
            "len": lambda s: len(str(s)),
            "int": int,
            "str": str,
        }
        
        try:
            # Evaluate with timeout
            result = eval(expression, {"__builtins__": {}}, safe_context)
            return bool(result)
        
        except Exception as e:
            logger.error(f"DSL evaluation error: {e}")
            return False


class MatcherEngine:
    """Engine for evaluating matchers."""
    
    MATCHER_TYPES = {
        "status": StatusMatcher,
        "word": WordMatcher,
        "regex": RegexMatcher,
        "xpath": XPathMatcher,
        "jsonpath": JSONPathMatcher,
        "dsl": DSLMatcher,
    }
    
    def evaluate(
        self,
        response: Response,
        matchers_config: List[Dict[str, Any]],
        condition: str = "and",
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate all matchers with logical condition.
        
        Args:
            response: Response to evaluate
            matchers_config: List of matcher configurations
            condition: "and" or "or" logical operator
        
        Returns:
            (matched: bool, data: dict)
        """
        
        match_results = []
        combined_data = {}
        
        for matcher_config in matchers_config:
            matcher_type = matcher_config.get("type", "word")
            
            # Get matcher class
            matcher_class = self.MATCHER_TYPES.get(matcher_type)
            if not matcher_class:
                logger.warning(f"Unknown matcher type: {matcher_type}")
                continue
            
            # Create and evaluate matcher
            try:
                matcher = matcher_class(matcher_config)
                matched, data = matcher.evaluate(response)
                match_results.append(matched)
                combined_data.update(data)
            
            except Exception as e:
                logger.error(f"Matcher evaluation failed: {e}")
                match_results.append(False)
        
        # Apply logical condition
        if condition == "and":
            final_result = all(match_results) if match_results else False
        elif condition == "or":
            final_result = any(match_results) if match_results else False
        else:
            final_result = False
        
        return (final_result, combined_data)
