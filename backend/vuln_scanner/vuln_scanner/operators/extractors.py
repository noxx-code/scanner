"""
Extractors for collecting data from responses.
"""

import re
import json
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from lxml import html as lxml_html
import jsonpath_ng
from loguru import logger

from ..core.models import Response


class Extractor(ABC):
    """Abstract base class for extractors."""
    
    @abstractmethod
    def extract(self, response: Response) -> Any:
        """Extract data from response."""
        pass


class RegexExtractor(Extractor):
    """Extract data via regex patterns."""
    
    def __init__(self, config: Dict[str, Any]):
        self.name = config.get("name", "")
        self.regex_pattern = config.get("regex", "")
        self.group = config.get("group", 1)
        self.internal = config.get("internal", False)
        self.compiled_regex = None
        self._compile()
    
    def _compile(self) -> None:
        """Compile regex pattern."""
        try:
            self.compiled_regex = re.compile(self.regex_pattern)
        except Exception as e:
            logger.error(f"Failed to compile regex: {self.regex_pattern}: {e}")
    
    def extract(self, response: Response) -> Any:
        
        if not self.compiled_regex:
            return None
        
        try:
            matches = self.compiled_regex.findall(response.body)
            
            if not matches:
                return None
            
            # Extract specified group
            if self.group > 0 and isinstance(matches[0], tuple):
                extracted_values = []
                for match in matches:
                    if len(match) >= self.group:
                        extracted_values.append(match[self.group - 1])
                
                if len(extracted_values) == 1:
                    return extracted_values[0]
                elif extracted_values:
                    return extracted_values
                else:
                    return None
            else:
                # Return all matches
                if len(matches) == 1:
                    return matches[0]
                else:
                    return matches
        
        except Exception as e:
            logger.error(f"Regex extraction failed: {e}")
            return None


class XPathExtractor(Extractor):
    """Extract data via XPath expressions."""
    
    def __init__(self, config: Dict[str, Any]):
        self.name = config.get("name", "")
        self.xpath = config.get("xpath", "")
        self.internal = config.get("internal", False)
    
    def extract(self, response: Response) -> Any:
        
        try:
            tree = lxml_html.fromstring(response.body.encode('utf-8'))
            nodes = tree.xpath(self.xpath)
            
            if not nodes:
                return None
            
            # Extract text content
            extracted_values = []
            for node in nodes:
                if isinstance(node, str):
                    extracted_values.append(node)
                else:
                    text = node.text_content().strip()
                    extracted_values.append(text)
            
            if len(extracted_values) == 1:
                return extracted_values[0]
            else:
                return extracted_values
        
        except Exception as e:
            logger.debug(f"XPath extraction failed: {e}")
            return None


class JSONPathExtractor(Extractor):
    """Extract data via JSONPath expressions."""
    
    def __init__(self, config: Dict[str, Any]):
        self.name = config.get("name", "")
        self.jsonpath = config.get("jsonpath", "")
        self.internal = config.get("internal", False)
        self.parser = None
        self._compile()
    
    def _compile(self) -> None:
        """Compile JSONPath expression."""
        try:
            self.parser = jsonpath_ng.parse(self.jsonpath)
        except Exception as e:
            logger.error(f"Failed to compile JSONPath: {self.jsonpath}: {e}")
    
    def extract(self, response: Response) -> Any:
        
        if not self.parser:
            return None
        
        try:
            data = json.loads(response.body)
            matches = self.parser.find(data)
            
            if not matches:
                return None
            
            values = [m.value for m in matches]
            
            if len(values) == 1:
                return values[0]
            else:
                return values
        
        except json.JSONDecodeError:
            logger.debug("Response is not valid JSON")
            return None
        
        except Exception as e:
            logger.debug(f"JSONPath extraction failed: {e}")
            return None


class ExtractorEngine:
    """Engine for evaluating extractors."""
    
    EXTRACTOR_TYPES = {
        "regex": RegexExtractor,
        "xpath": XPathExtractor,
        "jsonpath": JSONPathExtractor,
    }
    
    def evaluate(
        self,
        response: Response,
        extractors_config: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Extract data from response.
        
        Args:
            response: Response to extract from
            extractors_config: List of extractor configurations
        
        Returns:
            Dictionary of extracted values
        """
        
        extracted = {}
        
        for extractor_config in extractors_config:
            extractor_type = extractor_config.get("type", "regex")
            name = extractor_config.get("name", "")
            
            if not name:
                logger.warning("Extractor missing name field")
                continue
            
            # Get extractor class
            extractor_class = self.EXTRACTOR_TYPES.get(extractor_type)
            if not extractor_class:
                logger.warning(f"Unknown extractor type: {extractor_type}")
                continue
            
            # Create and evaluate extractor
            try:
                extractor = extractor_class(extractor_config)
                value = extractor.extract(response)
                
                if extractor.internal:
                    # Don't include internal extractions in results
                    continue
                
                if value is not None:
                    extracted[name] = value
            
            except Exception as e:
                logger.warning(f"Extraction failed for {name}: {e}")
        
        return extracted
