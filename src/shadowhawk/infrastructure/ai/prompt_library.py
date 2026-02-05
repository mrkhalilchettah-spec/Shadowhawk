"""
Prompt Library System
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License

Version-controlled prompt templates with interpolation support.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from string import Template
import structlog

logger = structlog.get_logger()


class PromptTemplate:
    """Represents a versioned prompt template"""
    
    def __init__(
        self,
        name: str,
        version: str,
        system_prompt: str,
        user_prompt_template: str,
        description: str = "",
        tags: Optional[list[str]] = None,
        examples: Optional[list[Dict[str, str]]] = None,
    ) -> None:
        """
        Initialize prompt template
        
        Args:
            name: Template name
            version: Version string (e.g., "1.0.0")
            system_prompt: System prompt text
            user_prompt_template: User prompt with ${variable} placeholders
            description: Template description
            tags: List of tags for categorization
            examples: Example inputs/outputs
        """
        self.name = name
        self.version = version
        self.system_prompt = system_prompt
        self.user_prompt_template = user_prompt_template
        self.description = description
        self.tags = tags or []
        self.examples = examples or []
    
    def render(self, **variables: Any) -> tuple[str, str]:
        """
        Render template with variables
        
        Args:
            **variables: Variables to interpolate
            
        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        template = Template(self.user_prompt_template)
        try:
            user_prompt = template.substitute(**variables)
        except KeyError as e:
            raise ValueError(f"Missing required variable: {e}")
        
        return self.system_prompt, user_prompt
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "version": self.version,
            "system_prompt": self.system_prompt,
            "user_prompt_template": self.user_prompt_template,
            "description": self.description,
            "tags": self.tags,
            "examples": self.examples,
        }


class PromptLibrary:
    """Manages prompt templates loaded from YAML files"""
    
    def __init__(self, prompts_dir: Optional[Path] = None) -> None:
        """
        Initialize prompt library
        
        Args:
            prompts_dir: Directory containing prompt YAML files
        """
        if prompts_dir is None:
            project_root = Path(__file__).parent.parent.parent.parent.parent
            prompts_dir = project_root / "config" / "prompts"
        
        self.prompts_dir = Path(prompts_dir)
        self.templates: Dict[str, PromptTemplate] = {}
        self._load_templates()
    
    def _load_templates(self) -> None:
        """Load all prompt templates from directory"""
        if not self.prompts_dir.exists():
            logger.warning(
                "prompts_directory_not_found",
                path=str(self.prompts_dir),
            )
            return
        
        for yaml_file in self.prompts_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r") as f:
                    data = yaml.safe_load(f)
                
                if not data:
                    continue
                
                template = PromptTemplate(
                    name=data.get("name", yaml_file.stem),
                    version=data.get("version", "1.0.0"),
                    system_prompt=data.get("system_prompt", ""),
                    user_prompt_template=data.get("user_prompt", ""),
                    description=data.get("description", ""),
                    tags=data.get("tags", []),
                    examples=data.get("examples", []),
                )
                
                self.templates[template.name] = template
                
                logger.info(
                    "prompt_template_loaded",
                    name=template.name,
                    version=template.version,
                )
                
            except Exception as e:
                logger.error(
                    "failed_to_load_template",
                    file=str(yaml_file),
                    error=str(e),
                )
    
    def get(self, name: str) -> PromptTemplate:
        """
        Get prompt template by name
        
        Args:
            name: Template name
            
        Returns:
            PromptTemplate instance
            
        Raises:
            KeyError: If template not found
        """
        if name not in self.templates:
            raise KeyError(f"Prompt template '{name}' not found")
        return self.templates[name]
    
    def list_templates(self) -> list[str]:
        """List all available template names"""
        return list(self.templates.keys())
    
    def search_by_tag(self, tag: str) -> list[PromptTemplate]:
        """
        Search templates by tag
        
        Args:
            tag: Tag to search for
            
        Returns:
            List of matching templates
        """
        return [
            template
            for template in self.templates.values()
            if tag in template.tags
        ]
    
    def reload(self) -> None:
        """Reload all templates from disk"""
        self.templates.clear()
        self._load_templates()
        logger.info("prompt_templates_reloaded")
