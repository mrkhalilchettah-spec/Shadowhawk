"""
Prompt Library Unit Tests
Copyright (c) 2024 ShadowHawk Team
Licensed under the MIT License
"""

import pytest
import tempfile
from pathlib import Path

from shadowhawk.infrastructure.ai.prompt_library import PromptTemplate, PromptLibrary


def test_prompt_template_creation() -> None:
    """Test creating a prompt template"""
    template = PromptTemplate(
        name="test_prompt",
        version="1.0.0",
        system_prompt="You are a test assistant.",
        user_prompt_template="Analyze this: ${input}",
        description="Test template",
        tags=["test"],
    )
    
    assert template.name == "test_prompt"
    assert template.version == "1.0.0"
    assert len(template.system_prompt) > 0
    assert "${input}" in template.user_prompt_template


def test_prompt_template_render() -> None:
    """Test rendering a prompt template"""
    template = PromptTemplate(
        name="test",
        version="1.0.0",
        system_prompt="System prompt",
        user_prompt_template="Hello ${name}, you are ${age} years old.",
    )
    
    system, user = template.render(name="Alice", age=25)
    
    assert system == "System prompt"
    assert user == "Hello Alice, you are 25 years old."


def test_prompt_template_render_missing_variable() -> None:
    """Test rendering with missing variable"""
    template = PromptTemplate(
        name="test",
        version="1.0.0",
        system_prompt="System",
        user_prompt_template="Hello ${name}",
    )
    
    with pytest.raises(ValueError, match="Missing required variable"):
        template.render()


def test_prompt_template_to_dict() -> None:
    """Test converting template to dict"""
    template = PromptTemplate(
        name="test",
        version="1.0.0",
        system_prompt="System",
        user_prompt_template="User ${var}",
        description="Description",
        tags=["tag1", "tag2"],
    )
    
    data = template.to_dict()
    
    assert data["name"] == "test"
    assert data["version"] == "1.0.0"
    assert data["system_prompt"] == "System"
    assert data["user_prompt_template"] == "User ${var}"
    assert data["description"] == "Description"
    assert data["tags"] == ["tag1", "tag2"]


def test_prompt_library_with_yaml_files() -> None:
    """Test loading prompts from YAML files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        prompts_dir = Path(tmpdir)
        
        # Create a test YAML file
        yaml_content = """
name: test_prompt
version: 1.0.0
system_prompt: "You are a test assistant."
user_prompt: "Process this: ${input}"
description: "Test prompt template"
tags:
  - test
  - example
examples:
  - input: "test input"
    output: "test output"
"""
        yaml_file = prompts_dir / "test_prompt.yaml"
        yaml_file.write_text(yaml_content)
        
        # Load prompts
        library = PromptLibrary(prompts_dir=prompts_dir)
        
        # Verify template was loaded
        assert "test_prompt" in library.list_templates()
        
        template = library.get("test_prompt")
        assert template.name == "test_prompt"
        assert template.version == "1.0.0"
        assert "test" in template.tags


def test_prompt_library_get_nonexistent() -> None:
    """Test getting non-existent template"""
    with tempfile.TemporaryDirectory() as tmpdir:
        library = PromptLibrary(prompts_dir=Path(tmpdir))
        
        with pytest.raises(KeyError, match="not found"):
            library.get("nonexistent_prompt")


def test_prompt_library_search_by_tag() -> None:
    """Test searching templates by tag"""
    with tempfile.TemporaryDirectory() as tmpdir:
        prompts_dir = Path(tmpdir)
        
        # Create multiple test YAML files
        yaml1 = prompts_dir / "prompt1.yaml"
        yaml1.write_text("""
name: prompt1
version: 1.0.0
system_prompt: "System 1"
user_prompt: "User 1"
tags:
  - security
  - analysis
""")
        
        yaml2 = prompts_dir / "prompt2.yaml"
        yaml2.write_text("""
name: prompt2
version: 1.0.0
system_prompt: "System 2"
user_prompt: "User 2"
tags:
  - security
  - reporting
""")
        
        library = PromptLibrary(prompts_dir=prompts_dir)
        
        # Search by tag
        security_templates = library.search_by_tag("security")
        assert len(security_templates) == 2
        
        analysis_templates = library.search_by_tag("analysis")
        assert len(analysis_templates) == 1
        assert analysis_templates[0].name == "prompt1"


def test_prompt_library_reload() -> None:
    """Test reloading templates"""
    with tempfile.TemporaryDirectory() as tmpdir:
        prompts_dir = Path(tmpdir)
        
        # Initial load
        yaml_file = prompts_dir / "test.yaml"
        yaml_file.write_text("""
name: test
version: 1.0.0
system_prompt: "Original"
user_prompt: "Original"
""")
        
        library = PromptLibrary(prompts_dir=prompts_dir)
        template = library.get("test")
        assert template.system_prompt == "Original"
        
        # Modify file
        yaml_file.write_text("""
name: test
version: 2.0.0
system_prompt: "Updated"
user_prompt: "Updated"
""")
        
        # Reload
        library.reload()
        template = library.get("test")
        assert template.version == "2.0.0"
        assert template.system_prompt == "Updated"


def test_prompt_library_empty_directory() -> None:
    """Test with empty prompts directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        library = PromptLibrary(prompts_dir=Path(tmpdir))
        assert len(library.list_templates()) == 0


def test_prompt_library_invalid_yaml() -> None:
    """Test handling of invalid YAML files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        prompts_dir = Path(tmpdir)
        
        # Create invalid YAML
        yaml_file = prompts_dir / "invalid.yaml"
        yaml_file.write_text("{ invalid yaml content")
        
        # Should not raise exception, just skip the file
        library = PromptLibrary(prompts_dir=prompts_dir)
        assert "invalid" not in library.list_templates()
