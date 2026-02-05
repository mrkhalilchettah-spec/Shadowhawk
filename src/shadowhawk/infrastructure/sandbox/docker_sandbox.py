"""
ShadowHawk Platform - Docker Sandbox

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import Dict, Any, Optional, List
import logging
import tempfile
import os

logger = logging.getLogger(__name__)


class DockerSandbox:
    """
    Docker-based sandbox for secure tool execution.
    
    Provides isolated execution environment for security tools.
    """
    
    def __init__(
        self,
        image: str = "python:3.11-slim",
        timeout: int = 300,
        memory_limit: str = "512m",
        cpu_limit: float = 1.0
    ):
        """
        Initialize Docker sandbox.
        
        Args:
            image: Docker image to use
            timeout: Execution timeout in seconds
            memory_limit: Memory limit for container
            cpu_limit: CPU limit for container
        """
        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.docker_available = self._check_docker_availability()
    
    def _check_docker_availability(self) -> bool:
        """Check if Docker is available."""
        try:
            import docker
            client = docker.from_env()
            client.ping()
            logger.info("Docker is available")
            return True
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            return False
    
    def execute(
        self,
        command: str,
        workdir: str = "/app",
        environment: Optional[Dict[str, str]] = None,
        volumes: Optional[Dict[str, Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Execute a command in Docker container.
        
        Args:
            command: Command to execute
            workdir: Working directory in container
            environment: Environment variables
            volumes: Volume mappings
            
        Returns:
            Execution result with output and status
        """
        if not self.docker_available:
            return self._simulate_execution(command)
        
        try:
            import docker
            client = docker.from_env()
            
            container = client.containers.run(
                self.image,
                command=command,
                working_dir=workdir,
                environment=environment or {},
                volumes=volumes or {},
                mem_limit=self.memory_limit,
                nano_cpus=int(self.cpu_limit * 1e9),
                network_mode="none",
                detach=True,
                remove=False,
            )
            
            try:
                result = container.wait(timeout=self.timeout)
                logs = container.logs().decode("utf-8")
                
                return {
                    "success": result["StatusCode"] == 0,
                    "exit_code": result["StatusCode"],
                    "output": logs,
                    "error": None if result["StatusCode"] == 0 else logs,
                }
            finally:
                container.remove(force=True)
                
        except Exception as e:
            logger.error(f"Docker execution failed: {e}")
            return {
                "success": False,
                "exit_code": -1,
                "output": "",
                "error": str(e),
            }
    
    def _simulate_execution(self, command: str) -> Dict[str, Any]:
        """Simulate execution when Docker is not available."""
        logger.info(f"Simulating Docker execution: {command}")
        return {
            "success": True,
            "exit_code": 0,
            "output": f"Simulated execution of: {command}",
            "error": None,
            "simulated": True,
        }
    
    def execute_script(
        self,
        script_content: str,
        script_type: str = "python",
        workdir: str = "/app"
    ) -> Dict[str, Any]:
        """
        Execute a script in Docker container.
        
        Args:
            script_content: Script content to execute
            script_type: Type of script (python, bash, etc.)
            workdir: Working directory
            
        Returns:
            Execution result
        """
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix=f".{script_type}",
            delete=False
        ) as f:
            f.write(script_content)
            script_path = f.name
        
        try:
            volumes = {
                script_path: {"bind": f"{workdir}/script", "mode": "ro"}
            }
            
            command_map = {
                "python": "python /app/script",
                "bash": "bash /app/script",
                "sh": "sh /app/script",
            }
            
            command = command_map.get(script_type, f"{script_type} /app/script")
            
            return self.execute(
                command=command,
                workdir=workdir,
                volumes=volumes
            )
        finally:
            try:
                os.unlink(script_path)
            except Exception:
                pass
    
    def run_security_tool(
        self,
        tool_name: str,
        args: List[str],
        input_data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run a security tool in isolated environment.
        
        Args:
            tool_name: Name of the security tool
            args: Arguments to pass to the tool
            input_data: Optional input data
            
        Returns:
            Tool execution result
        """
        command = f"{tool_name} {' '.join(args)}"
        
        environment = {}
        if input_data:
            environment["INPUT_DATA"] = input_data
        
        result = self.execute(
            command=command,
            environment=environment
        )
        
        logger.info(f"Executed security tool: {tool_name}")
        return result
    
    def cleanup(self) -> None:
        """Clean up Docker resources."""
        if not self.docker_available:
            return
        
        try:
            import docker
            client = docker.from_env()
            
            containers = client.containers.list(
                all=True,
                filters={"status": "exited"}
            )
            
            for container in containers:
                try:
                    container.remove()
                except Exception:
                    pass
            
            logger.info("Cleaned up Docker containers")
        except Exception as e:
            logger.error(f"Docker cleanup failed: {e}")
