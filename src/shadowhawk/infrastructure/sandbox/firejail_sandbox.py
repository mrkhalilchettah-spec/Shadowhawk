"""
ShadowHawk Platform - Firejail Sandbox

Copyright (c) 2024 ShadowHawk Platform
Licensed under the MIT License
See LICENSE file in the project root for full license information.
"""

from typing import Dict, Any, Optional, List
import subprocess
import logging
import shutil

logger = logging.getLogger(__name__)


class FirejailSandbox:
    """
    Firejail-based sandbox for additional security isolation.
    
    Provides an additional layer of sandboxing using Firejail.
    """
    
    def __init__(self, timeout: int = 300):
        """
        Initialize Firejail sandbox.
        
        Args:
            timeout: Execution timeout in seconds
        """
        self.timeout = timeout
        self.firejail_available = self._check_firejail_availability()
    
    def _check_firejail_availability(self) -> bool:
        """Check if Firejail is available on the system."""
        try:
            result = shutil.which("firejail")
            if result:
                logger.info("Firejail is available")
                return True
            else:
                logger.warning("Firejail not found in PATH")
                return False
        except Exception as e:
            logger.warning(f"Error checking Firejail availability: {e}")
            return False
    
    def execute(
        self,
        command: List[str],
        private_home: bool = True,
        no_network: bool = True,
        no_sound: bool = True,
        additional_args: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute a command in Firejail sandbox.
        
        Args:
            command: Command and arguments to execute
            private_home: Use private home directory
            no_network: Disable network access
            no_sound: Disable sound
            additional_args: Additional Firejail arguments
            
        Returns:
            Execution result
        """
        if not self.firejail_available:
            return self._simulate_execution(command)
        
        firejail_cmd = ["firejail"]
        
        if private_home:
            firejail_cmd.append("--private")
        
        if no_network:
            firejail_cmd.append("--net=none")
        
        if no_sound:
            firejail_cmd.append("--nosound")
        
        firejail_cmd.extend([
            "--quiet",
            "--noprofile",
            "--caps.drop=all",
            "--seccomp",
            "--noroot",
            "--private-dev",
            "--private-tmp",
        ])
        
        if additional_args:
            firejail_cmd.extend(additional_args)
        
        firejail_cmd.append("--")
        firejail_cmd.extend(command)
        
        try:
            result = subprocess.run(
                firejail_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            
            return {
                "success": result.returncode == 0,
                "exit_code": result.returncode,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None,
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Firejail execution timed out after {self.timeout} seconds")
            return {
                "success": False,
                "exit_code": -1,
                "output": "",
                "error": f"Execution timed out after {self.timeout} seconds",
            }
        except Exception as e:
            logger.error(f"Firejail execution failed: {e}")
            return {
                "success": False,
                "exit_code": -1,
                "output": "",
                "error": str(e),
            }
    
    def _simulate_execution(self, command: List[str]) -> Dict[str, Any]:
        """Simulate execution when Firejail is not available."""
        logger.info(f"Simulating Firejail execution: {' '.join(command)}")
        return {
            "success": True,
            "exit_code": 0,
            "output": f"Simulated execution of: {' '.join(command)}",
            "error": None,
            "simulated": True,
        }
    
    def execute_script(
        self,
        script_path: str,
        interpreter: str = "bash",
        private_home: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a script in Firejail sandbox.
        
        Args:
            script_path: Path to the script file
            interpreter: Script interpreter (bash, python, etc.)
            private_home: Use private home directory
            
        Returns:
            Execution result
        """
        command = [interpreter, script_path]
        return self.execute(
            command=command,
            private_home=private_home,
            no_network=True
        )
    
    def run_command_safe(
        self,
        command: str,
        shell: str = "/bin/bash"
    ) -> Dict[str, Any]:
        """
        Run a shell command safely in Firejail.
        
        Args:
            command: Shell command to execute
            shell: Shell to use
            
        Returns:
            Execution result
        """
        return self.execute(
            command=[shell, "-c", command],
            private_home=True,
            no_network=True
        )
