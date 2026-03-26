# utils/cli_theme.py

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# Professional color palette
THEME = {
    "info": "cyan",
    "success": "green",
    "warning": "yellow",
    "error": "red",
    "bold": "bold white",
    "muted": "bright_black"
}

def print_logo():
    logo = r"""
 ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
 ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
 ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝ 
 ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗ 
  ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
   ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═══╝   ╚══════╝╚═╝  ╚══╝
    Vortex - Offensive & Defensive Network Scanner
    """
    console.print(Panel(Text(logo, style="bold cyan"), border_style="blue", expand=False))

def print_info(message):
    console.print(f"[[{THEME['info']} bold]*[/]] {message}")

def print_success(message):
    console.print(f"[[{THEME['success']} bold]+[/]] {message}")

def print_warning(message):
    console.print(f"[[{THEME['warning']} bold]![/]] {message}")

def print_error(message):
    console.print(f"[[{THEME['error']} bold]-[/]] {message}")