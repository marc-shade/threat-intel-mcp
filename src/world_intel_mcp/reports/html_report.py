"""HTML report renderer using Jinja2 templates.

Loads templates from the ``templates/`` subdirectory and renders them
with the provided context data.
"""

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("world-intel-mcp.reports.html_report")

_TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_template(template_name: str, context: dict) -> str:
    """Render a Jinja2 HTML template with the given context.

    Args:
        template_name: Name of the template file in ``templates/``.
        context: Dict of variables to pass to the template.

    Returns:
        Rendered HTML string.
    """
    template = _env.get_template(template_name)
    return template.render(**context)
