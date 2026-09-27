# scanner_extensions.py

FRONTEND_EXTENSIONS = {
    ".html",
    ".htm",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".vue",
    ".svelte",
    ".css",
    ".scss",
}

BACKEND_EXTENSIONS = {
    ".py",
    ".php",
    ".go",
    ".java",
    ".kt",
    ".cs",
    ".rb",
}

TEMPLATE_EXTENSIONS = {
    ".blade.php",
    ".twig",
    ".ejs",
    ".hbs",
    ".handlebars",
}

CONFIG_EXTENSIONS = {
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".toml",
    ".ini",
}

IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".next",
    ".svelte-kit",
    "coverage",
}

SUPPORTED_EXTENSIONS = (
    FRONTEND_EXTENSIONS
    | BACKEND_EXTENSIONS
    | TEMPLATE_EXTENSIONS
    | CONFIG_EXTENSIONS
)