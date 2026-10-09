"""Map display names to npm packages."""

ALIASES = {
    "react": "react",
    "react.js": "react",
    "vue": "vue",
    "vue.js": "vue",
    "angular": "@angular/core",
    "next": "next",
    "next.js": "next",
    "express": "express",
    "express.js": "express",
    "jquery": "jquery",
    "lodash": "lodash",
    "moment": "moment",
    "axios": "axios",
    "bootstrap": "bootstrap",
    "webpack": "webpack",
    "babel": "@babel/core",
    "typescript": "typescript",
}


def resolve_alias(name: str) -> str | None:
    """Resolve a display name to an npm package."""
    if not name:
        return None
    lower = name.lower().strip()
    return ALIASES.get(lower, lower if lower in ALIASES.values() else None)
