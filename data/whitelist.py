"""Hardcoded whitelist of top domains that are auto-allowed (no API call)."""

# Top legitimate domains — extend as needed.
# These NEVER hit the scoring API, resolving instantly.
WHITELIST = {
    # Search / portals
    "google.com", "www.google.com", "google.co.in",
    "bing.com", "www.bing.com",
    "yahoo.com", "www.yahoo.com",
    "duckduckgo.com",
    "baidu.com",

    # Big tech
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
    "github.com", "www.github.com",
    "gitlab.com",
    "stackoverflow.com",
    "openai.com", "chat.openai.com", "api.openai.com",

    # Social
    "facebook.com", "www.facebook.com",
    "twitter.com", "x.com",
    "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com",
    "reddit.com", "www.reddit.com",
    "youtube.com", "www.youtube.com",
    "tiktok.com",
    "whatsapp.com", "web.whatsapp.com",
    "discord.com",
    "telegram.org",

    # Cloud / CDN
    "cloudflare.com",
    "amazonaws.com",
    "azure.com", "portal.azure.com",
    "googleapis.com",
    "gstatic.com",
    "akamaized.net",
    "fastly.net",
    "cloudfront.net",

    # Email
    "outlook.com", "outlook.office365.com", "outlook.office.com",
    "gmail.com", "mail.google.com",

    # Dev tools
    "npmjs.com",
    "pypi.org",
    "docker.com",
    "visualstudio.com",
    "vscode.dev",

    # OS / updates
    "windowsupdate.com",
    "update.microsoft.com",
    "download.microsoft.com",

    # Media
    "netflix.com",
    "spotify.com",
    "twitch.tv",

    # Others
    "wikipedia.org", "en.wikipedia.org",
    "archive.org",
    "w3.org",
    "mozilla.org",
}


def is_whitelisted(domain: str) -> bool:
    """Check if domain (or its parent) is whitelisted."""
    domain = domain.lower().rstrip(".")
    if domain in WHITELIST:
        return True
    # Check parent domain: e.g. "docs.google.com" → "google.com"
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in WHITELIST:
            return True
    return False
