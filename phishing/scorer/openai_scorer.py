"""OpenAI-based URL phishing scorer."""

from openai import AsyncOpenAI
import json
import config

client = AsyncOpenAI(api_key=config.OPENAI_API_KEY)

SYSTEM_PROMPT = """You are a cybersecurity expert that analyzes URLs for phishing indicators.

Given a URL, analyze it for these phishing signals:
1. Domain lookalike (e.g., paypa1.com mimicking paypal.com, g00gle.com mimicking google.com)
2. Suspicious TLD (.xyz, .tk, .ml, .ga, .cf — commonly abused free TLDs)
3. Excessive subdomains (secure.login.verify.evil.com)
4. IP address as hostname
5. Unusual URL length or special characters (@, %, encoded chars)
6. Brand impersonation in path or subdomain
7. Known suspicious patterns (login, verify, secure, account, update in URL)
8. Unicode/homograph characters in domain

Respond ONLY with valid JSON in this exact format:
{"score": <float 0.0 to 1.0>, "reasons": ["reason1", "reason2"]}

Score meaning:
- 0.0-0.3: Clearly legitimate (well-known brand, normal structure)
- 0.3-0.7: Uncertain (some suspicious signals but not conclusive)
- 0.7-1.0: Likely phishing (multiple strong indicators)

Be conservative: only score > 0.7 if there are clear phishing indicators.
Well-known domains like google.com, github.com, microsoft.com should score < 0.1."""


async def score_url(url: str) -> dict:
    """Score a URL for phishing probability using OpenAI.

    Returns: {"score": float, "reasons": list[str], "error": None}
    """
    try:
        response = await client.chat.completions.create(
            model=config.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this URL: {url}"},
            ],
            temperature=0.1,
            max_tokens=300,
        )
        content = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            content = content.rsplit("```", 1)[0].strip()

        result = json.loads(content)
        return {
            "score": float(result["score"]),
            "reasons": result.get("reasons", []),
            "error": None,
        }
    except json.JSONDecodeError:
        return {"score": 0.5, "reasons": ["LLM returned invalid JSON"], "error": "parse_error"}
    except Exception as e:
        return {"score": 0.0, "reasons": [], "error": str(e)}
