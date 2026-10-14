"""Quick Gemini connectivity check. Run:  python check_gemini.py   (never prints your key)"""
import time

from google import genai
from google.genai import types

from app.ai_service import thinking_for
from app.config import settings

if not settings.gemini_api_key:
    raise SystemExit("GEMINI_API_KEY is empty in backend/.env")

client = genai.Client(api_key=settings.gemini_api_key,
                      http_options=types.HttpOptions(timeout=60_000))
models = [settings.gemini_model, *settings.gemini_fallback_models]
for model in models:
    for name, cfg in {"app-settings": types.GenerateContentConfig(thinking_config=thinking_for(model))}.items():
        t = time.time()
        try:
            r = client.models.generate_content(model=model, contents="Reply with just: OK", config=cfg)
            print(f"OK    {model:28} {name:13} {time.time()-t:5.1f}s  -> {(r.text or '').strip()[:20]!r}")
        except Exception as e:
            code = getattr(e, "code", "")
            msg = " ".join(str(getattr(e, "message", None) or e).split())[:110]
            print(f"FAIL  {model:28} {name:13} {time.time()-t:5.1f}s  {type(e).__name__} {code}: {msg}")
try:
    names = [m.name.split("/")[-1] for m in client.models.list() if "flash" in m.name and "audio" not in m.name and "tts" not in m.name and "image" not in m.name]
    print("\nFlash models your key can use:", ", ".join(sorted(names)))
except Exception as e:
    print("\nCould not list models:", type(e).__name__, getattr(e, "code", ""))
