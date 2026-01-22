"""
Screenshot Module
Takes screenshots of target web pages using Playwright
"""

import os
import logging
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)


def take_screenshot(target, output_dir="screenshots", timeout=60000):
    """
    Take a full-page screenshot of a target URL.

    Fix:
      - Create a NEW page per attempt to avoid "chrome-error://chromewebdata/" interfering
    """

    os.makedirs(output_dir, exist_ok=True)

    # Build candidate URLs (ensure https -> http fallback even if scheme is provided)
    if target.startswith("https://"):
        candidates = [target, "http://" + target[len("https://"):]]
    elif target.startswith("http://"):
        candidates = [target]
    else:
        candidates = [f"https://{target}", f"http://{target}"]

    def _safe_name(url: str) -> str:
        return (
            url.replace("https://", "")
               .replace("http://", "")
               .replace("/", "_")
               .replace(":", "_")
        )

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
            )

            for url in candidates:
                screenshot_path = os.path.join(output_dir, f"{_safe_name(url)}.png")

                # ✅ New page per attempt (important)
                page = context.new_page()
                try:
                    logger.info(f"Screenshot: trying {url}")

                    page.goto(url, timeout=timeout, wait_until="load")
                    page.wait_for_timeout(1500)

                    page.screenshot(path=screenshot_path, full_page=True)
                    logger.info(f"Screenshot saved: {screenshot_path}")

                    page.close()
                    context.close()
                    browser.close()
                    return screenshot_path

                except Exception as e:
                    logger.warning(f"Screenshot failed for {url}: {e}")
                    try:
                        page.close()
                    except Exception:
                        pass
                    # try next candidate

            context.close()
            browser.close()
            return None

    except Exception as e:
        logger.error(f"Screenshot module fatal error: {e}")
        return None
