"""
Screenshot Module
Takes screenshots of target web pages using Playwright
"""

import os
import logging
from playwright.sync_api import sync_playwright


logger = logging.getLogger(__name__)


def take_screenshot(target, output_dir="screenshots", timeout=30000):
    """
    Take a full-page screenshot of a target URL.

    Strategy:
      - Try https:// first if scheme missing
      - If fails, try http://
      - Log the real error (so we can debug instead of returning None silently)

    Args:
        target (str): Target URL or host (domain/IP)
        output_dir (str): Directory to save screenshots
        timeout (int): Page load timeout in milliseconds

    Returns:
        str | None: Path to screenshot if successful, else None
    """

    os.makedirs(output_dir, exist_ok=True)

    # Build candidate URLs (try https then http if scheme is missing)
    candidates = []
    if target.startswith(("http://", "https://")):
        candidates.append(target)
    else:
        candidates.append(f"https://{target}")
        candidates.append(f"http://{target}")

    # A safe filename base (strip scheme + replace slashes)
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
                ignore_https_errors=True,  # مهم لو SSL فيه مشاكل
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            )
            page = context.new_page()

            for url in candidates:
                screenshot_path = os.path.join(output_dir, f"{_safe_name(url)}.png")
                try:
                    logger.info(f"Screenshot: trying {url}")

                    # domcontentloaded أسرع من networkidle وأقل فشلًا مع المواقع الثقيلة
                    page.goto(url, timeout=timeout, wait_until="domcontentloaded")

                    # انتظري شوية للـ JS يرسم المحتوى
                    page.wait_for_timeout(1500)

                    page.screenshot(path=screenshot_path, full_page=True)
                    logger.info(f"Screenshot saved: {screenshot_path}")

                    context.close()
                    browser.close()
                    return screenshot_path

                except Exception as e:
                    logger.warning(f"Screenshot failed for {url}: {e}")
                    # جرّبي URL اللي بعده (https -> http)

            # كل المحاولات فشلت
            context.close()
            browser.close()
            return None

    except Exception as e:
        logger.error(f"Screenshot module fatal error: {e}")
        return None
