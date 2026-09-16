"""Generate app/tray icons from the university emblem supplied by the user.
Manual asset tool: requires Pillow (python -m pip install Pillow).
Cargo embeds the checked-in ICO; end users need no Python dependencies.
Source: https://www.yzu.edu.cn/__local/1/9C/B7/D2DA849218454F5605A81A3A442_5795DDB8_117BF.jpg?e=.jpg
"""
from pathlib import Path
import base64
import io
import math

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent
SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def emblem():
    # Left-hand official green mark only; exclude the red variant and captions.
    source = Image.open(ROOT / "yzu-emblem-source.jpg").convert("RGB")
    crop = source.crop((16, 26, 164, 175))
    alpha = Image.new("L", crop.size)
    # Green chroma separates the printed mark from its white background.
    # Recover edge coverage instead of thresholding away the fine globe lines.
    alpha.putdata([
        round(255 * min(1, max(0, (g - r) / 104)))
        for r, g, b in (crop.getpixel((x, y))
                        for y in range(crop.height) for x in range(crop.width))
    ])
    mark = Image.new("RGBA", crop.size, (255, 255, 255, 0))
    mark.putalpha(alpha)
    return mark


def main():
    mark = emblem()
    scale = 4
    size = 256 * scale
    image = Image.new("RGBA", (size, size))
    pixels = image.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * (size - 1))
            pixels[x, y] = tuple(round(a * (1 - t) + b * t)
                                for a, b in zip((56, 195, 137), (0, 91, 60))) + (255,)
    mask = Image.new("L", (size, size))
    ImageDraw.Draw(mask).rounded_rectangle((4 * scale, 4 * scale, 252 * scale - 1, 252 * scale - 1),
                                          radius=52 * scale, fill=255)
    image.putalpha(mask)
    # Keep the university mark intact and separate the Wi-Fi glyph above it.
    image.alpha_composite(mark.resize((148 * scale, 149 * scale), Image.Resampling.LANCZOS),
                          (54 * scale, 74 * scale))
    draw = ImageDraw.Draw(image)
    for radius in (29, 18):
        points = [(scale * (128 + radius * math.cos(math.radians(angle))),
                   scale * (62 + radius * math.sin(math.radians(angle))))
                  for angle in range(225, 316)]
        draw.line(points, fill="white", width=4 * scale, joint="curve")
        for x, y in (points[0], points[-1]):
            draw.ellipse((x - 2 * scale, y - 2 * scale, x + 2 * scale, y + 2 * scale), fill="white")
    draw.ellipse((125 * scale, 56 * scale, 131 * scale, 62 * scale), fill="white")
    preview = image.resize((256, 256), Image.Resampling.LANCZOS)
    preview.save(ROOT / "campus-link.png")
    preview.save(ROOT / "campus-link.ico", sizes=[(s, s) for s in SIZES], bitmap_format="bmp")
    buffer = io.BytesIO()
    mark.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256" role="img" aria-labelledby="title desc">
  <title id="title">Campus Link · 扬大校园网</title>
  <desc id="desc">绿色渐变背景、白色扬州大学校徽与无线网络标识。第三方校园网客户端，非学校官方应用。</desc>
  <defs><linearGradient id="green" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#38c389"/><stop offset="1" stop-color="#005b3c"/></linearGradient></defs>
  <rect x="4" y="4" width="248" height="248" rx="52" fill="url(#green)"/>
  <image x="54" y="74" width="148" height="149" href="data:image/png;base64,{encoded}"/>
  <g fill="none" stroke="white" stroke-width="4" stroke-linecap="round">
    <path d="M107.494 41.494 A29 29 0 0 1 148.506 41.494 M115.272 49.272 A18 18 0 0 1 140.728 49.272"/>
  </g>
  <circle cx="128" cy="59" r="3" fill="white"/>
</svg>
'''
    (ROOT / "campus-link.svg").write_text(svg, encoding="utf-8")


if __name__ == "__main__":
    main()
