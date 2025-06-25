#!/usr/bin/env python3
import re
import sys

if len(sys.argv) != 3:
    print("Usage: pylint_badge.py <pylint.log> <output.svg>")
    sys.exit(1)

log_path, svg_path = sys.argv[1], sys.argv[2]

try:
    text = open(log_path).read()
except FileNotFoundError:
    text = ""

m = re.search(r"rated at ([0-9.]+)/10", text)
score = float(m.group(1)) if m else 0.0

if score >= 9.5:
    color = "#4c1"  # brightgreen
elif score >= 8:
    color = "#97CA00"  # green
elif score >= 7:
    color = "#dfb317"  # yellow
elif score >= 6:
    color = "#fe7d37"  # orange
else:
    color = "#e05d44"  # red

left_text = "pylint"
right_text = f"{score:.2f}/10"

def text_width(text: str) -> int:
    return len(text) * 7 + 10

left_width = text_width(left_text)
right_width = text_width(right_text)
width = left_width + right_width

svg = f"""<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='20'>
  <linearGradient id='b' x2='0' y2='100%'>
    <stop offset='0' stop-color='#bbb' stop-opacity='.1'/>
    <stop offset='1' stop-opacity='.1'/>
  </linearGradient>
  <mask id='a'>
    <rect width='{width}' height='20' rx='3' fill='#fff'/>
  </mask>
  <g mask='url(#a)'>
    <rect width='{left_width}' height='20' fill='#555'/>
    <rect x='{left_width}' width='{right_width}' height='20' fill='{color}'/>
    <rect width='{width}' height='20' fill='url(#b)'/>
  </g>
  <g fill='#fff' text-anchor='middle' font-family='Verdana' font-size='110'>
    <text x='{left_width/2:.0f}' y='150' fill='#010101' fill-opacity='.3' transform='scale(.1)' textLength='{len(left_text)*100}'>{left_text}</text>
    <text x='{left_width/2:.0f}' y='140' transform='scale(.1)' textLength='{len(left_text)*100}'>{left_text}</text>
    <text x='{left_width + right_width/2:.0f}' y='150' fill='#010101' fill-opacity='.3' transform='scale(.1)' textLength='{len(right_text)*100}'>{right_text}</text>
    <text x='{left_width + right_width/2:.0f}' y='140' transform='scale(.1)' textLength='{len(right_text)*100}'>{right_text}</text>
  </g>
</svg>
"""

with open(svg_path, "w") as f:
    f.write(svg)
