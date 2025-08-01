#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET

if len(sys.argv) != 3:
    print("Usage: coverage_badge.py <coverage.xml> <output.svg>")
    sys.exit(1)

xml_path, svg_path = sys.argv[1], sys.argv[2]

try:
    root = ET.parse(xml_path).getroot()
    line_rate = float(root.attrib.get("line-rate", 0.0))
except FileNotFoundError:
    line_rate = 0.0

percentage = line_rate * 100

if percentage >= 95:
    color = "#4c1"  # brightgreen
elif percentage >= 80:
    color = "#97CA00"  # green
elif percentage >= 70:
    color = "#dfb317"  # yellow
elif percentage >= 60:
    color = "#fe7d37"  # orange
else:
    color = "#e05d44"  # red

left_text = "coverage"
right_text = f"{percentage:.0f}%"


def text_width(text: str) -> int:
    return len(text) * 10 + 20


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
