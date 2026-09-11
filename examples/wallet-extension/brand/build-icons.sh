#!/usr/bin/env bash
# Regenerates public/icon-*.png from the vector mark in logo.svg.
# Requires librsvg:  brew install librsvg
set -euo pipefail
cd "$(dirname "$0")"
out=../public

# The mark's centerline path, drawn in an 80x90 "mark space" with a 10-unit stroke.
PATH_D="M 5 90 L 5 40 A 35 35 0 0 1 75 40 L 75 73.5 A 8.5 8.5 0 0 1 58 73.5 L 58 40 A 18 18 0 0 0 22 40 L 22 69.5 A 10.5 10.5 0 0 0 43 69.5"

# size  corner-radius  padding  stroke(mark units)
# Stroke is nudged up at small sizes so the counters survive rasterisation.
render() {
  local size=$1 rx=$2 pad=$3 sw=$4
  python3 -c "
size, pad, sw = $size, $pad, $sw
ink_h = size - 2*pad
k = ink_h / 90.0
tx = (size - 80*k) / 2.0
print(f'''<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{size}\" height=\"{size}\" viewBox=\"0 0 {size} {size}\" fill=\"none\">
  <rect width=\"{size}\" height=\"{size}\" rx=\"$rx\" fill=\"#FFF9F4\"/>
  <g transform=\"translate({tx:.3f},{pad}) scale({k:.5f})\">
    <path d=\"$PATH_D\" stroke=\"#0B0B0F\" stroke-width=\"{sw}\" stroke-linejoin=\"round\"/>
  </g>
</svg>''')" > "/tmp/nunchi-icon-$size.svg"
  rsvg-convert -w "$size" -h "$size" "/tmp/nunchi-icon-$size.svg" -o "$out/icon-$size.png"
  rm -f "/tmp/nunchi-icon-$size.svg"
  echo "  wrote $out/icon-$size.png"
}

render 16  3.5 1.0 10
render 32  7   3   12
render 48  10  5   11
render 128 28  18  10
