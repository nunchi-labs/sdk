/**
 * The Nunchi mark: one continuous stroke that runs up the outer arch, spirals
 * inward, and stops at the inner tail. Drawn as vector geometry so it stays
 * crisp at any size, and stroked in `currentColor` so callers set the colour.
 *
 * Coordinates live in an 80x90 "mark space" with a 10-unit stroke; the same
 * path drives the extension icons (see brand/build-icons.sh).
 */
export const MARK_PATH =
  "M 5 90 L 5 40 A 35 35 0 0 1 75 40 L 75 73.5 A 8.5 8.5 0 0 1 58 73.5 " +
  "L 58 40 A 18 18 0 0 0 22 40 L 22 69.5 A 10.5 10.5 0 0 0 43 69.5";

export function BrandMark({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 80 90" fill="none" role="img" aria-label="Nunchi">
      <path d={MARK_PATH} stroke="currentColor" strokeWidth={10} strokeLinejoin="round" />
    </svg>
  );
}
