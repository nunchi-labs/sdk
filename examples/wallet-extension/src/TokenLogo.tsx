/**
 * Token logos.
 *
 * Coins with official artwork use the real mark, shipped under public/tokens
 * rather than hotlinked — a wallet should not phone a CDN every time the popup
 * opens, and local files need no host permission and work offline.
 *
 * Anything without official artwork (Hexy, or an unknown coin) falls back to a
 * generated geometric mark on a coloured disc. The same fallback covers an
 * image that fails to decode, so a row is never left blank.
 */
import { useState } from "react";
import { tokenByCoinId, type Token } from "./tokens";

const GLYPHS: Record<Token["glyph"], JSX.Element> = {
  hex: <path d="M16 6.5 24 11v10l-8 4.5L8 21V11z" />,
  diamond: <path d="M16 5.5 23 16l-7 4-7-4zM16 21.5 23 17.5 16 27 9 17.5z" />,
  ring: <path d="M16 6a10 10 0 1 0 0 20 10 10 0 0 0 0-20m0 5a5 5 0 1 1 0 10 5 5 0 0 1 0-10" />,
  bars: <path d="M9 11h14l-3.5 3.5H5.5zM9 16h14l-3.5 3.5H5.5zM9 21h14l-3.5 3.5H5.5z" />,
  orbit: (
    <>
      <circle cx="16" cy="16" r="9.5" fill="none" strokeWidth="2.5" stroke="currentColor" />
      <circle cx="16" cy="16" r="3.5" />
    </>
  ),
  chevrons: <path d="M16 5.5 26 16l-10 10.5L6 16zm0 5.5L11.5 16 16 21l4.5-5z" />,
  dollar: (
    <>
      <circle cx="16" cy="16" r="9.5" fill="none" strokeWidth="2.5" stroke="currentColor" />
      <path d="M15 8.5h2v15h-2z" />
      <path d="M12 12.5h8v2h-8zM12 17.5h8v2h-8z" />
    </>
  ),
  blocks: <path d="M8 8h7v7H8zM17 8h7v7h-7zM8 17h7v7H8zM17 17h7v7h-7z" />,
};

export function TokenLogo({ coinId, size = 40 }: { coinId?: string; size?: number }) {
  const token = coinId ? tokenByCoinId(coinId) : undefined;
  const [failed, setFailed] = useState<string | null>(null);
  const useArt = Boolean(token?.logo) && failed !== token?.coinId;

  // One stable wrapper for both cases. Returning a <span> for the glyph and an
  // <img> for the artwork made React unmount and remount on every change of
  // coin, so the new image painted blank for a frame — visible as a flash when
  // picking an asset. Keeping the element identity means only the contents swap.
  return (
    <span
      className={`tokenLogo ${useArt ? "" : "generated"}`}
      style={{
        width: size,
        height: size,
        background: useArt ? "transparent" : (token?.color ?? "#6e6e6e"),
      }}
      aria-hidden
    >
      {useArt ? (
        <img
          src={token!.logo}
          alt=""
          width={size}
          height={size}
          decoding="sync"
          onError={() => setFailed(token!.coinId)}
        />
      ) : (
        <svg viewBox="0 0 32 32" width={size * 0.62} height={size * 0.62} fill="currentColor">
          {token ? GLYPHS[token.glyph] : GLYPHS.ring}
        </svg>
      )}
    </span>
  );
}
