import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ImageResponse } from 'next/og';

const fontDir = join(process.cwd(), 'node_modules/@fontsource');
let fonts: Promise<{ display: Buffer; sans: Buffer; sansBold: Buffer }> | undefined;

function loadFonts() {
  fonts ??= Promise.all([
    readFile(join(fontDir, 'shippori-mincho-b1/files/shippori-mincho-b1-japanese-800-normal.woff')),
    readFile(join(fontDir, 'zen-kaku-gothic-new/files/zen-kaku-gothic-new-latin-400-normal.woff')),
    readFile(join(fontDir, 'zen-kaku-gothic-new/files/zen-kaku-gothic-new-latin-700-normal.woff')),
  ]).then(([display, sans, sansBold]) => ({ display, sans, sansBold }));
  return fonts;
}

let mark: Promise<string> | undefined;

function loadMark() {
  mark ??= readFile(join(process.cwd(), 'public/brand/mark.svg'), 'utf8').then(
    (svg) => `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`,
  );
  return mark;
}

const seigaiha = `data:image/svg+xml;base64,${Buffer.from(
  `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="96" viewBox="0 0 1200 96"><defs><pattern id="p" width="48" height="24" patternUnits="userSpaceOnUse"><g id="s"><circle r="24" fill="#f6f0e4"/><g fill="none" stroke="#c53a2b" stroke-width="1.2"><circle r="22.5"/><circle r="17"/><circle r="11.5"/><circle r="6"/></g></g><use href="#s" x="48" y="-12"/><use href="#s" x="0" y="-12" /><use href="#s" x="24" y="0"/><use href="#s" x="0" y="12"/><use href="#s" x="48" y="12"/><use href="#s" x="24" y="24"/><use href="#s" x="0" y="36"/><use href="#s" x="48" y="36"/></pattern></defs><rect width="1200" height="96" fill="url(#p)"/></svg>`,
).toString('base64')}`;

export async function renderOgImage({ title, description, eyebrow }: { title: string; description?: string; eyebrow?: string }) {
  const [{ display, sans, sansBold }, markSrc] = await Promise.all([loadFonts(), loadMark()]);

  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          background: '#f6f0e4',
          color: '#1f1a15',
          position: 'relative',
          fontFamily: 'Zen Kaku Gothic New',
        }}
      >
        <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 8, background: '#c53a2b', display: 'flex' }} />
        <div
          style={{
            position: 'absolute',
            right: 40,
            top: 40,
            fontFamily: 'Shippori Mincho B1',
            fontSize: 360,
            lineHeight: 1,
            color: 'rgba(197,58,43,0.08)',
            display: 'flex',
          }}
        >
          関
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', padding: '72px 80px 0', flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={markSrc} width={72} height={72} alt="" />
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 14 }}>
              <span style={{ fontFamily: 'Shippori Mincho B1', fontSize: 40 }}>Sekisho</span>
              <span style={{ fontFamily: 'Shippori Mincho B1', fontSize: 30, color: '#c53a2b' }}>関所</span>
            </div>
          </div>
          <div
            style={{
              marginTop: 56,
              fontSize: 22,
              letterSpacing: 6,
              textTransform: 'uppercase',
              color: '#6b5d4b',
              display: 'flex',
              fontWeight: 700,
            }}
          >
            {eyebrow ?? 'Documentation'}
          </div>
          <div
            style={{
              marginTop: 12,
              fontFamily: 'Shippori Mincho B1',
              fontSize: title.length > 28 ? 64 : 80,
              lineHeight: 1.1,
              maxWidth: 940,
              display: 'flex',
            }}
          >
            {title}
          </div>
          {description ? (
            <div style={{ marginTop: 24, fontSize: 28, lineHeight: 1.5, color: '#4a3f33', maxWidth: 900, display: 'flex' }}>
              {description}
            </div>
          ) : null}
        </div>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={seigaiha} width={1200} height={96} alt="" style={{ opacity: 0.35 }} />
      </div>
    ),
    {
      width: 1200,
      height: 630,
      fonts: [
        { name: 'Shippori Mincho B1', data: display, weight: 800, style: 'normal' },
        { name: 'Zen Kaku Gothic New', data: sans, weight: 400, style: 'normal' },
        { name: 'Zen Kaku Gothic New', data: sansBold, weight: 700, style: 'normal' },
      ],
    },
  );
}
