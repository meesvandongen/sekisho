import type { Metadata, Viewport } from 'next';
import { Provider } from '@/components/provider';
import { appName, siteUrl } from '@/lib/shared';
import '@fontsource/shippori-mincho-b1/600.css';
import '@fontsource/shippori-mincho-b1/800.css';
import '@fontsource/zen-kaku-gothic-new/400.css';
import '@fontsource/zen-kaku-gothic-new/700.css';
import '@fontsource-variable/jetbrains-mono/index.css';
import './global.css';

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: {
    default: `${appName} 関所 — OIDC policy gateway`,
    template: `%s · ${appName}`,
  },
  description:
    'Sekisho is an OIDC-aware policy gateway: it verifies inbound JWTs, binds every OpenAPI operation to an explicit CEL policy, and forwards only what you allow.',
  openGraph: {
    siteName: appName,
    type: 'website',
    images: '/og/home.png',
  },
  twitter: { card: 'summary_large_image' },
};

export const viewport: Viewport = {
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#F6F0E4' },
    { media: '(prefers-color-scheme: dark)', color: '#14120F' },
  ],
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex min-h-screen flex-col">
        <Provider>{children}</Provider>
      </body>
    </html>
  );
}
