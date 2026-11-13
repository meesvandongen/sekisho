import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { Mark } from '@/components/logo';
import { githubUrl } from '@/lib/shared';

/** Hero banner for the introduction page. */
export function GateHero() {
  return (
    <div className="not-prose relative my-8 overflow-hidden rounded-sm border border-fd-border bg-fd-card">
      <div
        aria-hidden
        className="seigaiha pointer-events-none absolute inset-0 opacity-20 [mask-image:linear-gradient(100deg,transparent_35%,black)]"
      />
      <div className="relative grid items-center gap-8 p-7 sm:grid-cols-[1fr_auto] sm:p-9">
        <div>
          <p className="flex items-center gap-3 text-xs tracking-[0.2em] text-fd-muted-foreground uppercase">
            <span className="h-px w-6 bg-shu" />
            <span lang="ja" className="font-display font-extrabold tracking-[0.3em] text-shu normal-case">
              関所
            </span>
            OIDC policy gateway
          </p>
          <p className="mt-4 font-display text-3xl leading-tight font-extrabold tracking-tight sm:text-4xl">
            Every request passes the <span className="text-shu">gate</span>.
          </p>
          <div className="mt-6 flex flex-wrap gap-3 text-sm">
            <Link href="/quickstart" className="btn-shu">
              Quickstart <ArrowRight className="size-4" />
            </Link>
            <a href={githubUrl} className="btn-ghost" rel="noreferrer">
              GitHub
            </a>
          </div>
        </div>
        <div className="relative hidden size-36 items-center justify-center sm:flex">
          <div aria-hidden className="absolute inset-0 rounded-full bg-shu/10 ring-1 ring-shu/20" />
          <Mark className="stamp-in relative w-24 -rotate-[4deg] drop-shadow-[0_12px_20px_rgb(120_40_20/0.35)]" />
          <span
            aria-hidden
            lang="ja"
            className="vertical-ja absolute top-0 -right-6 text-xs tracking-[0.4em] text-fd-muted-foreground"
          >
            通行手形改め
          </span>
        </div>
      </div>
    </div>
  );
}

const stations = [
  {
    kanji: '経路',
    reading: 'keiro',
    title: 'Route',
    body: 'The path and method must exist in your OpenAPI spec, used as a strict allowlist.',
    code: 'route_not_found',
  },
  {
    kanji: '手形',
    reading: 'tegata',
    title: 'Verify',
    body: 'The bearer JWT is the travel pass: signature, issuer, audience, expiry and algorithm.',
    code: 'auth_invalid',
  },
  {
    kanji: '権限',
    reading: 'kengen',
    title: 'Scope',
    body: 'Scopes declared by every matching binding are checked before any policy runs.',
    code: 'insufficient_scope',
  },
  {
    kanji: '規則',
    reading: 'kisoku',
    title: 'Policy',
    body: 'Reusable CEL rules composed with all, any and not — evaluated lazily.',
    code: 'policy_denied',
  },
  {
    kanji: '札',
    reading: 'fuda',
    title: 'Credential',
    body: 'A least-privilege backend token for this route, via client credentials or token exchange.',
    code: 'backend_token_unavailable',
  },
  {
    kanji: '通過',
    reading: 'tsūka',
    title: 'Forward',
    body: 'Streamed to the upstream. The caller’s token is passed on only where a route opts in.',
    code: 'forwarded',
  },
];

/** The six checks every request passes, drawn as stations on a road. */
export function Stations() {
  return (
    <ol className="not-prose my-8 grid gap-px overflow-hidden rounded-sm border border-fd-border bg-fd-border sm:grid-cols-2 lg:grid-cols-3">
      {stations.map((s, i) => (
        <li key={s.title} className="relative flex gap-4 bg-fd-card p-5">
          <span className={`hanko size-12 shrink-0 ${s.kanji.length === 1 ? 'text-xl' : 'text-base'}`} lang="ja">
            {s.kanji}
          </span>
          <div className="min-w-0">
            <p className="text-[0.68rem] tracking-[0.2em] text-fd-muted-foreground uppercase">
              {String(i + 1).padStart(2, '0')} · <span className="normal-case italic">{s.reading}</span>
            </p>
            <p className="font-display text-lg font-extrabold">{s.title}</p>
            <p className="mt-1 text-sm leading-relaxed text-fd-muted-foreground">{s.body}</p>
            <code className="mt-2 inline-block max-w-full break-all rounded-sm border border-fd-border bg-fd-background px-1.5 py-0.5 font-mono text-[0.68rem] text-shu">
              {s.code}
            </code>
          </div>
        </li>
      ))}
    </ol>
  );
}
