import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { ServerCodeBlock } from 'fumadocs-ui/components/codeblock.rsc';
import { Mark } from '@/components/logo';
import { githubUrl } from '@/lib/shared';

const stations = [
  {
    kanji: '経路',
    reading: 'keiro',
    title: 'Route',
    body: 'The path and method must exist in your OpenAPI spec. Everything else is turned away.',
    code: 'route_not_found',
  },
  {
    kanji: '手形',
    reading: 'tegata',
    title: 'Verify',
    body: 'The bearer JWT is your travel pass: signature, issuer, audience, expiry and algorithm.',
    code: 'auth_invalid',
  },
  {
    kanji: '権限',
    reading: 'kengen',
    title: 'Scope',
    body: 'Required scopes are checked before any policy runs — no wasted lookups.',
    code: 'insufficient_scope',
  },
  {
    kanji: '規則',
    reading: 'kisoku',
    title: 'Policy',
    body: 'Composable CEL rules over claims, query, body and identity — evaluated lazily.',
    code: 'policy_denied',
  },
  {
    kanji: '札',
    reading: 'fuda',
    title: 'Credential',
    body: 'A least-privilege backend token for this route. The caller’s token never travels on.',
    code: 'backend_token_unavailable',
  },
  {
    kanji: '通過',
    reading: 'tsūka',
    title: 'Forward',
    body: 'Streamed to your upstream, with an audit record and trace at the gate.',
    code: 'forwarded',
  },
];

const features = [
  {
    kanji: '明',
    title: 'Explicit by construction',
    body: 'Every OpenAPI operation needs exactly one binding. Missing, duplicate or unknown bindings stop startup — there is no permissive fallback.',
  },
  {
    kanji: '組',
    title: 'Composable CEL',
    body: 'Reusable named rules with parameters, combined with all, any and not. Compiled and type-checked once at startup.',
  },
  {
    kanji: '鍵',
    title: 'Least-privilege upstream',
    body: 'Client credentials or RFC 8693 token exchange, per route. Read traffic never carries a write token.',
  },
  {
    kanji: '省',
    title: 'Lazy by default',
    body: 'Bodies, userinfo and introspection are fetched only when a selected branch needs them. Everything else streams.',
  },
  {
    kanji: '試',
    title: 'Testable offline',
    body: 'Run the compiled policies against JSON fixtures in CI — no issuer, network or secrets required.',
  },
  {
    kanji: '記',
    title: 'Observable',
    body: 'Stable outcome codes, a structured audit trail and compile-time OpenTelemetry instrumentation.',
  },
];

const binding = `{
  "name": "publish_item",
  "match": { "operation_id": "createItem" },
  "check": { "all": [
    { "ref": "publisher", "params": { "subject": "alice" } },
    { "cel": "body.amount <= params.max" }
  ]},
  "params": { "max": 5 },
  "auth": { "backend": "write", "required_scopes": ["items:write"] },
  "on_deny": {
    "response": { "status": 403, "code": "package_denied" }
  }
}`;

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col">
      <Hero />
      <Road />
      <Features />
      <Showcase />
      <Closing />
    </main>
  );
}

function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div
        aria-hidden
        className="seigaiha pointer-events-none absolute inset-x-0 bottom-0 h-48 opacity-25 [mask-image:linear-gradient(to_top,black,transparent)]"
      />
      <div className="relative mx-auto grid w-full max-w-6xl items-center gap-12 px-6 pt-16 pb-24 md:pt-24 lg:grid-cols-[1.25fr_1fr]">
        <div>
          <p className="mb-6 inline-flex items-center gap-3 text-sm tracking-[0.2em] text-fd-muted-foreground uppercase">
            <span className="h-px w-8 bg-shu" />
            <span lang="ja" className="font-display font-extrabold tracking-[0.3em] text-shu normal-case">
              関所
            </span>
            OIDC policy gateway
          </p>
          <h1 className="font-display text-5xl leading-[1.05] font-extrabold tracking-tight md:text-7xl">
            Every request
            <br />
            passes the <span className="text-shu">gate</span>.
          </h1>
          <p className="mt-7 max-w-xl text-lg leading-relaxed text-fd-muted-foreground">
            Sekisho verifies inbound JWTs, binds every OpenAPI operation to an explicit CEL policy, and forwards only
            what you allow — with least-privilege credentials upstream.
          </p>
          <div className="mt-9 flex flex-wrap gap-3">
            <Link href="/docs" className="btn-shu">
              Read the docs <ArrowRight className="size-4" />
            </Link>
            <Link href="/docs/quickstart" className="btn-ghost">
              Quickstart
            </Link>
            <a href={githubUrl} className="btn-ghost" rel="noreferrer">
              GitHub
            </a>
          </div>
        </div>

        <div className="relative mx-auto flex aspect-square w-full max-w-sm items-center justify-center">
          <div aria-hidden className="absolute inset-[6%] rounded-full bg-shu/10 ring-1 ring-shu/20" />
          <div aria-hidden className="absolute inset-[18%] rounded-full border border-dashed border-shu/30" />
          <Mark className="stamp-in relative w-[58%] -rotate-[4deg] drop-shadow-[0_18px_30px_rgb(120_40_20/0.35)]" />
          <span
            aria-hidden
            lang="ja"
            className="vertical-ja absolute top-[8%] right-0 text-sm tracking-[0.5em] text-fd-muted-foreground"
          >
            通行手形改め
          </span>
          <span
            aria-hidden
            lang="ja"
            className="vertical-ja absolute bottom-[8%] left-0 text-sm tracking-[0.5em] text-shu/70"
          >
            関守在番
          </span>
        </div>
      </div>
    </section>
  );
}

function Road() {
  return (
    <section className="relative border-y border-fd-border bg-fd-card/60">
      <div className="mx-auto w-full max-w-6xl px-6 py-20">
        <SectionHeading kanji="道中" eyebrow="The road through the gate">
          Six stations, one direction.
        </SectionHeading>
        <p className="mt-4 max-w-2xl text-fd-muted-foreground">
          Each request travels the same road. A traveller who fails a station is turned back with a stable outcome
          code — and nothing reaches your upstream.
        </p>

        <ol className="relative mt-14 grid gap-10 md:grid-cols-3 lg:grid-cols-6 lg:gap-6">
          <div aria-hidden className="station-road absolute top-7 right-8 left-8 hidden lg:block" />
          {stations.map((s, i) => (
            <li key={s.title} className="relative flex gap-4 lg:flex-col lg:gap-0">
              <div className="relative z-10 flex shrink-0 flex-col items-start">
                <span
                  className={`hanko size-14 text-lg ${s.kanji.length === 1 ? 'text-2xl' : ''} ${i === stations.length - 1 ? '' : ''}`}
                  lang="ja"
                >
                  {s.kanji}
                </span>
              </div>
              <div className="lg:mt-5">
                <p className="text-xs tracking-[0.2em] text-fd-muted-foreground uppercase">
                  {String(i + 1).padStart(2, '0')} · <span className="normal-case italic">{s.reading}</span>
                </p>
                <h3 className="mt-1 font-display text-xl font-extrabold">{s.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-fd-muted-foreground">{s.body}</p>
                <code className="mt-3 inline-block rounded-sm border border-fd-border bg-fd-background px-1.5 py-0.5 font-mono text-[0.7rem] text-shu">
                  {s.code}
                </code>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}

function Features() {
  return (
    <section className="mx-auto w-full max-w-6xl px-6 py-24">
      <SectionHeading kanji="心得" eyebrow="Principles">
        Built like a checkpoint, not a turnstile.
      </SectionHeading>
      <div className="mt-12 grid gap-px overflow-hidden rounded-sm border border-fd-border bg-fd-border sm:grid-cols-2 lg:grid-cols-3">
        {features.map((f) => (
          <div key={f.title} className="group relative overflow-hidden bg-fd-background p-7">
            <span
              aria-hidden
              lang="ja"
              className="pointer-events-none absolute -right-3 -bottom-6 font-display text-[7.5rem] leading-none font-extrabold text-fd-foreground/[0.045] transition-colors duration-300 group-hover:text-shu/15"
            >
              {f.kanji}
            </span>
            <h3 className="relative flex items-center gap-2.5 font-display text-lg font-extrabold">
              <span aria-hidden className="size-2 rotate-45 bg-shu" />
              {f.title}
            </h3>
            <p className="relative mt-3 text-sm leading-relaxed text-fd-muted-foreground">{f.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function Showcase() {
  return (
    <section className="relative overflow-hidden border-y border-fd-border bg-fd-card/60">
      <div className="mx-auto grid w-full max-w-6xl items-center gap-12 px-6 py-24 lg:grid-cols-[1fr_1.15fr]">
        <div>
          <SectionHeading kanji="掟" eyebrow="Rules of the gate">
            Policies that read like the notice board.
          </SectionHeading>
          <ul className="mt-8 space-y-4 text-fd-muted-foreground">
            {[
              ['Bind', 'by operationId, or by path template and method.'],
              ['Compose', 'named rules with parameters; short-circuit with all and any.'],
              ['Deny', 'with your own status, code and audit reason — never caller input.'],
              ['Select', 'the narrowest backend credential for the route.'],
            ].map(([k, v]) => (
              <li key={k} className="flex gap-3">
                <span aria-hidden className="mt-2.5 size-1.5 shrink-0 rotate-45 bg-shu" />
                <span>
                  <strong className="font-display text-fd-foreground">{k}</strong> {v}
                </span>
              </li>
            ))}
          </ul>
          <Link href="/docs/policies" className="btn-ghost mt-9">
            Writing policies <ArrowRight className="size-4" />
          </Link>
        </div>
        <div className="relative">
          <div aria-hidden className="absolute -inset-4 -rotate-1 rounded-sm border border-shu/25" />
          <ServerCodeBlock
            code={binding}
            lang="json"
            themes={{ light: 'kanagawa-lotus', dark: 'kanagawa-dragon' }}
            codeblock={{ title: 'config.json · policy.routes[]', className: 'my-0 relative' }}
          />
        </div>
      </div>
    </section>
  );
}

function Closing() {
  return (
    <section className="relative overflow-hidden">
      <div
        aria-hidden
        className="seigaiha pointer-events-none absolute inset-0 opacity-20 [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]"
      />
      <div className="relative mx-auto flex w-full max-w-3xl flex-col items-center px-6 py-28 text-center">
        <span className="hanko size-16 text-2xl" lang="ja">
          通
        </span>
        <h2 className="mt-8 font-display text-4xl font-extrabold tracking-tight md:text-5xl">
          Raise the barrier only for a valid pass.
        </h2>
        <p className="mt-5 max-w-xl text-fd-muted-foreground">
          Build the gateway, bind your first route, and test it offline in a few minutes.
        </p>
        <div className="mt-9 flex flex-wrap justify-center gap-3">
          <Link href="/docs/quickstart" className="btn-shu">
            Start the quickstart <ArrowRight className="size-4" />
          </Link>
          <Link href="/docs/configuration" className="btn-ghost">
            Configuration reference
          </Link>
        </div>
      </div>
    </section>
  );
}

function SectionHeading({ kanji, eyebrow, children }: { kanji: string; eyebrow: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-5">
      <span aria-hidden lang="ja" className="vertical-ja mt-1 text-2xl leading-none text-shu">
        {kanji}
      </span>
      <div>
        <p className="text-xs tracking-[0.25em] text-fd-muted-foreground uppercase">{eyebrow}</p>
        <h2 className="mt-2 font-display text-3xl font-extrabold tracking-tight md:text-4xl">{children}</h2>
      </div>
    </div>
  );
}
