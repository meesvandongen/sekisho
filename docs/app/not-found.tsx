import Link from 'next/link';
import { HomeLayout } from 'fumadocs-ui/layouts/home';
import { baseOptions } from '@/lib/layout.shared';

export default function NotFound() {
  return (
    <HomeLayout {...baseOptions()}>
      <main className="relative flex flex-1 flex-col items-center justify-center overflow-hidden px-6 py-32 text-center">
        <div
          aria-hidden
          className="seigaiha pointer-events-none absolute inset-x-0 bottom-0 h-40 opacity-20 [mask-image:linear-gradient(to_top,black,transparent)]"
        />
        <span className="hanko size-20 text-3xl" lang="ja">
          止
        </span>
        <p className="mt-8 text-xs tracking-[0.3em] text-fd-muted-foreground uppercase">404 · route_not_found</p>
        <h1 className="mt-3 font-display text-4xl font-extrabold md:text-5xl">No road leads here.</h1>
        <p className="mt-4 max-w-md text-fd-muted-foreground">
          The gatekeeper found no such path. Like any unlisted route, this request has been turned back.
        </p>
        <Link href="/" className="btn-shu mt-9">
          Return to the gate
        </Link>
      </main>
    </HomeLayout>
  );
}
