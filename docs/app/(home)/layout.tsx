import { HomeLayout } from 'fumadocs-ui/layouts/home';
import Link from 'next/link';
import { baseOptions } from '@/lib/layout.shared';
import { Mark } from '@/components/logo';
import { githubUrl } from '@/lib/shared';

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <HomeLayout {...baseOptions()}>
      {children}
      <Footer />
    </HomeLayout>
  );
}

function Footer() {
  return (
    <footer className="mt-auto border-t border-fd-border">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-6 py-10 text-sm text-fd-muted-foreground md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <Mark className="size-9" aria-hidden title="" />
          <div>
            <p className="font-display text-base font-extrabold text-fd-foreground">
              Sekisho <span className="text-shu" lang="ja">関所</span>
            </p>
            <p>The checkpoint in front of your API.</p>
          </div>
        </div>
        <nav className="flex flex-wrap gap-x-6 gap-y-2">
          <Link href="/docs" className="hover:text-shu">
            Documentation
          </Link>
          <Link href="/docs/quickstart" className="hover:text-shu">
            Quickstart
          </Link>
          <a href={githubUrl} className="hover:text-shu" rel="noreferrer">
            GitHub
          </a>
          <a href="/llms.txt" className="hover:text-shu">
            llms.txt
          </a>
        </nav>
      </div>
    </footer>
  );
}
