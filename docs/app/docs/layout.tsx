import { source } from '@/lib/source';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { baseOptions } from '@/lib/layout.shared';

export default function Layout({ children }: LayoutProps<'/docs'>) {
  const { links: _links, ...options } = baseOptions();
  return (
    <DocsLayout
      tree={source.getPageTree()}
      {...options}
      sidebar={{
        banner: (
          <div className="sidebar-banner" lang="ja" aria-hidden>
            <span>通行手形改め</span>
            <span className="sidebar-banner-en">Passes inspected here</span>
          </div>
        ),
      }}
    >
      {children}
    </DocsLayout>
  );
}
