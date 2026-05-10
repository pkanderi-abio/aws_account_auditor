// Route segment layout - provides generateStaticParams for static export
import { ReactNode } from 'react';

export function generateStaticParams() {
  return [];
}

export default function Layout({ children }: { children: ReactNode }) {
  return children as unknown as JSX.Element;
}
