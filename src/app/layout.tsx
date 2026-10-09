import type { ReactNode } from 'react';
import './globals.css';

export const metadata = {
  title: 'Stackwatch',
  description: 'Continuous stack discovery, advisory matching, and exposure verification.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
