// src/app/layout.tsx
import type { Metadata } from 'next';
import './globals.css';
import localFont from 'next/font/local';
import { Toaster } from 'react-hot-toast';

const nexaFont = localFont({
  src: './fonts/NexaRegular.otf',
  display: 'swap',
  variable: '--nexa',
});

export const metadata: Metadata = {
  title: 'File Integrity Monitoring Dashboard',
  description: 'File Integrity Monitoring Dashboard',
  icons: {
    icon: './img/favicon.png',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={nexaFont.variable}>
        <Toaster position="top-right" reverseOrder={false} />
        {children}
      </body>
    </html>
  );
}
