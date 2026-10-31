import type { Metadata } from "next";
import { Geist_Mono } from "next/font/google";
import "./globals.css";

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AEGIS // Campus IDS SOC Console (CTBF-CS-03)",
  description: "Ultra-Lightweight, Deterministic Intrusion Detection System for Campus Networks",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${geistMono.variable} dark h-full`}>
      <body className="min-h-full bg-zinc-950 text-zinc-300 font-mono antialiased selection:bg-red-950 selection:text-red-200">
        {children}
      </body>
    </html>
  );
}
