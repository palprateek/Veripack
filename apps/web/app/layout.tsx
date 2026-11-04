import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { getDashboardSession } from "@/lib/auth";

export const metadata: Metadata = {
  title: "Veripack",
  description:
    "A private JavaScript package registry for npm, pnpm, and Bun that audits every release before it becomes installable.",
};

export const dynamic = "force-dynamic";

export default async function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const gatewayUrl = process.env.GATEWAY_URL ?? "http://localhost:4874";
  const session = await getDashboardSession();

  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <div className="header-inner">
            <Link className="brand" href="/">
              <span className="brand-mark">T</span>
              <span>Veripack</span>
            </Link>
            <nav className="nav">
              <span className="nav-label">
                Private package registry · {session?.displayName ?? "signed out"}
              </span>
              {session && <Link href="/review">Review</Link>}
              {session && <Link href="/policy">Policy</Link>}
              {session && <Link href="/blocklist">Blocklist</Link>}
              {session && <Link href="/install-events">Install events</Link>}
              {session && <Link href="/claims">Claims</Link>}
              {session && <Link href="/agents">Agents</Link>}
              {session && <Link href="/security">Security</Link>}
              <a href={`${gatewayUrl}/health`} target="_blank" rel="noreferrer">
                Gateway health
              </a>
              {session ? (
                <form action="/api/auth/logout" method="post">
                  <button className="link-button" type="submit">
                    Sign out
                  </button>
                </form>
              ) : (
                <Link href="/api/auth/login">Sign in</Link>
              )}
            </nav>
          </div>
        </header>

        <main className="container">{children}</main>

        <footer className="site-footer">
          <div className="footer-inner">
            <span>
              Pending releases are never installable. Every decision is recorded.
            </span>
            <span>No package code executes during static analysis.</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
