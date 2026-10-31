import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Veritor",
  description: "Published package vs source code integrity analyzer",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
