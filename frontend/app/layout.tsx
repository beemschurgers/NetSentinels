import Sidebar from "@/components/layout/sidebar";
import { ThreatDetectionProvider } from "@/contexts/ThreatDetectionContext";
import { ThreatNotification } from "@/components/ThreatNotification";

import "@/app/globals.css";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html>
      <body>
        <ThreatDetectionProvider>
          <div className="flex h-screen text-gray-900 dark:text-white bg-white dark:bg-gray-950">
            <Sidebar />
            <main className="flex-1 p-6 overflow-y-auto bg-white dark:bg-[#0B1120] transition-colors duration-300">
              {children}
            </main>
            <ThreatNotification />
          </div>
        </ThreatDetectionProvider>
      </body>
    </html>
  );
}
