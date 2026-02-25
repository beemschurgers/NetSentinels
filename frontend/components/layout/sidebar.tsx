"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import { sidebarItems } from "@/lib/constants/sidebar-items";
import { useThreatDetection } from "@/contexts/ThreatDetectionContext";
import {
  ShieldCheck,
  Sun,
  Moon,
  PanelLeftOpen,
  PanelLeftClose,
  Settings,
} from "lucide-react";

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [darkMode, setDarkMode] = useState(true);
  const pathname = usePathname();
  const { recentThreatCount, isConnected } = useThreatDetection();

  useEffect(() => {
    const stored = localStorage.getItem("theme");
    const prefersDark =
      stored === "dark" ||
      (!stored && window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", prefersDark);
    setDarkMode(prefersDark);
  }, []);

  const toggleTheme = () => {
    const newMode = !darkMode;
    setDarkMode(newMode);
    localStorage.setItem("theme", newMode ? "dark" : "light");
    document.documentElement.classList.toggle("dark", newMode);
  };

  return (
    <aside
      className={cn(
        "shadow-xl border-r flex flex-col justify-between transition-all duration-300 ease-in-out",
        "dark:bg-[#0B1120] bg-gray-100 dark:border-gray-800 border-gray-300",
        collapsed ? "w-20" : "w-64"
      )}
    >
      {/* Logo & Title */}
      <div
        className={cn(
          "flex items-center w-full h-10 rounded-md transition-all",
          collapsed ? "justify-center ml-[6px]" : "justify-start px-4 ml-3"
        )}
      >
        <ShieldCheck className="h-6 w-6 text-green-400" />
        <span
          className={cn(
            "ml-3 font-bold text-green-400 text-lg tracking-wide transition-all origin-left",
            collapsed
              ? "opacity-0 translate-x-[-10px] w-0 overflow-hidden"
              : "opacity-100 translate-x-0 w-auto"
          )}
        >
          NetSentinel
        </span>
      </div>

      <Separator />

      {/* Nav */}
      <nav className="flex flex-col gap-2 p-4 flex-1 items-center w-full">
        {sidebarItems.map((item) => {
          const isActive = pathname === item.href;
          const isThreatsPage = item.href === "/threats";
          const showThreatBadge = isThreatsPage && recentThreatCount > 0;
          
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center text-sm font-medium w-full h-10 rounded-md transition-all relative",
                isActive
                  ? "bg-green-100 dark:bg-green-300/20 text-green-600 dark:text-green-400"
                  : "hover:bg-green-100/10 dark:hover:bg-green-300/10 hover:text-green-400",
                collapsed ? "justify-center" : "justify-start px-4"
              )}
            >
              <div className="relative">
                <item.icon
                  className={cn(
                    "h-5 w-5 transition-transform",
                    isActive ? "scale-110" : "group-hover:scale-110"
                  )}
                />
                {/* Threat indicator */}
                {showThreatBadge && (
                  <div className="absolute -top-1 -right-1 w-3 h-3 bg-red-500 rounded-full animate-pulse" />
                )}
              </div>
              <span
                className={cn(
                  "origin-left whitespace-nowrap flex items-center",
                  collapsed
                    ? "opacity-0 translate-x-[-10px] w-0 overflow-hidden"
                    : "opacity-100 translate-x-0 w-auto ml-3"
                )}
              >
                {item.label}
                {/* Threat count badge for expanded sidebar */}
                {showThreatBadge && !collapsed && (
                  <span className="ml-2 px-1.5 py-0.5 text-xs bg-red-500 text-white rounded-full min-w-[18px] text-center animate-pulse">
                    {recentThreatCount > 99 ? "99+" : recentThreatCount}
                  </span>
                )}
              </span>
            </Link>
          );
        })}
        
        {/* Connection Status Indicator */}
        <div className={cn(
          "flex items-center w-full h-8 text-xs transition-all mt-2",
          collapsed ? "justify-center" : "justify-start px-4"
        )}>
          <div className={cn(
            "flex items-center gap-2",
            isConnected ? "text-green-500" : "text-yellow-500"
          )}>
            <div className={cn(
              "w-2 h-2 rounded-full",
              isConnected ? "bg-green-500 animate-pulse" : "bg-yellow-500 animate-pulse"
            )} />
            {!collapsed && (
              <span className="whitespace-nowrap">
                {isConnected ? "Detection Active" : "Connecting..."}
              </span>
            )}
          </div>
        </div>
      </nav>

      <Separator />

      {/* Bottom Controls */}
      <div className="p-4 flex flex-col gap-2 items-center w-full">
        {/* Sidebar Toggle Button */}
        <Button
          variant="ghost"
          className="w-full h-10 flex justify-center group transition"
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? (
            <PanelLeftOpen className="h-5 w-5 text-green-400 group-hover:text-green-500" />
          ) : (
            <PanelLeftClose
              className={cn(
                "h-5 w-5 group-hover:text-green-500 transition-all duration-300",
                darkMode ? "text-white" : "text-gray-800"
              )}
            />
          )}
        </Button>

        {/* Theme Toggle */}
        <Button
          variant="ghost"
          className="w-full h-10 flex justify-center transition"
          onClick={toggleTheme}
        >
          {darkMode ? (
            <Sun className="h-5 w-5 text-yellow-300 hover:text-yellow-400" />
          ) : (
            <Moon className="h-5 w-5 text-blue-500 hover:text-blue-600" />
          )}
        </Button>

        {/* Settings */}
        {/* <Link
          href="/settings"
          className={cn(
            "w-full",
            pathname === "/settings"
              ? "bg-green-100 dark:bg-green-300/20 text-green-600 dark:text-green-400"
              : ""
          )}
        >
          <Button
            variant="ghost"
            className={cn(
              "w-full h-10 flex justify-center transition",
              pathname === "/settings"
                ? "text-green-600 dark:text-green-400"
                : "hover:text-green-400"
            )}
          >
            <Settings className="h-5 w-5" />
          </Button>
        </Link> */}
      </div>
    </aside>
  );
}