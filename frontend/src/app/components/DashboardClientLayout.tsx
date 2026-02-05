// src/components/DashboardClientLayout.tsx

'use client';
import React, { useState, ReactNode, useEffect } from 'react';
import Sidebar from './Sidebar';
import Navbar from './Navbar';
import { useMediaQuery } from '../hooks/useMediaQuery';

interface LayoutProps {
  children: ReactNode;
}

export default function DashboardClientLayout({ children }: LayoutProps) {
  const isDesktop = useMediaQuery('(min-width: 768px)');
  const [isSidebarOpen, setSidebarOpen] = useState(isDesktop);

  const toggleSidebar = () => {
    setSidebarOpen(!isSidebarOpen);
  };

  useEffect(() => {
    setSidebarOpen(isDesktop);
  }, [isDesktop]);

  return (
    <div className="bg-background-dark min-h-screen">
      <Sidebar isOpen={isSidebarOpen} toggle={toggleSidebar} isMobile={!isDesktop} />

      {isSidebarOpen && (
        <div
          onClick={toggleSidebar}
          className="
            fixed inset-0 bg-black/20 bg-opacity-50 z-20
            md:hidden
          "
        ></div>
      )}

      <div
        className={`
          relative h-screen flex flex-col
          transition-all duration-300 ease-in-out
          ${isSidebarOpen ? 'md:ml-64' : 'md:ml-20'}
        `}
      >
        <Navbar toggleSidebar={toggleSidebar} isSidebarOpen={isSidebarOpen} isMobile={!isDesktop} />
        <main className="flex-1 overflow-y-auto p-4 md:p-6">
          <div className="max-w-7xl mx-auto w-full">{children}</div>
        </main>
      </div>
    </div>
  );
}
