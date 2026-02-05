// src/components/Sidebar.tsx

'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { FiChevronsLeft, FiChevronsRight, FiBarChart, FiFileText, FiServer, FiChevronDown, FiGrid } from 'react-icons/fi';
import { motion, AnimatePresence } from 'framer-motion';

const mainMenu = [{ name: 'Dashboard', href: '/', icon: FiGrid }];
const serverGroups = [
  {
    id: 'main',
    label: 'main',
    icon: FiServer,
    items: [
      { name: 'Server Analytics', href: '/main/analytics', icon: FiBarChart },
      { name: 'Server Log', href: '/main/logs', icon: FiFileText },
    ],
  },
  {
    id: 'server2',
    label: 'Server 2',
    icon: FiServer,
    items: [
      { name: 'Server Analytics', href: '/server2/analytics', icon: FiBarChart },
      { name: 'Server Log', href: '/server2/logs', icon: FiFileText },
    ],
  },
  {
    id: 'server3',
    label: 'Server 3',
    icon: FiServer,
    items: [
      { name: 'Server Analytics', href: '/server3/analytics', icon: FiBarChart },
      { name: 'Server Log', href: '/server3/logs', icon: FiFileText },
    ],
  },
  {
    id: 'server4',
    label: 'Server 4',
    icon: FiServer,
    items: [
      { name: 'Server Analytics', href: '/server4/analytics', icon: FiBarChart },
      { name: 'Server Log', href: '/server4/logs', icon: FiFileText },
    ],
  },
  {
    id: 'server5',
    label: 'Server 5',
    icon: FiServer,
    items: [
      { name: 'Server Analytics', href: '/server5/analytics', icon: FiBarChart },
      { name: 'Server Log', href: '/server5/logs', icon: FiFileText },
    ],
  },
];

interface SidebarProps {
  isOpen: boolean;
  toggle: () => void;
  isMobile: boolean;
}

export default function Sidebar({ isOpen, toggle, isMobile }: SidebarProps) {
  const pathname = usePathname();
  const [expandedGroups, setExpandedGroups] = useState<string[]>([]);

  const toggleGroup = (groupId: string) => {
    if (!isOpen) {
      toggle();
    }
    setExpandedGroups((prev) => (prev.includes(groupId) ? prev.filter((id) => id !== groupId) : [...prev, groupId]));
  };

  const handleLinkClick = () => {
    if (isMobile && isOpen) {
      toggle();
    }
  };

  return (
    <aside
      className={`
        bg-background-dark text-gray-9
        fixed top-0 left-0 h-full z-30
        transition-all duration-300 ease-in-out
        ${isOpen ? 'w-64' : 'w-20'}
        md:translate-x-0 
        ${isOpen ? 'translate-x-0' : '-translate-x-full'}
        border-r border-gray-6/30
      `}
    >
      <div className="flex flex-col h-full">
        {/* Header */}
        <div className={`flex items-center relative justify-center pt-5 pb-5 border-b h-[105px]`}>
          <div className={`${!isOpen && 'hidden'} transition-opacity duration-300`}>
            <img src="./img/(your logo).png" className="w-[130px] object-contain" alt="Logo" />
          </div>

          {/* Toggle Button */}
          <button
            onClick={toggle}
            className={`absolute right-0 p-2 rounded-md hover:bg-gray-5/20 text-gray-400 hover:text-white transition-colors cursor-pointer ${!isOpen ? 'right-3' : 'right-2'}`}
            title={isOpen ? 'Sembunyikan Sidebar' : 'Tampilkan Sidebar'}
          >
            {isOpen ? <FiChevronsLeft size={22} /> : <FiChevronsRight size={24} />}
          </button>
        </div>

        {/* Navigasi */}
        <nav className="flex-1 py-4 overflow-y-auto space-y-2 custom-scrollbar px-3">
          {mainMenu.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.name}
                href={item.href}
                onClick={handleLinkClick}
                className={`
                  w-full flex items-center p-3 pb-4 rounded-lg transition-all duration-200 mb-1
                  ${isActive ? 'bg-gray-6/20 text-gray-100 font-medium' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-5/5'}
                  ${!isOpen && 'justify-center'}
                `}
                title={!isOpen ? item.name : ''}
              >
                <item.icon size={20} />
                {isOpen && <span className="ml-3 font-medium text-sm tracking-wide">{item.name}</span>}
              </Link>
            );
          })}

          <div className="my-2 mx-2"></div>
          {/* Label */}
          {isOpen && <div className="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 mt-4">server</div>}

          {serverGroups.map((group) => {
            const isExpanded = expandedGroups.includes(group.id);
            // Cek jika salah satu anak aktif untuk highlight parent
            const isChildActive = group.items.some((item) => pathname === item.href);

            return (
              <div key={group.id} className="mb-1">
                <button
                  onClick={() => toggleGroup(group.id)}
                  className={`
                    w-full flex items-center justify-between p-3 rounded-lg transition-all duration-200 cursor-pointer
                    ${isChildActive ? 'text-gray-100' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-5/10'}
                    ${!isOpen && 'justify-center'}
                  `}
                  title={!isOpen ? group.label : ''}
                >
                  <div className="flex items-center gap-3">
                    <group.icon size={20} className={isChildActive ? 'text-blue-500' : ''} />
                    {isOpen && <span className="font-medium text-sm tracking-wide">{group.label}</span>}
                  </div>

                  {isOpen && (
                    <div className={`transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
                      <FiChevronDown size={16} />
                    </div>
                  )}
                </button>

                <AnimatePresence>
                  {isOpen && isExpanded && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.3, ease: 'easeInOut' }} className="overflow-hidden">
                      <div className="mt-1 ml-4 pl-4 border-l border-gray-700 space-y-1 cursor-pointer py-1">
                        {group.items.map((item) => {
                          const isActive = pathname === item.href;
                          return (
                            <Link
                              key={item.name}
                              href={item.href}
                              onClick={handleLinkClick}
                              className={`
                                flex items-center gap-3 px-3 py-2 pb-3 rounded-md text-sm transition-all duration-200
                                ${isActive ? 'bg-gray-6/20 text-gray-100 font-medium' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-5/5'}
                              `}
                            >
                              <item.icon size={16} />
                              <span>{item.name}</span>
                            </Link>
                          );
                        })}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </nav>

        {/* Footer User Info */}
        {isOpen && (
          <div className="p-4 border-t border-gray-6/30">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-black border-[2px] border-gray-8/80 flex items-center justify-center text-xs text-white">WA</div>
              <div className="flex flex-col">
                <span className="text-sm text-gray-200 font-medium">Web Admin</span>
                <span className="text-xs text-gray-500">Super User</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
