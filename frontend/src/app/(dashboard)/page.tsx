'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { FiServer, FiPower } from 'react-icons/fi';
import { SiLinux } from 'react-icons/si';
import api, { ApiServerKey } from '../lib/api';

interface ServerInfo {
  id: string;
  apiKey: ApiServerKey;
  name: string;
  url: string;
  ip: string;
  incronStatus: 'running' | 'inactive';
  services: string[];
}

export default function DashboardHome() {
  const [servers, setServers] = useState<ServerInfo[]>([
    {
      id: 'main',
      apiKey: 'main',
      name: 'main',
      url: '/main/analytics',
      ip: 'mainserver.com',
      incronStatus: 'inactive',
      services: ['FIM'],
    },
    {
      id: 'server2',
      apiKey: 'server2',
      name: 'Server 2',
      url: '/server2/analytics',
      ip: 'server2.com',
      incronStatus: 'inactive',
      services: ['FIM'],
    },
    {
      id: 'server3',
      apiKey: 'server3',
      name: 'Server 3',
      url: '/server3/analytics',
      ip: 'server3.com',
      incronStatus: 'inactive',
      services: ['FIM'],
    },
    {
      id: 'server4',
      apiKey: 'server4',
      name: 'Server 4',
      url: '/server4/analytics',
      ip: 'server4.com',
      incronStatus: 'inactive',
      services: ['FIM'],
    },
    {
      id: 'server5',
      apiKey: 'server5',
      name: 'Server 5',
      url: '/server5/analytics',
      ip: 'server5.com',
      incronStatus: 'inactive',
      services: ['FIM'],
    },
  ]);

  useEffect(() => {
    const checkAllServers = async () => {
      const statusPromises = servers.map(async (server) => {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);

          const response = await api('incron/control/', { signal: controller.signal }, server.apiKey);
          clearTimeout(timeoutId);

          return { id: server.id, status: response.is_running ? 'running' : 'inactive' };
        } catch (error) {
          return { id: server.id, status: 'inactive' };
        }
      });

      const results = await Promise.all(statusPromises);

      setServers((prevServers) =>
        prevServers.map((s) => {
          const result = results.find((r) => r.id === s.id);
          return result ? { ...s, incronStatus: result.status as 'running' | 'inactive' } : s;
        }),
      );
    };

    checkAllServers();

    const interval = setInterval(checkAllServers, 60000);
    return () => clearInterval(interval);
  }, []);

  return (
    <main className="min-h-screen">
      <div className="container mx-auto max-w-7xl">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
          {servers.map((server) => (
            <Link
              href={server.incronStatus === 'running' ? server.url : '#'}
              key={server.id}
              className={`
      relative group rounded-xl overflow-hidden transition-all duration-300
      ${server.incronStatus === 'inactive' ? 'cursor-not-allowed opacity-60 border border-gray-800' : 'cursor-pointer border border-gray-6/40 hover:border-green-500/50 hover:shadow-[0_0_20px_rgba(34,197,94,0.2)]'} `}
            >
              {server.incronStatus === 'running' && <div className="absolute inset-[-200%] animate-[spin_4s_linear_infinite] bg-[conic-gradient(from_90deg_at_50%_50%,#0000_0%,#22c55e_50%,#0000_100%)]" />}

              <div
                className={`
        absolute inset-[1.5px] rounded-[10px] z-0 h-full w-full
        ${server.incronStatus === 'running' ? 'bg-background-dark border border-gray-800' : 'bg-gray-900/30'}
      `}
              />

              <div className="relative z-10 p-5 h-full">
                <div className="flex justify-between items-start mb-4">
                  <div className={`p-2 rounded-lg ${server.incronStatus === 'inactive' ? ' text-gray-600' : ' text-gray-200'}`}>
                    <FiServer size={20} />
                  </div>

                  <div
                    className={`px-2 py-1 rounded-full text-[10px] uppercase tracking-wider flex items-center gap-1
          ${server.incronStatus === 'running' ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-500'}
        `}
                  >
                    {server.incronStatus === 'running' && <FiPower className="animate-pulse" />}
                    {server.incronStatus === 'inactive' ? 'OFFLINE' : 'RUNNING'}
                  </div>
                </div>
                <h3 className={`text-lg ${server.incronStatus === 'inactive' ? 'text-gray-500' : 'text-gray-100'}`}>{server.name}</h3>
                <p className="text-xs text-gray-500 font-mono mt-1">{server.ip}</p>
                <div className="mt-6 pt-4 border-t border-gray-800 flex items-center justify-between">
                  <div className="flex gap-2">{server.services.includes('FIM') && <SiLinux size={14} className={server.incronStatus === 'inactive' ? 'text-gray-600' : 'text-yellow-500'} />}</div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </main>
  );
}
