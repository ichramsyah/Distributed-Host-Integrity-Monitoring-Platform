// components/LogTable.tsx

import React, { useState } from 'react';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import Pagination from './Pagination';

interface LogEntry {
  id: string;
  jam: string;
  metode: string;
  nama_file: string;
  path_lengkap: string;
  tag: string;
  comm: string;
  exe: string;
  user: string;
}

interface LogTableProps {
  title: string;
  logs: LogEntry[];
  bgColor?: string;
  icon?: string | React.ReactNode;
}

const LogTable: React.FC<LogTableProps> = ({ title, logs, bgColor, icon }) => {
  const [isVisible, setIsVisible] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  if (logs.length === 0) {
    return (
      <div className="mb-6">
        <h3 className={`text-sm text-gray-3 mb-2`}>{title} (0)</h3>
        <div className="text-center text-gray-500 p-8 rounded-lg border border-gray-5/70">Tidak ada data log yang tersedia.</div>
      </div>
    );
  }

  const totalPages = Math.ceil(logs.length / itemsPerPage);
  const currentLogs = logs.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
  };

  return (
    <div className="mb-6">
      <div className="mb-3 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <h3 className={`text-md text-gray-3`}>
            {title} ({logs.length})
          </h3>
          {icon}
        </div>

        <button onClick={() => setIsVisible(!isVisible)} className="text-white px-2 py-2 bg-gray-5/30 rounded-sm flex items-center justify-center cursor-pointer hover:bg-gray-5/50 transition-colors">
          {isVisible ? <FaEye size={15} className="text-white" /> : <FaEyeSlash size={15} className="text-white" />}
        </button>
      </div>

      {isVisible && (
        <div className="overflow-x-auto rounded-lg transition-all duration-300 ease-in-out">
          <table className="min-w-full text-sm">
            <thead className={`${bgColor} hidden md:table-header-group`}>
              <tr>
                <th className="p-4 font-medium text-left text-gray-3">Jam</th>
                <th className="p-4 font-medium text-left text-gray-3">Nama File</th>
                <th className="p-4 font-medium text-left text-gray-3">User</th>
                <th className="p-4 font-medium text-left text-gray-3">Command</th>
                <th className="p-4 font-medium text-left text-gray-3">Eksekusi</th>
                <th className="p-4 font-medium text-left text-gray-3">Metode</th>
                <th className="p-4 font-medium text-left text-gray-3">Path File</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 md:divide-y-0">
              {currentLogs.map((log) => (
                <tr key={log.id} className="block md:table-row mb-4 md:mb-0 rounded-lg md:rounded-none bg-gray-4/10">
                  <td data-label="Jam:" className="p-4 pl-3 flex justify-end md:table-cell text-right md:text-left ">
                    <span className="text-gray-400">{log.jam ? log.jam.slice(0, 5) : '-'}</span>
                  </td>
                  <td data-label="File:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-200 ">
                    {log.nama_file}
                  </td>
                  <td data-label="User:" className="p-4 flex justify-end md:table-cell text-right md:text-left text-gray-200 ">
                    {log.user}
                  </td>
                  <td data-label="Command:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-300 ">
                    {log.comm}
                  </td>
                  <td data-label="Eksekusi:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-300 ">
                    {log.exe}
                  </td>
                  <td data-label="Metode:" className="p-4 flex justify-end md:table-cell text-right md:text-left ">
                    <span
                      className={`px-2 py-1 text-xs font-medium rounded-full ${
                        log.tag.includes('[BAHAYA]')
                          ? 'bg-orange-700 text-gray-1'
                          : log.tag.includes('[MALWARE]')
                          ? 'bg-red-800 text-gray-1'
                          : log.tag.includes('[KEGIATAN MENCURIGAKAN]')
                          ? 'bg-yellow-600 text-gray-1'
                          : 'bg-blue-900 text-gray-1'
                      }`}
                    >
                      {log.metode}
                    </span>
                  </td>
                  <td data-label="Path:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-400  break-all">
                    {log.path_lengkap}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {logs.length > itemsPerPage && (
            <div className="p-4 border-t border-gray-6/30">
              <Pagination currentPage={currentPage} totalPages={totalPages} onPageChange={handlePageChange} totalCount={logs.length} itemsPerPage={itemsPerPage} />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default LogTable;
