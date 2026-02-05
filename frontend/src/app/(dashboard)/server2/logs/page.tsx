'use client';

import React, { useState, useEffect, useRef } from 'react';
import { FiCheckSquare, FiSearch, FiTrash2 } from 'react-icons/fi';
import { CgSpinner } from 'react-icons/cg';
import { FaSlidersH, FaTimes, FaTrash, FaBiohazard, FaExclamationTriangle } from 'react-icons/fa'; // Tambah Icon
import api from '../../../lib/api';
import Pagination from '../../../components/Pagination';
import toast from 'react-hot-toast';
import Swal from 'sweetalert2';

interface LogEntry {
  id: string;
  tanggal: string;
  jam: string;
  metode: string;
  nama_file: string;
  path_lengkap: string;
  tag: string;
  user: string;
  comm: string;
  exe: string;
}

interface PaginationInfo {
  count: number;
  total_pages: number;
  current_page: number;
}

export default function Server2Log() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [paginationInfo, setPaginationInfo] = useState<PaginationInfo | null>(null);
  const [statusFilter, setStatusFilter] = useState('all');
  const [isFilterOpen, setIsFilterOpen] = useState(false);
  const filterRef = useRef<HTMLDivElement>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [isSelectMode, setIsSelectMode] = useState(false);

  // --- LOGIC SELEKSI ---
  const toggleSelectMode = () => {
    setIsSelectMode(!isSelectMode);
    setSelectedIds([]);
  };

  const handleSelectLog = (logId: string) => {
    setSelectedIds((prev) => (prev.includes(logId) ? prev.filter((id) => id !== logId) : [...prev, logId]));
  };

  const handleSelectAll = () => {
    if (selectedIds.length === logs.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(logs.map((log) => log.id));
    }
  };

  const fetchLogs = (page = 1, query = '', status = 'all') => {
    setIsLoading(true);
    const params = new URLSearchParams();
    params.append('page', String(page));
    if (query) params.append('search', query);
    if (status && status !== 'all') params.append('status', status);

    api(`logs/?${params.toString()}`, {}, 'journal')
      .then((data) => {
        setLogs(data.results);
        setPaginationInfo({
          count: data.count,
          total_pages: Math.ceil(data.count / 10),
          current_page: page,
        });
        setError(null);
      })
      .catch((err: any) => {
        setError(err.message || 'Gagal mengambil data dari API Journal.');
        setLogs([]);
        setPaginationInfo(null);
      })
      .finally(() => setIsLoading(false));
  };

  const handleMultipleMoveToTrash = async () => {
    const result = await Swal.fire({
      title: 'Hapus Log Journal?',
      text: `Anda yakin ingin menghapus ${selectedIds.length} log ini secara permanen dari server Journal?`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#d33',
      cancelButtonColor: '#3085d6',
      confirmButtonText: 'Ya, hapus!',
      cancelButtonText: 'Batal',
      background: '#1f2937',
      color: '#fff',
    });
    if (!result.isConfirmed) return;
    try {
      await api(
        'logs/',
        {
          method: 'DELETE',
          body: JSON.stringify({ ids: selectedIds }),
        },
        'journal',
      );
      toast.success(`${selectedIds.length} log journal berhasil dihapus.`);
      fetchLogs(currentPage, searchQuery, statusFilter);
      setSelectedIds([]);
    } catch (error: any) {
      toast.error(`Error: ${error.message}`);
    }
  };

  const handleMoveToTrash = async (logId: string) => {
    try {
      await api(
        'logs/',
        {
          method: 'DELETE',
          body: JSON.stringify({ id: logId }),
        },
        'journal',
      );
      toast.success('Log berhasil dihapus.');
      fetchLogs(currentPage, searchQuery, statusFilter);
    } catch (error: any) {
      toast.error(`Error: ${error.message}`);
    }
  };

  // --- HANDLERS LAINNYA ---

  const handlePageChange = (newPage: number) => {
    if (newPage > 0 && newPage <= (paginationInfo?.total_pages || 1)) {
      setCurrentPage(newPage);
      fetchLogs(newPage, searchQuery, statusFilter);
    }
  };

  useEffect(() => {
    const handler = setTimeout(() => {
      fetchLogs(currentPage, searchQuery, statusFilter);
    }, 500);

    return () => {
      clearTimeout(handler);
    };
  }, [searchQuery, statusFilter]);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
    setCurrentPage(1);
  };

  const handleFilterChange = (newStatus: string) => {
    setStatusFilter(newStatus);
    setCurrentPage(1);
    setIsFilterOpen(false);
  };

  const filters = [
    { label: 'Semua', value: 'all' },
    { label: 'Malware', value: 'malware' },
    { label: 'Bahaya', value: 'bahaya' },
    { label: 'Mencurigakan', value: 'mencurigakan' },
    { label: 'Normal', value: 'normal' },
  ];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (filterRef.current && !filterRef.current.contains(event.target as Node)) {
        setIsFilterOpen(false);
      }
    };
    if (isFilterOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isFilterOpen]);

  const activeFilterLabel = filters.find((f) => f.value === statusFilter)?.label;

  // Helper untuk warna badge
  const getBadgeStyle = (tag: string) => {
    const t = tag.toUpperCase();
    if (t.includes('MALWARE')) return 'bg-red-700 text-white border border-red-500';
    if (t.includes('BAHAYA')) return 'bg-orange-600 text-white';
    if (t.includes('MENCURIGAKAN')) return 'bg-yellow-600 text-white';
    return 'bg-blue-900 text-gray-200';
  };

  // Helper untuk background row
  const getRowStyle = (tag: string, isSelected: boolean) => {
    const t = tag.toUpperCase();
    let baseClass = 'block md:table-row mb-6 md:mb-0 border-b border-gray-6/30 rounded-lg md:rounded-none ';

    if (isSelected) return baseClass + 'bg-gray-9/10';
    if (t.includes('MALWARE')) return baseClass + 'bg-red-900/10 border-red-900/30';
    return baseClass + 'bg-background-dark';
  };

  return (
    <main className="min-h-screen">
      <div className="container mx-auto max-w-7xl px-2">
        <div className="mb-4 flex flex-col md:flex-row md:justify-between">
          <h1 className="text-[24px] text-gray-2 mb-4 md:mb-0">Log Perubahan</h1>
          <div className="hidden lg:flex items-center gap-4 mr-6 bg-gray-5/10 px-4 py-2 rounded-full border border-gray-6/20">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.6)]"></div>
              <span className="text-xs text-gray-400">Malware</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_6px_rgba(249,115,22,0.6)]"></div>
              <span className="text-xs text-gray-400">Bahaya</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-yellow-500 shadow-[0_0_6px_rgba(234,179,8,0.6)]"></div>
              <span className="text-xs text-gray-400">Mencurigakan</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_6px_rgba(59,130,246,0.6)]"></div>
              <span className="text-xs text-gray-400">Normal</span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center gap-2">
            <div className="relative">
              <FiSearch className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" size={20} />
              <input
                type="text"
                value={searchQuery}
                onChange={handleSearchChange}
                placeholder="Search..."
                className="w-full py-2 pl-12 pr-4 rounded-[6px] hover:rounded-[50px] focus:rounded-[50px] border border-gray-4 focus:outline-none transition-all duration-300 placeholder:text-gray-500 text-gray-300 placeholder:text-md"
              />
            </div>

            <div className="flex items-center gap-3">
              {isSelectMode && selectedIds.length > 0 && (
                <button onClick={handleMultipleMoveToTrash} className="bg-red-500 text-white px-3 py-2.5 rounded-lg hover:bg-red-600 text-sm flex items-center gap-2">
                  <FiTrash2 />
                  <span>Pindahkan ({selectedIds.length})</span>
                </button>
              )}

              <button
                onClick={toggleSelectMode}
                className={`px-3 py-2.5 pb-3 rounded-lg text-sm flex items-center gap-2 transition-colors ${isSelectMode ? 'bg-gray-4/50 text-gray-2 hover:bg-gray-4/30' : 'text-gray-2 bg-gray-5/30 hover:bg-gray-5/50'}`}
              >
                {isSelectMode ? (
                  <div className="flex items-center gap-1.5">
                    <FaTimes />
                    <span>Batal</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5">
                    <FiCheckSquare />
                    <span>Pilih</span>
                  </div>
                )}
              </button>
            </div>

            <div ref={filterRef} className="relative">
              <button onClick={() => setIsFilterOpen(!isFilterOpen)} className="bg-gray-5/30 px-4 py-2.5 pb-3 rounded-lg text-gray-200 flex items-center hover:bg-gray-5/50 transition-colors " title="Filter">
                <FaSlidersH size={14} className="mr-2 text-gray-200" />
                <span className="text-sm">{activeFilterLabel}</span>
              </button>

              {/* Menu Dropdown */}
              {isFilterOpen && (
                <div className="absolute md:right-0 sm:right-[-90px] mt-2 w-48 bg-background-main rounded-lg shadow-xl z-10">
                  <div className="py-1">
                    {filters.map((filter) => (
                      <button
                        key={filter.value}
                        onClick={() => handleFilterChange(filter.value)}
                        className={`w-full text-left px-4 py-2 text-sm transition-colors ${statusFilter === filter.value ? 'bg-gray-5/30 text-gray-2' : 'text-gray-4 hover:bg-gray-5/30 hover:text-gray-2'}`}
                      >
                        {filter.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto md:bg-transparent bg-transparent rounded-lg">
          {isLoading ? (
            <div className="flex justify-center items-center h-64">
              <CgSpinner className="animate-spin text-gray-500" size={40} />
            </div>
          ) : error ? (
            <p className="text-center text-red-600 p-8">{error}</p>
          ) : logs.length === 0 ? (
            <p className="text-center text-gray-500 p-8">Tidak ada log journal yang ditemukan.</p>
          ) : (
            <table className="min-w-full text-sm">
              <thead className="bg-gray-6/20 hidden md:table-header-group">
                <tr>
                  {isSelectMode && (
                    <th className="p-4 w-12 text-center">
                      <input type="checkbox" className="rounded" checked={logs.length > 0 && selectedIds.length === logs.length} onChange={handleSelectAll} />
                    </th>
                  )}

                  <th className="p-4 text-left text-gray-200 font-medium">Tanggal</th>
                  <th className="p-4 text-left text-gray-200 font-medium">Jam</th>
                  <th className="p-4 text-left text-gray-200 font-medium">User</th>
                  <th className="p-4 text-left text-gray-200 font-medium">Metode</th>
                  <th className="py-4 px-0 text-left text-gray-200 font-medium">Nama File</th>
                  <th className="p-4 text-left text-gray-200 font-medium">Command</th>
                  <th className="p-4 text-left text-gray-200 font-medium">Eksekusi</th>
                  <th className="p-4 text-left text-gray-200 font-medium">Kondisi</th>
                  <th className="p-4 text-left text-gray-200 font-medium">Path File</th>
                  <th className="p-4 text-center text-gray-200 font-medium"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 ">
                {logs.map((log) => (
                  <tr key={log.id} className={getRowStyle(log.tag, selectedIds.includes(log.id))}>
                    {isSelectMode && (
                      <td data-label="Pilih:" className="p-4 flex justify-end md:justify-center md:table-cell text-right md:text-left ">
                        <input type="checkbox" className="rounded" checked={selectedIds.includes(log.id)} onChange={() => handleSelectLog(log.id)} />
                      </td>
                    )}

                    {/* Tanggal */}
                    <td data-label="Tanggal:" className="p-4 flex justify-end md:table-cell text-right md:text-left ">
                      <div className="flex flex-col">
                        <span className="text-[12px] text-gray-4">{log.tanggal}</span>
                      </div>
                    </td>
                    {/* Jam */}
                    <td data-label="Jam:" className="p-2 flex justify-end md:table-cell text-right md:text-left ">
                      <div className="flex flex-col">
                        <span className="text-gray-300 text-[13px]">{log.jam ? log.jam.slice(0, 5) : '-'}</span>
                      </div>
                    </td>
                    {/* User */}
                    <td data-label="User:" className="p-4 flex justify-end md:table-cell text-right md:text-left ">
                      <div className="flex flex-col">
                        <span className="text-gray-300 text-[13px]">{log.user}</span>
                      </div>
                    </td>
                    {/* Metode */}
                    <td data-label="Metode:" className="p-4 flex justify-end md:table-cell text-right md:text-left ">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getBadgeStyle(log.tag)}`}>{log.metode}</span>
                    </td>
                    {/* Nama File */}
                    <td data-label="File:" className="py-4 px-0 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-200 ">
                      {log.nama_file}
                    </td>
                    {/* Command */}
                    <td data-label="Command:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-200 ">
                      {log.comm}
                    </td>
                    {/* Exe */}
                    <td data-label="Exe:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-200 break-all">
                      {log.exe}
                    </td>
                    {/* Kondisi */}
                    <td data-label="Kondisi:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-200 ">
                      {log.tag.includes('MALWARE') ? <div className="flex items-center gap-2 text-red-500 font-bold">Terdeteksi {log.tag}</div> : log.tag}
                    </td>
                    {/* Path Lengkap */}
                    <td data-label="Path:" className="p-4 flex justify-end md:table-cell text-right md:text-left font-mono text-gray-400 break-all">
                      {log.path_lengkap}
                    </td>
                    {/* Aksi */}
                    <td data-label="Aksi:" className="p-4 flex justify-end md:table-cell text-right md:text-center">
                      <button onClick={() => handleMoveToTrash(log.id)} className="bg-red-500 p-2 rounded-sm text-gray-1 text-[12px] hover:bg-red-600 transition-colors" title="Pindah ke Tempat Sampah">
                        <FaTrash />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        {paginationInfo && <Pagination currentPage={paginationInfo.current_page} totalPages={paginationInfo.total_pages} onPageChange={handlePageChange} totalCount={paginationInfo.count} itemsPerPage={logs.length} />}
      </div>
    </main>
  );
}
