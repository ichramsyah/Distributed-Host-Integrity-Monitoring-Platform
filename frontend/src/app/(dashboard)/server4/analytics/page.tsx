'use client';

import React, { useState, useEffect } from 'react';
import { CgSpinner } from 'react-icons/cg';
import { FaExclamationTriangle, FaBell, FaShieldAlt, FaBiohazard } from 'react-icons/fa';
import api from '../../../lib/api';
import LogTable from '../../../components/LogTable';
import { DatePicker } from '../../../components/DatePicker';
import { ParentSize } from '@visx/responsive';
import CustomAreaChart from '../../../components/CustomAreaChart';

interface DetailStats {
  malware: number;
  bahaya: number;
  mencurigakan: number;
  normal: number;
}

interface TodayStats {
  tanggal_analisis: string;
  total_perubahan_hari_ini: number;
  detail: DetailStats;
}

interface HistoricalDataEntry {
  tanggal: string;
  total_perubahan: number;
  detail: DetailStats;
}

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

interface TodayLogs {
  malware: LogEntry[];
  bahaya: LogEntry[];
  mencurigakan: LogEntry[];
  normal: LogEntry[];
}

interface ReportData {
  stats: TodayStats | null;
  logs: TodayLogs;
}

export default function Server4Analytics() {
  const [historicalData, setHistoricalData] = useState<HistoricalDataEntry[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(30);
  const [todayData, setTodayData] = useState<ReportData | null>(null);
  const [reportData, setReportData] = useState<ReportData | null>(null);
  const [activeReportDate, setActiveReportDate] = useState<string>('Hari Ini');
  const [isFetchingDetails, setIsFetchingDetails] = useState(false);

  useEffect(() => {
    const fetchInitialData = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const [todayStats, historicalResponse, todayLogs] = await Promise.all([api('logs/analytics/', {}, 'server4'), api(`logs/analytics/historical/?days=${days}`, {}, 'server4'), api('logs/today/', {}, 'server4')]);

        const initialTodayData = { stats: todayStats, logs: todayLogs };
        setTodayData(initialTodayData);
        setReportData(initialTodayData);
        setHistoricalData(historicalResponse.slice());
        setActiveReportDate('Hari Ini');
      } catch (err: any) {
        setError(err.message || 'Gagal memuat data analisis');
      } finally {
        setIsLoading(false);
      }
    };
    fetchInitialData();
  }, [days]);

  const handleDateSelect = async (date: string) => {
    if (activeReportDate === date) return;

    setIsFetchingDetails(true);
    setActiveReportDate(date);
    try {
      const [statsResponse, logsResponse] = await Promise.all([api(`logs/stats-by-date/?date=${date}`, {}, 'server4'), api(`logs/by-date/?date=${date}`, {}, 'server4')]);
      setReportData({ stats: statsResponse, logs: logsResponse });
    } catch (err) {
      console.error(`Gagal mengambil laporan untuk tanggal ${date}:`, err);
    } finally {
      setIsFetchingDetails(false);
    }
  };

  const resetToToday = () => {
    if (todayData) {
      setReportData(todayData);
      setActiveReportDate('Hari Ini');
    }
  };

  const availableDatesSet = new Set(historicalData.map((d) => new Date(d.tanggal).setHours(0, 0, 0, 0)));
  if (todayData?.stats && todayData.stats.total_perubahan_hari_ini > 0) {
    availableDatesSet.add(new Date().setHours(0, 0, 0, 0));
  }

  const StatCard = ({ icon, title, value, color, iconBg }: any) => (
    <div className={`flex-1 pl-4 py-5 rounded-lg flex items-center bg-gray-4/10 border border-gray-6/40`}>
      <div className={`rounded-full mr-4 ${color} p-4 ${iconBg || 'bg-gray-7/30'}`}>{icon}</div>
      <div>
        <p className="text-[15px] text-gray-400">{title}</p>
        <p className="mt-1 text-[25px] font-bold text-gray-100">{value}</p>
      </div>
    </div>
  );

  return (
    <main className="min-h-screen">
      <div className="container mx-auto max-w-7xl md:px-2 px-1">
        {error && <p className="text-center text-red-600 bg-red-100 p-4 rounded-md mb-4">{error}</p>}

        {isLoading ? (
          <div className="flex justify-center items-center h-96">
            <CgSpinner className="animate-spin text-gray-500" size={40} />
          </div>
        ) : (
          <div>
            <div className=" pb-5 rounded-lg">
              {/* Bagian Grafik */}
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4 px-1">
                <h2 className="text-gray-2 text-xl mb-2 sm:mb-0">Grafik Perubahan</h2>
                <div className="flex items-center gap-2">
                  {[7, 15, 30].map((d) => (
                    <button
                      key={d}
                      onClick={() => setDays(d)}
                      className={`px-4 py-1 pb-1.5 text-sm rounded-md transition-all cursor-pointer ${days === d ? 'bg-gray-4/20 text-gray-2' : 'text-gray-4 bg-transparent hover:bg-gray-5/30 hover:text-gray-2'}`}
                    >
                      {d} Hari
                    </button>
                  ))}
                </div>
              </div>
              {historicalData.length > 0 ? (
                <div style={{ width: '100%', height: 350, cursor: 'pointer' }}>
                  <ParentSize>{({ width, height }) => <CustomAreaChart data={historicalData} width={width} height={height} onDateSelect={handleDateSelect} />}</ParentSize>
                </div>
              ) : (
                <div className="text-center text-gray-500 p-8 bg-white rounded-lg border border-gray-200">Tidak ada data historis yang tersedia.</div>
              )}
            </div>

            <div className="py-5 rounded-lg">
              {/* Bagian Laporan */}
              <div className="px-1 w-full pb-6">
                <div className="mb-2">
                  <div className="mb-6 flex flex-col sm:flex-row justify-between items-start sm:items-center">
                    <h3 className="text-gray-2 text-xl mb-3 sm:mb-0">Laporan {activeReportDate}</h3>
                    <DatePicker selectedDate={activeReportDate} onDateSelect={handleDateSelect} resetToToday={resetToToday} availableDates={availableDatesSet} />
                  </div>
                </div>

                {isFetchingDetails ? (
                  <div className="flex justify-center items-center h-64">
                    <CgSpinner className="animate-spin text-gray-500" size={40} />
                  </div>
                ) : (
                  <>
                    <div className="mt-4 mb-2">
                      <StatCard icon={<FaShieldAlt size={22} />} title="Total Perubahan" value={reportData?.stats?.total_perubahan_hari_ini ?? 0} color="text-gray-200/80" />
                    </div>

                    <div className="gap-2 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
                      {/* 1. Malware */}
                      <StatCard icon={<FaBiohazard size={22} />} title="Malware" value={reportData?.stats?.detail.malware ?? 0} color="text-red-600" iconBg="bg-red-500/20" />
                      {/* 2. Bahaya */}
                      <StatCard icon={<FaExclamationTriangle size={22} />} title="Bahaya" value={reportData?.stats?.detail.bahaya ?? 0} color="text-orange-500" iconBg="bg-orange-500/10" />
                      {/* 3. Mencurigakan */}
                      <StatCard icon={<FaExclamationTriangle size={22} />} title="Mencurigakan" value={reportData?.stats?.detail.mencurigakan ?? 0} color="text-yellow-500/80" />
                      {/* 4. Normal */}
                      <StatCard icon={<FaBell size={22} />} title="Normal" value={reportData?.stats?.detail.normal ?? 0} color="text-blue-500/80" />
                    </div>

                    <div className="mt-8 grid grid-cols-1 lg:grid-cols-1 gap-6">
                      {/* TABEL-TABEL (Tidak ada perubahan) */}
                      {(reportData?.logs.malware?.length ?? 0) > 0 && (
                        <LogTable title="Terdeteksi Malware" icon={<FaBiohazard size={18} className="text-red-600" />} logs={reportData?.logs.malware ?? []} bgColor="bg-red-900/10 border border-red-900/30" />
                      )}

                      <LogTable title="Bahaya" icon={<FaExclamationTriangle size={16} className="text-orange-500" />} logs={reportData?.logs.bahaya ?? []} bgColor="bg-gray-5/20" />
                      <LogTable title="Mencurigakan" icon={<FaExclamationTriangle size={16} className="text-yellow-500/80" />} logs={reportData?.logs.mencurigakan ?? []} bgColor="bg-gray-5/20" />
                      <LogTable title="Normal" icon={<FaBell size={16} className="text-blue-500/80" />} logs={reportData?.logs.normal ?? []} bgColor="bg-gray-5/20" />
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
